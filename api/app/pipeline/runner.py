"""Run orchestration: a small in-process job queue with per-stage state.

Each stage is idempotent and keyed by run id + stage; outputs are stored in
`Run.artifacts[stage]` so a failed stage never loses earlier output and any stage
can be re-run on its own (it then re-runs everything downstream of it).
IoC enrichment runs in parallel with synthesis -> query generation.

For multi-node deployments, swap the ThreadPoolExecutor for Celery/Arq on Redis:
`execute_run(run_id, from_stage)` is the task entry point.
"""

from __future__ import annotations

import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ..config import get_settings
from ..db import SessionLocal
from ..models import Research, Run, RunLog

log = logging.getLogger(__name__)

STAGES: list[tuple[str, str]] = [
    ("intake", "Intake"),
    ("discovery", "Source discovery"),
    ("extraction", "Per-article extraction"),
    ("synthesis", "Synthesis"),
    ("attack", "ATT&CK mapping"),
    ("detection", "Detection reasoning"),
    ("queries", "Query generation"),
    ("iocs", "IoC extraction + enrichment"),
    ("report", "Report build"),
    ("export", "Export readiness"),
]
STAGE_IDS = [s for s, _ in STAGES]
MAIN_CHAIN = ["synthesis", "attack", "detection", "queries"]

_pool = ThreadPoolExecutor(max_workers=get_settings().run_workers, thread_name_prefix="run")
_locks: dict[str, threading.Lock] = {}
_active: set[str] = set()


def _lock(run_id: str) -> threading.Lock:
    return _locks.setdefault(run_id, threading.Lock())


def now() -> datetime:
    return datetime.now(timezone.utc)


class Cancelled(Exception):
    pass


class StageWarning(Exception):
    """Raise from a stage to finish it in the warning state with a reason."""

    def __init__(self, badge: str, message: str):
        super().__init__(message)
        self.badge = badge
        self.message = message


class Ctx:
    """What a stage sees: config, earlier artifacts, a logger and token accounting."""

    def __init__(self, run_id: str, stage: str):
        self.run_id = run_id
        self.stage = stage
        with SessionLocal() as db:
            run = db.get(Run, run_id)
            self.config: dict = dict(run.config or {})
            self.artifacts: dict = dict(run.artifacts or {})
            self.research_id = run.research_id
            self.mode = run.mode
        self.tokens = 0

    def log(self, message: str, level: str = "info") -> None:
        with SessionLocal() as db:
            db.add(RunLog(run_id=self.run_id, stage=self.stage, level=level, message=message[:2000]))
            db.commit()

    def refresh_config(self) -> dict:
        with SessionLocal() as db:
            self.config = dict(db.get(Run, self.run_id).config or {})
        return self.config

    def check_cancel(self) -> None:
        with SessionLocal() as db:
            if db.get(Run, self.run_id).status == "cancelled":
                raise Cancelled()

    def progress(self, badge: str) -> None:
        _set_stage(self.run_id, self.stage, badge=badge)


def _set_stage(run_id: str, stage: str, **fields) -> None:
    with _lock(run_id):
        with SessionLocal() as db:
            run = db.get(Run, run_id)
            ss = dict(run.stage_status or {})
            cur = dict(ss.get(stage, {}))
            cur.update(fields)
            ss[stage] = cur
            run.stage_status = ss
            if fields.get("state") == "running":
                run.stage = stage
            db.commit()


def _save_artifact(run_id: str, stage: str, data, tokens: int) -> None:
    with _lock(run_id):
        with SessionLocal() as db:
            run = db.get(Run, run_id)
            arts = dict(run.artifacts or {})
            arts[stage] = data
            run.artifacts = arts
            run.cost_tokens = (run.cost_tokens or 0) + tokens
            db.commit()


# --------------------------------------------------------------------------- run budget (spec section 12)

BUDGET_KEY = "_budget"  # marker kept in Run.stage_status (not a stage) so state changes are logged once


def _parse(ts) -> datetime | None:
    if not ts:
        return None
    if isinstance(ts, datetime):
        dt = ts
    else:
        try:
            dt = datetime.fromisoformat(str(ts))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def elapsed_seconds(run: Run, at: datetime | None = None) -> float:
    """Wall-clock time spent executing: the union of stage intervals (IoC enrichment overlaps the main chain, and
    idle time between a failure and a retry is not counted). Falls back to started_at..finished_at."""
    at = at or now()
    spans = []
    for sid in STAGE_IDS:
        st = (run.stage_status or {}).get(sid) or {}
        start = _parse(st.get("started_at"))
        if start is None:
            continue
        end = _parse(st.get("finished_at")) or (at if st.get("state") == "running" else None)
        if end is None:
            continue
        spans.append((start, max(start, end)))
    if not spans:
        start, end = _parse(run.started_at), _parse(run.finished_at) or at
        return max(0.0, (end - start).total_seconds()) if start else 0.0
    spans.sort()
    total, cur_s, cur_e = 0.0, spans[0][0], spans[0][1]
    for s, e in spans[1:]:
        if s <= cur_e:
            cur_e = max(cur_e, e)
        else:
            total += (cur_e - cur_s).total_seconds()
            cur_s, cur_e = s, e
    return total + (cur_e - cur_s).total_seconds()


def budget_limits(depth: str | None) -> dict:
    budgets = get_settings().run_budgets
    b = budgets.get(depth or "standard") or budgets.get("standard") or {"max_minutes": 10, "max_tokens": 600_000}
    return {"max_minutes": float(b.get("max_minutes", 10)), "max_tokens": int(b.get("max_tokens", 600_000))}


def budget_state(depth: str | None, elapsed_s: float, tokens: int, warn_pct: float | None = None) -> dict:
    """Budget meter: percentages of the per-depth limits and ok | warning (>= warn_pct) | over (>= 100 %)."""
    lim = budget_limits(depth)
    warn_pct = get_settings().budget_warn_pct if warn_pct is None else warn_pct
    minutes = elapsed_s / 60.0
    pct_time = round(100.0 * minutes / lim["max_minutes"], 1) if lim["max_minutes"] > 0 else 0.0
    pct_tokens = round(100.0 * (tokens or 0) / lim["max_tokens"], 1) if lim["max_tokens"] > 0 else 0.0
    worst = max(pct_time, pct_tokens)
    state = "over" if worst >= 100.0 else "warning" if worst >= warn_pct else "ok"
    return {"depth": depth or "standard", "max_minutes": lim["max_minutes"], "max_tokens": lim["max_tokens"],
            "elapsed_minutes": round(minutes, 2), "tokens": int(tokens or 0), "pct_time": pct_time, "pct_tokens": pct_tokens,
            "state": state, "enforced": get_settings().budget_enforce}


def run_budget(run: Run, at: datetime | None = None) -> dict:
    b = budget_state((run.config or {}).get("depth"), elapsed_seconds(run, at), run.cost_tokens or 0)
    mark = (run.stage_status or {}).get(BUDGET_KEY) or {}
    b["flagged"] = mark.get("state")  # worst state reached and logged during execution, if any
    b["stopped"] = bool(mark.get("stopped"))
    return b


def _check_budget(run_id: str, stage: str, final: bool = False) -> bool:
    """Called between stages. Logs a warning at warn_pct and an error when over budget (once each). Returns False only
    when `budget_enforce` is on and the run is over budget, so the caller stops."""
    with _lock(run_id):
        with SessionLocal() as db:
            run = db.get(Run, run_id)
            if run is None or run.mode == "manual":
                return True
            b = run_budget(run)
            ss = dict(run.stage_status or {})
            mark = dict(ss.get(BUDGET_KEY) or {})
            rank = {"ok": 0, "warning": 1, "over": 2}
            detail = (f"{b['elapsed_minutes']:.1f}/{b['max_minutes']:g} min ({b['pct_time']:.0f}%), "
                      f"{b['tokens']:,}/{b['max_tokens']:,} tokens ({b['pct_tokens']:.0f}%)")
            stop = b["state"] == "over" and get_settings().budget_enforce and not mark.get("override") and not final
            if rank[b["state"]] > rank.get(mark.get("state", "ok"), 0):
                if b["state"] == "warning":
                    msg = f"Run budget at {max(b['pct_time'], b['pct_tokens']):.0f}% ({b['depth']} depth): {detail}"
                    db.add(RunLog(run_id=run_id, stage=stage, level="warn", message=msg))
                    log.warning("run %s: %s", run_id, msg)
                else:
                    msg = (f"Run over budget ({b['depth']} depth): {detail}. "
                           + ("Stopping: budget enforcement is on." if stop else ("The run continues (budget is not enforced)." if not get_settings().budget_enforce else "The run continues (retry override).") if not final else ""))
                    db.add(RunLog(run_id=run_id, stage=stage, level="error", message=msg))
                    log.error("run %s: %s", run_id, msg)
                mark.update(state=b["state"], at=now().isoformat(), stage=stage)
            if stop:
                mark["stopped"] = True
            if mark:
                ss[BUDGET_KEY] = mark
                run.stage_status = ss
            db.commit()
            return not stop


def _step(run_id: str, stage: str) -> bool:
    """Budget gate, then the stage."""
    if not _check_budget(run_id, stage):
        _set_stage(run_id, stage, state="failed", finished_at=None,
                   message="Not started: the run is over its budget and budget enforcement is on. Retry this stage to continue.")
        return False
    return _run_stage(run_id, stage)


def _run_stage(run_id: str, stage: str) -> bool:
    """Run one stage. Returns False if the run must stop (failure or cancel)."""
    from . import stages as S

    fn = getattr(S, f"stage_{stage}")
    started = now()
    _set_stage(run_id, stage, state="running", started_at=started.isoformat(), finished_at=None, message=None, badge=None)
    ctx = Ctx(run_id, stage)
    try:
        ctx.check_cancel()
        data, badge = fn(ctx)
        _save_artifact(run_id, stage, data, ctx.tokens)
        _set_stage(run_id, stage, state="done", finished_at=now().isoformat(), badge=badge)
        return True
    except StageWarning as w:
        data = getattr(w, "data", None)
        if data is not None:
            _save_artifact(run_id, stage, data, ctx.tokens)
        _set_stage(run_id, stage, state="warning", finished_at=now().isoformat(), badge=w.badge, message=w.message)
        ctx.log(w.message, "warn")
        return True
    except Cancelled:
        _set_stage(run_id, stage, state="pending", started_at=None)
        return False
    except Exception as e:  # noqa: BLE001 - surface any stage error to the hunter with a retry
        log.exception("stage %s failed", stage)
        ctx.log(f"{type(e).__name__}: {e}", "error")
        ctx.log(traceback.format_exc(limit=3), "debug")
        _set_stage(run_id, stage, state="failed", finished_at=now().isoformat(), message=str(e)[:400])
        return False


def execute_run(run_id: str, from_stage: str = "intake") -> None:
    if run_id in _active:
        return
    _active.add(run_id)
    try:
        with SessionLocal() as db:
            run = db.get(Run, run_id)
            run.status = "running"
            run.started_at = run.started_at or now()
            run.finished_at = None
            ss = dict(run.stage_status or {})
            start_idx = STAGE_IDS.index(from_stage)
            for s in STAGE_IDS[start_idx:]:
                ss[s] = {"state": "pending"}
            mark = ss.get(BUDGET_KEY)
            if mark and mark.get("state") == "over":
                # A hunter-initiated retry of an over-budget run is an explicit override: finish without stopping again.
                ss[BUDGET_KEY] = {**mark, "override": True, "stopped": False}
            run.stage_status = ss
            r = db.get(Research, run.research_id)
            if r and r.status in ("draft", "failed", "running"):
                r.status = "running"
            db.commit()

        todo = STAGE_IDS[STAGE_IDS.index(from_stage):]
        ok = True
        for s in ["intake", "discovery", "extraction"]:
            if s in todo and ok:
                ok = _step(run_id, s)

        if ok:
            chain = [s for s in MAIN_CHAIN if s in todo]
            ioc_thread = None
            ioc_ok = [True]
            if "iocs" in todo:
                def _iocs():
                    ioc_ok[0] = _run_stage(run_id, "iocs")
                ioc_thread = threading.Thread(target=_iocs, name=f"iocs-{run_id}")
                ioc_thread.start()
            for s in chain:
                if ok:
                    ok = _step(run_id, s)
            if ioc_thread:
                ioc_thread.join()
                ok = ok and ioc_ok[0]

        for s in ["report", "export"]:
            if s in todo and ok:
                ok = _step(run_id, s)

        _check_budget(run_id, "export", final=True)  # final reading, logs an overrun that happened in the last stage
        with SessionLocal() as db:
            run = db.get(Run, run_id)
            r = db.get(Research, run.research_id)
            if run.status == "cancelled":
                if r and r.status == "running":
                    r.status = "draft"
            elif ok:
                run.status = "done"
                if r and r.status == "running":
                    r.status = "draft"
            else:
                run.status = "failed"
                if r and r.status == "running":
                    r.status = "failed" if not r.record else "draft"
            run.finished_at = now()
            db.commit()
    finally:
        _active.discard(run_id)


def submit(run_id: str, from_stage: str = "intake") -> None:
    _pool.submit(execute_run, run_id, from_stage)


def is_active(run_id: str) -> bool:
    return run_id in _active
