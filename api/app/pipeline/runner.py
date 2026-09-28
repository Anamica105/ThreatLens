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
            run.stage_status = ss
            r = db.get(Research, run.research_id)
            if r and r.status in ("draft", "failed", "running"):
                r.status = "running"
            db.commit()

        todo = STAGE_IDS[STAGE_IDS.index(from_stage):]
        ok = True
        for s in ["intake", "discovery", "extraction"]:
            if s in todo and ok:
                ok = _run_stage(run_id, s)

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
                    ok = _run_stage(run_id, s)
            if ioc_thread:
                ioc_thread.join()
                ok = ok and ioc_ok[0]

        for s in ["report", "export"]:
            if s in todo and ok:
                ok = _run_stage(run_id, s)

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
