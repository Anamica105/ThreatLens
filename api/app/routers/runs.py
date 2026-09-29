from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, iso
from ..models import Research, Run, RunLog, User
from ..pipeline import runner
from ..records import log_activity

router = APIRouter(prefix="/api/runs", tags=["runs"])


def _run(db: Session, run_id: str) -> Run:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    return run


@router.get("/{run_id}")
def get_run(run_id: str, after_log: int = 0, db: Session = Depends(get_db)):
    run = _run(db, run_id)
    r = db.get(Research, run.research_id)
    logs = db.query(RunLog).filter(RunLog.run_id == run_id, RunLog.id > after_log).order_by(RunLog.id).limit(500).all()
    arts = run.artifacts or {}
    sources = []
    ext = (arts.get("extraction") or {}).get("results", {})
    excluded = set((run.config or {}).get("excluded_sources", []))
    for s in (arts.get("discovery") or {}).get("sources", []):
        e = ext.get(s["id"], {})
        sources.append({"id": s["id"], "url": s["url"], "title": (e.get("fetch") or {}).get("title") or s.get("title") or s["url"],
                        "publisher": s["publisher"], "reliability": s.get("reliability"), "origin": s.get("origin"),
                        "excluded": s["id"] in excluded,
                        "state": "read" if e.get("ok") else ("excluded" if s["id"] in excluded else ("failed" if e else "pending"))})
    return {
        "id": run.id, "research_id": run.research_id, "title": r.title if r else "", "status": run.status, "mode": run.mode,
        "stage": run.stage, "config": run.config, "started_at": iso(run.started_at), "finished_at": iso(run.finished_at),
        "tokens": run.cost_tokens, "active": runner.is_active(run.id),
        "stages": [{"id": sid, "label": label, **(run.stage_status or {}).get(sid, {"state": "pending"})} for sid, label in runner.STAGES],
        "logs": [{"id": x.id, "stage": x.stage, "level": x.level, "message": x.message, "created_at": iso(x.created_at)} for x in logs],
        "sources": sources,
        "budget": runner.run_budget(run),
    }


@router.get("/{run_id}/budget")
def get_budget(run_id: str, db: Session = Depends(get_db)):
    return runner.run_budget(_run(db, run_id))


class RetryIn(BaseModel):
    stage: str


@router.post("/{run_id}/retry")
def retry(run_id: str, body: RetryIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    run = _run(db, run_id)
    if body.stage not in runner.STAGE_IDS:
        raise HTTPException(422, "Unknown stage")
    if runner.is_active(run_id):
        raise HTTPException(409, "The run is still in progress")
    idx = runner.STAGE_IDS.index(body.stage)
    missing = [s for s in runner.STAGE_IDS[:idx] if s not in (run.artifacts or {}) and s not in ("report", "export", "iocs")]
    if missing:
        raise HTTPException(409, f"Earlier stages have no output yet: {', '.join(missing)}")
    run.status = "queued"
    log_activity(db, run.research_id, "created", f"Stage retried: {dict(runner.STAGES)[body.stage]} by {user.name}", user.id)
    db.commit()
    runner.submit(run_id, body.stage)
    return {"ok": True}


@router.post("/{run_id}/cancel")
def cancel(run_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    run = _run(db, run_id)
    if run.status not in ("running", "queued"):
        raise HTTPException(409, "Run is not in progress")
    run.status = "cancelled"
    log_activity(db, run.research_id, "status", f"Run cancelled by {user.name}", user.id)
    db.commit()
    return {"ok": True}


class ExcludeIn(BaseModel):
    excluded: bool


@router.post("/{run_id}/sources/{sid}")
def exclude_source(run_id: str, sid: str, body: ExcludeIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    run = _run(db, run_id)
    cfg = dict(run.config or {})
    ex = set(cfg.get("excluded_sources", []))
    (ex.add if body.excluded else ex.discard)(sid)
    cfg["excluded_sources"] = sorted(ex)
    run.config = cfg
    db.add(RunLog(run_id=run_id, stage=run.stage, level="info", message=f"{sid} {'excluded' if body.excluded else 'included'} by {user.name}"))
    db.commit()
    return {"excluded_sources": cfg["excluded_sources"]}
