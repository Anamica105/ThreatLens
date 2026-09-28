from __future__ import annotations

import copy
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query as Q
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import detection, llm
from ..db import get_db
from ..deps import REVIEW_ROLES, current_user, iso, research_summary, user_dict, workspace_dict
from ..exports import context as export_ctx
from ..exports import render
from ..models import ActivityEvent, ExportLog, Query, Research, ResearchVersion, Result, Run, RunLog, User, Workspace
from ..pipeline import runner
from ..records import backfill_provenance, log_activity, new_research_id, save_record, tactic_rail

router = APIRouter(prefix="/api/research", tags=["research"])


def _get(db: Session, rid: str) -> Research:
    r = db.get(Research, rid)
    if r is None:
        raise HTTPException(404, "This research doesn't exist. It may have been archived or the link is wrong.")
    return r


def _users(db: Session) -> dict[str, User]:
    return {u.id: u for u in db.query(User).all()}


# ------------------------------------------------------------------ list / search

@router.get("")
def list_research(
    db: Session = Depends(get_db), ws: str | None = None, q: str | None = None, status: list[str] = Q(default=[]),
    severity: list[str] = Q(default=[]), classification: list[str] = Q(default=[]), actor: str | None = None,
    industry: str | None = None, platform: str | None = None, result: list[str] = Q(default=[]), author: str | None = None,
    date_from: str | None = Q(default=None, alias="from"), date_to: str | None = Q(default=None, alias="to"),
    cve: str | None = None, technique: str | None = None, tactic: str | None = None,
    sort: str = "-created_at", page: int = 1, page_size: int = 50,
):
    query = db.query(Research)
    if status:
        query = query.filter(Research.status.in_(status))
    else:
        query = query.filter(Research.status != "archived")
    if severity:
        query = query.filter(Research.severity.in_(severity))
    if author:
        query = query.filter(Research.created_by == author)
    if date_from:
        query = query.filter(Research.created_at >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.filter(Research.created_at <= datetime.fromisoformat(date_to + "T23:59:59"))
    if q:
        for term in q.lower().split():
            query = query.filter(or_(Research.search_text.contains(term), Research.id.ilike(f"%{term}%")))
    rows = query.all()

    def keep(r: Research) -> bool:
        rec = r.record or {}
        if ws and ws != "all" and ws not in (r.workspace_ids or []):
            return False
        if classification and not set(classification) & set(r.classification or []):
            return False
        if actor and not any(actor.lower() in [a["name"].lower()] + [x.lower() for x in a.get("aliases", [])] for a in rec.get("threat_actors", [])):
            return False
        if industry and not any(industry.lower() == i["industry"].lower() for i in rec.get("industries", [])):
            return False
        if platform and platform not in rec.get("hunts", {}).get("platforms", []):
            return False
        if cve and cve.upper() not in [v["cve"] for v in rec.get("vulnerabilities", [])]:
            return False
        if technique and technique.upper() not in [m["technique_id"] for m in rec.get("mitre", [])]:
            return False
        if tactic and tactic not in [m["tactic_id"] for m in rec.get("mitre", [])]:
            return False
        return True

    rows = [r for r in rows if keep(r)]
    results = db.query(Result).filter(Result.research_id.in_([r.id for r in rows])).all() if rows else []
    by_r: dict[str, list[Result]] = {}
    for x in results:
        by_r.setdefault(x.research_id, []).append(x)
    if result and ws and ws != "all":
        rows = [r for r in rows if any(x.workspace_id == ws and x.status in result for x in by_r.get(r.id, []))]
    elif result:
        rows = [r for r in rows if any(x.status in result for x in by_r.get(r.id, []))]

    desc = sort.startswith("-")
    key = sort.lstrip("-")
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    keyf = {
        "created_at": lambda r: iso(r.created_at) or "",
        "updated_at": lambda r: iso(r.updated_at) or "",
        "severity": lambda r: sev_rank.get(r.severity, 0), "id": lambda r: r.id, "title": lambda r: r.title.lower(),
        "status": lambda r: r.status, "iocs": lambda r: len((r.record or {}).get("iocs", [])),
    }.get(key, lambda r: iso(r.created_at) or "")
    rows.sort(key=keyf, reverse=desc)
    total = len(rows)
    page_rows = rows[(page - 1) * page_size: page * page_size]
    users = _users(db)
    return {"total": total, "page": page, "page_size": page_size,
            "items": [research_summary(r, by_r.get(r.id, []), users, ws if ws != "all" else None) for r in page_rows]}


class DupCheck(BaseModel):
    seed: str
    seed_urls: list[str] = []


@router.post("/check-duplicates")
def check_duplicates(body: DupCheck, db: Session = Depends(get_db)):
    text = body.seed + " " + " ".join(body.seed_urls)
    cves = {c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)}
    matches = []
    for r in db.query(Research).filter(Research.status != "archived").all():
        rec = r.record or {}
        rc = {v["cve"] for v in rec.get("vulnerabilities", [])}
        names = {a["name"].lower() for a in rec.get("threat_actors", [])} | {x.lower() for a in rec.get("threat_actors", []) for x in a.get("aliases", [])}
        urls = {s.get("url") for s in rec.get("sources", [])}
        hit = sorted(cves & rc)
        why = [f"covers {', '.join(hit)}"] if hit else []
        named = [n for n in names if n and re.search(rf"\b{re.escape(n)}\b", text, re.I)]
        if named:
            why.append(f"covers {named[0].title()}")
        if set(body.seed_urls) & urls:
            why.append("uses the same source URL")
        if why:
            matches.append({"id": r.id, "title": r.title, "status": r.status, "reason": "; ".join(why)})
    return {"matches": matches[:5]}


# ------------------------------------------------------------------ create run

class NewRun(BaseModel):
    seed: str = Field(min_length=3)
    seed_urls: list[str] = []
    workspace_ids: list[str] = Field(min_length=1)
    platforms: list[str] = Field(min_length=1)
    vendors: list[str] | None = None
    open_web: bool = True
    depth: str = "standard"
    lookback_days: int = 30
    include_generic_hunts: bool = False  # generic (not threat-specific) TTP hunts are opt-in and capped
    tlp: str = "AMBER"
    draft: bool = False
    offline: bool = False


@router.post("")
def create_research(body: NewRun, db: Session = Depends(get_db), user: User = Depends(current_user)):
    bad = [p for p in body.platforms if p not in detection.PLATFORM_IDS]
    if bad:
        raise HTTPException(422, f"Unknown output platform(s): {', '.join(bad)}")
    rid = new_research_id(db)
    first = next((ln.strip() for ln in body.seed.splitlines() if ln.strip()), "Untitled threat")
    title = re.split(r"(?<=[.!?])\s", first, maxsplit=1)[0].rstrip(".")
    title = title if len(title) <= 100 else title[:99].rsplit(" ", 1)[0] + "…"
    r = Research(id=rid, title=title, status="draft" if body.draft else "running", created_by=user.id,
                 workspace_ids=body.workspace_ids, seed=body.seed, tlp=body.tlp,
                 record={}, search_text=title.lower())
    db.add(r)
    db.flush()
    run_id = f"RUN-{rid}-{uuid.uuid4().hex[:6]}"
    mode = "offline" if body.offline or not llm.available() else "llm"
    db.add(Run(id=run_id, research_id=rid, seed=body.seed, mode=mode,
               config={**body.model_dump(exclude={"draft", "offline"}), "excluded_sources": []},
               stage_status={s: {"state": "pending"} for s in runner.STAGE_IDS}))
    log_activity(db, rid, "created", "Saved as draft" if body.draft else "Research started", user.id)
    db.commit()
    if not body.draft:
        runner.submit(run_id)
    return {"id": rid, "run_id": run_id, "mode": mode}


@router.post("/{rid}/start")
def start_draft(rid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    run = db.query(Run).filter_by(research_id=rid).order_by(Run.started_at.desc().nullsfirst()).first()
    if run is None:
        raise HTTPException(409, "No run configuration saved for this draft")
    r.status = "running"
    log_activity(db, rid, "created", "Research started", user.id)
    db.commit()
    runner.submit(run.id)
    return {"id": rid, "run_id": run.id}


# ------------------------------------------------------------------ detail

@router.get("/{rid}")
def get_research(rid: str, db: Session = Depends(get_db), ws: str | None = None):
    r = _get(db, rid)
    results = db.query(Result).filter_by(research_id=rid).all()
    users = _users(db)
    run = db.query(Run).filter_by(research_id=rid).order_by(Run.started_at.desc().nullslast()).first()
    workspaces = {w.id: workspace_dict(w) for w in db.query(Workspace).filter(Workspace.id.in_(r.workspace_ids or [])).all()}
    related = []
    for oid in (r.record or {}).get("related_research_ids", []):
        o = db.get(Research, oid)
        if o:
            related.append({"id": o.id, "title": o.title, "severity": o.severity, "status": o.status})
    return {
        **research_summary(r, results, users, ws),
        # Records saved before queries/opportunities carried a source trail get it filled in on read.
        "record": backfill_provenance(copy.deepcopy(r.record or {})), "seed": r.seed,
        "reviewed_by": user_dict(users.get(r.reviewed_by)),
        "results": [{"workspace_id": x.workspace_id, "status": x.status, "summary": x.summary, "hunt_window": x.hunt_window,
                     "queries_run": x.queries_run, "analyst": user_dict(users.get(x.analyst_id)), "updated_at": iso(x.updated_at)} for x in results],
        "workspaces": workspaces, "related": related,
        "run": {"id": run.id, "status": run.status, "mode": run.mode, "config": run.config, "tokens": run.cost_tokens,
                "started_at": iso(run.started_at), "finished_at": iso(run.finished_at), "active": runner.is_active(run.id)} if run else None,
        "rail": tactic_rail(r.record or {}),
    }


# ------------------------------------------------------------------ editing

class RecordPatch(BaseModel):
    changes: dict
    summary: str = ""


EDITABLE = {"title", "executive_summary", "impact", "recommendations", "mitre", "industries", "tlp", "severity", "confidence",
            "classification", "study", "iocs", "tags", "attack_paths", "timeline", "claims", "tools_used", "geography",
            "vulnerabilities", "threat_actors", "malware_tools", "ioas", "detection_opportunities", "patching_insufficient"}


@router.patch("/{rid}/record")
def patch_record(rid: str, body: RecordPatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    if r.status == "archived":
        raise HTTPException(409, "Archived research is read-only. Restore it first.")
    bad = set(body.changes) - EDITABLE
    if bad:
        raise HTTPException(422, f"Not editable: {', '.join(sorted(bad))}")
    rec = copy.deepcopy(r.record or {})
    rec.update(body.changes)
    if "severity" in body.changes and isinstance(rec.get("impact"), dict):
        rec["impact"]["severity"] = body.changes["severity"]
    rec["_edited"] = sorted(set(rec.get("_edited", [])) | set(body.changes))
    review = rec.setdefault("review", {})
    for k in body.changes:
        if k in review:
            review[k] = "edited"
    if r.status == "published":
        r.status = "in_review"
        log_activity(db, rid, "status", f"Moved back to review after edits by {user.name}", user.id)
    save_record(db, r, rec, user.id, body.summary or f"Edited {', '.join(sorted(body.changes))}")
    log_activity(db, rid, "edited", f"v{r.version} · {len(body.changes)} section(s) changed by {user.name}", user.id,
                 sections=sorted(body.changes))
    db.commit()
    return {"version": r.version, "record": r.record}


class ReviewMark(BaseModel):
    section: str
    state: str = "approved"


REVIEW_STATES = ("generated", "edited", "approved")


@router.post("/{rid}/review")
def mark_review(rid: str, body: ReviewMark, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Mark one report section's review state. Reviewers, leads and admins only (403 otherwise)."""
    if user.role not in REVIEW_ROLES:
        raise HTTPException(403, "Only reviewers, leads and admins can mark sections as reviewed.")
    if body.state not in REVIEW_STATES:
        raise HTTPException(422, f"Invalid review state. Use one of: {', '.join(REVIEW_STATES)}.")
    r = _get(db, rid)
    if r.status == "archived":
        raise HTTPException(409, "Archived research is read-only. Restore it first.")
    rec = copy.deepcopy(r.record or {})
    rec.setdefault("review", {})[body.section] = body.state
    r.record = rec
    log_activity(db, rid, "edited", f"Section {body.section.replace('_', ' ')} marked {body.state} by {user.name}", user.id,
                 section=body.section)
    db.commit()
    return {"review": rec["review"]}


class StatusChange(BaseModel):
    action: str  # submit, publish, archive, restore, reopen
    note: str = ""


@router.post("/{rid}/status")
def change_status(rid: str, body: StatusChange, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    rec = r.record or {}
    if body.action == "submit":
        if r.status not in ("draft", "failed"):
            raise HTTPException(409, f"Only drafts can be submitted for review (status is {r.status}).")
        if not rec:
            raise HTTPException(409, "The run has not produced a report yet.")
        r.status = "in_review"
        msg = f"Review requested by {user.name}"
    elif body.action == "publish":
        if user.role not in REVIEW_ROLES:
            raise HTTPException(403, "Only reviewers, leads and admins can publish. Submit for review instead.")
        if r.status != "in_review":
            hint = " Submit it for review first." if r.status in ("draft", "failed") else ""
            raise HTTPException(409, f"Only research in review can be published (status is {r.status}).{hint}")
        blockers = []
        disputed = [c for c in rec.get("conflicts", []) if c.get("status") == "disputed"]
        if disputed:
            blockers.append(f"{len(disputed)} disputed claim(s) need a status")
        unsupported = [c for c in rec.get("claims", []) if not c.get("source_ids")]
        if unsupported:
            blockers.append(f"{len(unsupported)} unsupported claim(s) must be edited or removed")
        if blockers:
            raise HTTPException(409, "Cannot publish: " + "; ".join(blockers))
        r.status = "published"
        r.reviewed_by = user.id
        r.published_at = datetime.now(timezone.utc)
        new = copy.deepcopy(rec)
        new["status"] = "published"
        new["review"] = {k: "approved" for k in new.get("review", {})}
        msg = f"Published by {user.name}"
        # Publishing is a versioned edit like any other: it writes a ResearchVersion row (and re-syncs the libraries).
        save_record(db, r, new, user.id, msg + (f": {body.note}" if body.note else ""))
    elif body.action == "archive":
        r.status = "archived"
        msg = f"Archived by {user.name}"
    elif body.action in ("restore", "reopen"):
        r.status = "draft" if body.action == "restore" else "in_review"
        msg = f"{'Restored' if body.action == 'restore' else 'Reopened'} by {user.name}"
    else:
        raise HTTPException(422, "Unknown action")
    if r.record:
        r.record = {**r.record, "status": r.status}
    log_activity(db, rid, "status", msg + (f": {body.note}" if body.note else ""), user.id)
    db.commit()
    return {"status": r.status}


class BulkAction(BaseModel):
    ids: list[str]
    action: str


@router.post("/bulk")
def bulk(body: BulkAction, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if body.action != "archive":
        raise HTTPException(422, "Only archive is supported in bulk")
    n = 0
    for rid in body.ids:
        r = db.get(Research, rid)
        if r and r.status != "archived":
            r.status = "archived"
            log_activity(db, rid, "status", f"Archived by {user.name}", user.id)
            n += 1
    db.commit()
    return {"archived": n}


class ResultIn(BaseModel):
    status: str
    summary: str = ""
    hunt_window: str = ""
    queries_run: list[str] = []


@router.put("/{rid}/results/{ws_id}")
def set_result(rid: str, ws_id: str, body: ResultIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if body.status not in ("no_evidence", "suspicious", "confirmed", "not_applicable", "pending"):
        raise HTTPException(422, "Invalid result status")
    r = _get(db, rid)
    ws = db.get(Workspace, ws_id)
    if ws is None:
        raise HTTPException(404, "Workspace not found")
    row = db.query(Result).filter_by(research_id=rid, workspace_id=ws_id).first()
    if row is None:
        row = Result(research_id=rid, workspace_id=ws_id)
        db.add(row)
        if ws_id not in (r.workspace_ids or []):
            r.workspace_ids = list(r.workspace_ids or []) + [ws_id]
    row.status, row.summary, row.hunt_window, row.queries_run = body.status, body.summary, body.hunt_window, body.queries_run
    row.analyst_id = user.id
    row.updated_at = datetime.now(timezone.utc)
    db.flush()
    rows = db.query(Result).filter_by(research_id=rid).all()
    r.record = {**(r.record or {}), "results": [{"workspace_id": x.workspace_id, "status": x.status, "summary": x.summary,
                                                 "hunt_window": x.hunt_window, "queries_run": x.queries_run, "analyst": x.analyst_id} for x in rows]}
    log_activity(db, rid, "result", f"Hunt result for {ws.name}: {body.status.replace('_', ' ')}", user.id, workspace_id=ws_id)
    db.commit()
    return {"ok": True}


class ConflictStatus(BaseModel):
    status: str
    resolution: str | None = None


@router.patch("/{rid}/conflicts/{idx}")
def set_conflict(rid: str, idx: int, body: ConflictStatus, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    rec = copy.deepcopy(r.record or {})
    conflicts = rec.get("conflicts", [])
    if idx >= len(conflicts):
        raise HTTPException(404, "Conflict not found")
    if body.status not in ("confirmed", "disputed", "superseded"):
        raise HTTPException(422, "Invalid status")
    conflicts[idx]["status"] = body.status
    if body.resolution is not None:
        conflicts[idx]["resolution"] = body.resolution
    save_record(db, r, rec, user.id, f"Claim status set to {body.status}")
    log_activity(db, rid, "edited", f"Claim \"{conflicts[idx]['topic']}\" marked {body.status} by {user.name}", user.id)
    db.commit()
    return {"conflicts": conflicts}


class QueryPatch(BaseModel):
    status: str | None = None
    body: str | None = None
    fp_notes: str | None = None


@router.get("/{rid}/queries")
def list_queries(rid: str, db: Session = Depends(get_db), ws: str | None = None, platform: str | None = None,
                 group: str | None = None, include_reference: bool = True):
    """The research's hunt queries. With `ws=<workspace id>` each query also carries that workspace's field mappings
    applied server-side: `mapped_body`, `mapped_lint` (lint re-run on the mapped text) and `mapping_applied`."""
    r = _get(db, rid)
    w = None
    if ws and ws != "all":
        w = db.get(Workspace, ws)
        if w is None:
            raise HTTPException(404, "Workspace not found")
    rec = backfill_provenance(copy.deepcopy(r.record or {}))
    items = []
    for q in (rec.get("hunts") or {}).get("queries", []):
        if platform and q.get("platform") != platform:
            continue
        if group and q.get("group") != group:
            continue
        if not include_reference and q.get("origin") == "reference":
            continue
        items.append({**q, **(detection.map_query(q, w.field_mappings or {}) if w else {})})
    return {"research_id": rid, "workspace_id": w.id if w else None,
            "field_mappings": (w.field_mappings or {}) if w else None, "statuses": detection.QUERY_STATUSES,
            "total": len(items), "items": items}


def _record_query(r: Research, qid: str) -> dict | None:
    return next((x for x in (r.record or {}).get("hunts", {}).get("queries", []) if x["id"] == qid), None)


@router.patch("/{rid}/queries/{qid}")
def patch_query(rid: str, qid: str, body: QueryPatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Edit a query body / fp notes or move its status (detection.QUERY_STATUSES). 422 for an unknown status; 409 when
    the status needs a clean lint (syntax_checked and later) but the query fails lint, or for misuse of 'reference'."""
    r = _get(db, rid)
    if r.status == "archived":
        raise HTTPException(409, "Archived research is read-only. Restore it first.")
    rec = copy.deepcopy(r.record or {})
    for q in rec.get("hunts", {}).get("queries", []):
        if q["id"] == qid:
            origin = q.get("origin", "generated")
            new_body = body.body if body.body is not None else q.get("body", "")
            issues = [] if origin == "reference" else detection.lint(q["platform"], new_body, q.get("techniques"))
            if body.status:
                why = detection.check_status_change(body.status, origin=origin, lint_issues=issues)
                if why:
                    raise HTTPException(422 if "Unknown query status" in why else 409, why)
            if body.body is not None:
                q["body"] = body.body
                q["lint"] = issues
                if origin != "reference":
                    q["status"] = "syntax_checked" if not issues else "generated"
            if body.status:
                q["status"] = body.status
            if body.fp_notes is not None:
                q["fp_notes"] = body.fp_notes
            save_record(db, r, rec, user.id, f"Query {qid} updated")
            saved = _record_query(r, qid) or q
            # sync_library keeps the more advanced status; an explicit change here (including a demotion, or a body
            # edit that resets the status) is authoritative for the library row too.
            row = db.get(Query, qid)
            if row is not None and (body.status or body.body is not None):
                row.status = saved.get("status", row.status)
            log_activity(db, rid, "edited", f"Query {qid} {('marked ' + body.status) if body.status else 'edited'} by {user.name}", user.id)
            db.commit()
            return saved
    raise HTTPException(404, "Query not found")


class SourceToggle(BaseModel):
    included: bool


@router.post("/{rid}/sources/{sid}")
def toggle_source(rid: str, sid: str, body: SourceToggle, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    if r.status not in ("draft", "running", "failed"):
        raise HTTPException(409, "Sources can only be changed while the research is a draft.")
    run = db.query(Run).filter_by(research_id=rid).order_by(Run.started_at.desc().nullslast()).first()
    if run:
        cfg = dict(run.config or {})
        ex = set(cfg.get("excluded_sources", []))
        (ex.discard if body.included else ex.add)(sid)
        cfg["excluded_sources"] = sorted(ex)
        run.config = cfg
    rec = copy.deepcopy(r.record or {})
    for s in rec.get("sources", []):
        if s["id"] == sid:
            s["included"] = body.included
    r.record = rec
    log_activity(db, rid, "edited", f"Source {sid} {'included in' if body.included else 'excluded from'} synthesis by {user.name}", user.id)
    db.commit()
    return {"ok": True, "rerun_needed": True}


class Rerun(BaseModel):
    from_stage: str = "synthesis"
    platforms: list[str] | None = None
    workspace_ids: list[str] | None = None
    include_generic_hunts: bool | None = None


@router.post("/{rid}/rerun")
def rerun(rid: str, body: Rerun, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    if body.from_stage not in runner.STAGE_IDS:
        raise HTTPException(422, "Unknown stage")
    run = db.query(Run).filter_by(research_id=rid).order_by(Run.started_at.desc().nullslast()).first()
    if run is None or run.mode == "manual" or not run.artifacts:
        # No stored stage outputs (e.g. imported record): start a full fresh run from the seed.
        cfg = dict(run.config) if run else {}
        cfg.setdefault("seed", r.seed)
        cfg.setdefault("seed_urls", [s["url"] for s in (r.record or {}).get("sources", []) if s.get("url")])
        cfg.setdefault("workspace_ids", r.workspace_ids)
        cfg.setdefault("depth", "standard")
        cfg.setdefault("lookback_days", 30)
        cfg.setdefault("tlp", r.tlp)
        cfg.setdefault("excluded_sources", [])
        if body.platforms:
            cfg["platforms"] = body.platforms
        if body.include_generic_hunts is not None:
            cfg["include_generic_hunts"] = body.include_generic_hunts
        if not cfg.get("platforms"):
            from ..pipeline.stages import workspace_platforms
            cfg["platforms"] = workspace_platforms(db, cfg.get("workspace_ids") or r.workspace_ids)
        run = Run(id=f"RUN-{rid}-{uuid.uuid4().hex[:6]}", research_id=rid, seed=r.seed, config=cfg,
                  mode="llm" if llm.available() else "offline", stage_status={s: {"state": "pending"} for s in runner.STAGE_IDS})
        db.add(run)
        from_stage = "intake"
    else:
        if runner.is_active(run.id):
            raise HTTPException(409, "A run is already in progress for this research.")
        cfg = dict(run.config or {})
        if body.platforms:
            cfg["platforms"] = body.platforms
        if body.include_generic_hunts is not None:
            cfg["include_generic_hunts"] = body.include_generic_hunts
        if body.workspace_ids:
            cfg["workspace_ids"] = body.workspace_ids
            r.workspace_ids = body.workspace_ids
        run.config = cfg
        from_stage = body.from_stage
    if r.status == "published":
        r.status = "in_review"
    log_activity(db, rid, "created", f"Re-run from {dict(runner.STAGES)[from_stage]} by {user.name}", user.id)
    db.commit()
    runner.submit(run.id, from_stage)
    return {"run_id": run.id, "from_stage": from_stage}


# ------------------------------------------------------------------ versions & activity

@router.get("/{rid}/versions")
def versions(rid: str, db: Session = Depends(get_db)):
    users = _users(db)
    rows = db.query(ResearchVersion).filter_by(research_id=rid).order_by(ResearchVersion.id.desc()).all()
    return [{"version": v.version, "changed_by": user_dict(users.get(v.changed_by)), "changed_at": iso(v.changed_at),
             "summary": v.summary, "diff": v.diff} for v in rows]


@router.get("/{rid}/versions/{version}")
def version_detail(rid: str, version: int, db: Session = Depends(get_db)):
    v = db.query(ResearchVersion).filter_by(research_id=rid, version=version).order_by(ResearchVersion.id.desc()).first()
    if v is None:
        raise HTTPException(404, "Version not found")
    return {"version": v.version, "record": v.record, "changed_at": iso(v.changed_at), "summary": v.summary}


@router.get("/{rid}/activity")
def activity(rid: str, db: Session = Depends(get_db)):
    users = _users(db)
    rows = db.query(ActivityEvent).filter_by(research_id=rid).order_by(ActivityEvent.created_at.desc()).all()
    exports = db.query(ExportLog).filter_by(research_id=rid).order_by(ExportLog.created_at.desc()).all()
    return {"events": [{"id": e.id, "type": e.type, "message": e.message, "user": user_dict(users.get(e.user_id)),
                        "created_at": iso(e.created_at), "meta": e.meta} for e in rows],
            "exports": [{"format": x.format, "workspace_id": x.workspace_id, "user": user_dict(users.get(x.user_id)),
                         "created_at": iso(x.created_at), "file_name": x.file_name} for x in exports]}


class CommentIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    section: str | None = None


@router.post("/{rid}/comments")
def comment(rid: str, body: CommentIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    _get(db, rid)
    log_activity(db, rid, "comment", body.message, user.id, section=body.section)
    db.commit()
    return {"ok": True}


# ------------------------------------------------------------------ exports

EXPORTS = {
    "pdf": ("application/pdf", "pdf"), "html": ("text/html; charset=utf-8", "html"), "email": ("text/html; charset=utf-8", "html"),
    "eml": ("message/rfc822", "eml"), "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"),
    "json": ("application/json", "json"), "iocs_csv": ("text/csv; charset=utf-8", "csv"), "queries_csv": ("text/csv; charset=utf-8", "csv"),
}


@router.get("/{rid}/export/{fmt}")
def export(rid: str, fmt: str, db: Session = Depends(get_db), user: User = Depends(current_user), ws: str | None = None,
           hide: list[str] = Q(default=[]), study: bool = False, inline: bool = False):
    if fmt not in EXPORTS:
        raise HTTPException(404, "Unknown export format")
    r = _get(db, rid)
    if not r.record:
        raise HTTPException(409, "No report yet; wait for the run to finish.")
    sections = {k: False for k in hide}
    sections["study"] = study
    vm = export_ctx.build(db, r, ws if ws and ws != "all" else None, sections)
    try:
        data = {
            "pdf": lambda: render.pdf(vm), "html": lambda: render.report_html(vm).encode(), "email": lambda: render.email_html(vm).encode(),
            "eml": lambda: render.eml(vm), "pptx": lambda: render.pptx(vm), "json": lambda: render.record_json(vm),
            "iocs_csv": lambda: render.iocs_csv(vm), "queries_csv": lambda: render.queries_csv(vm),
        }[fmt]()
    except render.ExportRefused as e:
        raise HTTPException(403, str(e))
    except Exception as e:  # noqa: BLE001 - e.g. Chromium missing for PDF
        if fmt == "pdf":
            raise HTTPException(500, f"PDF rendering failed ({e}). Run 'python -m playwright install chromium' on the API host.")
        raise
    mime, ext = EXPORTS[fmt]
    suffix = {"iocs_csv": "-iocs", "queries_csv": "-queries", "email": "-email"}.get(fmt, "")
    name = f"{rid}{('-' + ws) if ws and ws != 'all' else ''}{suffix}.{ext}"
    if not inline or fmt not in ("html", "email"):
        db.add(ExportLog(research_id=rid, workspace_id=ws, format=fmt, user_id=user.id, file_name=name))
        label = {"pdf": "PDF", "html": "HTML", "email": "email HTML", "eml": "email draft", "pptx": "2-slide PPT", "json": "JSON",
                 "iocs_csv": "IoCs CSV", "queries_csv": "queries CSV"}[fmt]
        ws_name = (db.get(Workspace, ws).name if ws and ws != "all" and db.get(Workspace, ws) else "all workspaces")
        log_activity(db, rid, "exported", f"Exported {rid} as {label} ({ws_name})", user.id, format=fmt, workspace_id=ws)
        db.commit()
    disp = "inline" if inline else "attachment"
    return Response(content=data, media_type=mime, headers={"Content-Disposition": f'{disp}; filename="{name}"'})
