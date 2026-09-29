from __future__ import annotations

import copy
import difflib
import json
import re
import threading
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query as Q
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import String, case, cast, func, or_
from sqlalchemy.orm import Session

from .. import attack, detection, guardrails, llm
from ..db import SessionLocal, get_db
from ..deps import REVIEW_ROLES, current_user, iso, research_summary, user_dict, workspace_dict
from ..exports import context as export_ctx
from ..exports import render
from ..models import ActivityEvent, ExportLog, Query, Research, ResearchVersion, Result, Run, RunLog, User, Workspace
from ..pipeline import runner
from ..records import (backfill_provenance, log_activity, new_research_id, refresh_coverage_gaps, save_record, sort_sids,
                       tactic_rail)

router = APIRouter(prefix="/api/research", tags=["research"])


def _get(db: Session, rid: str) -> Research:
    r = db.get(Research, rid)
    if r is None:
        raise HTTPException(404, "This research doesn't exist. It may have been archived or the link is wrong.")
    return r


def _users(db: Session) -> dict[str, User]:
    return {u.id: u for u in db.query(User).all()}


# ------------------------------------------------------------------ list / search

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
MAX_PAGE_SIZE = 500


def _like_json(col, needle: str):
    """Portable (SQLite / PostgreSQL) substring test on a JSON column's text: a bounded pre-filter, exact check in Python."""
    esc = needle.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return cast(col, String).ilike(f"%{esc}%", escape="!")


# Facets of the record JSON used by list filters / the IoC-count sort, cached per research and keyed by
# (updated_at, version) so a saved edit invalidates it. Reading record JSON is the expensive part of the list at scale
# (records are ~15-20 KB); with the cache only rows changed since the last request are read. A proper fix is a facet
# table or indexed columns (models change).
_FACETS: dict[str, tuple[tuple, dict]] = {}
_FACETS_LOCK = threading.Lock()


def _facet_of(actors, industries, platforms, vulns, mitre, n_iocs) -> dict:
    return {
        "actors": {x.lower() for a in actors or [] for x in [a.get("name", "")] + list(a.get("aliases", []))},
        "industries": {(i.get("industry") or "").lower() for i in industries or []},
        "platforms": set(platforms or []), "cves": {v.get("cve") for v in vulns or []},
        "techniques": {m.get("technique_id") for m in mitre or []}, "tactics": {m.get("tactic_id") for m in mitre or []},
        "iocs": int(n_iocs or 0),
    }


def _facets(db: Session, rows: list[tuple]) -> dict[str, dict]:
    """rows: (id, updated_at, version) → {id: facets}, loading record fragments only for cache misses."""
    out, missing = {}, []
    with _FACETS_LOCK:
        for rid, upd, ver in rows:
            hit = _FACETS.get(rid)
            if hit and hit[0] == (upd, ver):
                out[rid] = hit[1]
            else:
                missing.append(rid)
    rec = Research.record
    for i in range(0, len(missing), 500):
        got = db.query(Research.id, Research.updated_at, Research.version, rec["threat_actors"], rec["industries"],
                       rec[("hunts", "platforms")], rec["vulnerabilities"], rec["mitre"],
                       func.json_array_length(rec["iocs"])).filter(Research.id.in_(missing[i:i + 500])).all()
        with _FACETS_LOCK:
            for rid, upd, ver, *frag in got:
                f = _facet_of(*frag)
                _FACETS[rid] = ((upd, ver), f)
                out[rid] = f
    return out


_WARMED = False


def _warm_facets() -> None:
    """Fill the facet cache in the background on the first list request, so the first JSON-derived filter is fast too."""
    global _WARMED
    if _WARMED:
        return
    _WARMED = True

    def run():
        db = SessionLocal()
        try:
            _facets(db, [tuple(x) for x in db.query(Research.id, Research.updated_at, Research.version).all()])
        except Exception:  # noqa: BLE001 - best effort; requests fill the cache on demand anyway
            pass
        finally:
            db.close()
    threading.Thread(target=run, name="research-facets", daemon=True).start()


def _json_keep(f: dict, actor, industry, platform, cve, technique, tactic) -> bool:
    """Exact checks for JSON-derived filters (same semantics as before B15)."""
    return not ((actor and actor.lower() not in f["actors"]) or (industry and industry.lower() not in f["industries"])
                or (platform and platform not in f["platforms"]) or (cve and cve.upper() not in f["cves"])
                or (technique and technique.upper() not in f["techniques"]) or (tactic and tactic not in f["tactics"]))


@router.get("")
def list_research(
    db: Session = Depends(get_db), ws: str | None = None, q: str | None = None, status: list[str] = Q(default=[]),
    severity: list[str] = Q(default=[]), classification: list[str] = Q(default=[]), actor: str | None = None,
    industry: str | None = None, platform: str | None = None, result: list[str] = Q(default=[]), author: str | None = None,
    date_from: str | None = Q(default=None, alias="from"), date_to: str | None = Q(default=None, alias="to"),
    cve: str | None = None, technique: str | None = None, tactic: str | None = None,
    sort: str = "-created_at", page: int = 1, page_size: int = 50,
):
    """Filtered, sorted, paginated research list. Column filters, workspace/classification membership, result status and
    free text run in SQL; filters on record JSON (actor, industry, platform, CVE, technique, tactic) are narrowed in SQL
    with a text pre-filter and confirmed in Python on the candidates only."""
    page = max(1, page)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
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
    scoped = ws and ws != "all"
    if scoped:
        query = query.filter(_like_json(Research.workspace_ids, f'"{ws}"'))
    if classification:
        query = query.filter(or_(*[_like_json(Research.classification, f'"{c}"') for c in classification]))
    if result:
        sub = db.query(Result.research_id).filter(Result.status.in_(result))
        if scoped:
            sub = sub.filter(Result.workspace_id == ws)
        query = query.filter(Research.id.in_(sub))
    # JSON-derived filters. Actor names/aliases, CVEs and technique ids are in search_text (lower-cased, rebuilt on every
    # save), which narrows the candidates in SQL; the exact checks (and industry / platform / tactic) use cached facets.
    for term in (actor, cve, technique):
        if term:
            query = query.filter(Research.search_text.contains(term.lower()))
    json_filter = any((actor, industry, platform, cve, technique, tactic))

    desc = sort.startswith("-")
    key = sort.lstrip("-")
    sev_expr = case(*[(Research.severity == k, v) for k, v in SEV_RANK.items()], else_=0)
    col = {"created_at": Research.created_at, "updated_at": Research.updated_at, "severity": sev_expr, "id": Research.id,
           "title": func.lower(Research.title), "status": Research.status}.get(key, Research.created_at)
    # Two phases: sort / filter / paginate over narrow (id, updated_at, version) rows, then load only the page's records.
    ids_q = query.with_entities(Research.id, Research.updated_at, Research.version).order_by(
        col.desc() if desc else col.asc(), Research.id.desc() if desc else Research.id.asc())
    if not json_filter and key != "iocs":
        _warm_facets()
        total = query.order_by(None).count()
        page_ids = [x[0] for x in ids_q.offset((page - 1) * page_size).limit(page_size).all()]
    else:
        cand = [tuple(x) for x in ids_q.all()]
        facets = _facets(db, cand)
        keep = [x[0] for x in cand if _json_keep(facets[x[0]], actor, industry, platform, cve, technique, tactic)]
        if key == "iocs":  # stable: ties keep the id order from SQL
            keep.sort(key=lambda i: facets[i]["iocs"], reverse=desc)
        total = len(keep)
        page_ids = keep[(page - 1) * page_size: page * page_size]
    loaded = {r.id: r for r in db.query(Research).filter(Research.id.in_(page_ids)).all()} if page_ids else {}
    page_rows = [loaded[i] for i in page_ids if i in loaded]
    ids = [r.id for r in page_rows]
    by_r: dict[str, list[Result]] = {}
    for x in (db.query(Result).filter(Result.research_id.in_(ids)).all() if ids else []):
        by_r.setdefault(x.research_id, []).append(x)
    users = _users(db)
    return {"total": total, "page": page, "page_size": page_size, "pages": -(-total // page_size),
            "items": [research_summary(r, by_r.get(r.id, []), users, ws if ws != "all" else None) for r in page_rows]}


# ------------------------------------------------------------------ notifications (B19)
# Declared before /{rid} so "notifications" is not taken for a research id. Stored as activity_event rows of type
# "mention" with meta {target, comment_id, thread_id, section, kind: mention|reply, read}; user_id is who wrote it.

SECTION_LABELS = {
    "executive_summary": "Executive summary", "impact": "Impact", "recommendations": "Recommendations", "result": "Result",
    "vulnerabilities": "Vulnerabilities", "threat_actors": "Threat actors", "attack_paths": "Attack paths",
    "mitre": "MITRE ATT&CK", "detection_opportunities": "Detection opportunities", "ioas": "Indicators of attack",
    "tools_used": "Tools used", "malware_tools": "Malware and tools", "workflow": "Workflow", "hunts": "Hunts", "iocs": "IoCs",
    "industries": "Industries", "timeline": "Timeline", "sources": "Sources", "claims": "Claims", "conflicts": "Conflicts",
    "study": "Study", "title": "Title", "tlp": "TLP", "severity": "Severity", "confidence": "Confidence",
    "classification": "Classification", "tags": "Tags", "geography": "Geography", "log_sources_required": "Log sources",
    "coverage_gaps": "Coverage gaps", "applicability": "Applicability", "results": "Results", "patching_insufficient": "Patching",
    "affected_technologies": "Affected technologies", "related_research_ids": "Related research",
}


def section_label(section: str | None) -> str:
    return SECTION_LABELS.get(section or "", (section or "General").replace("_", " ").capitalize())


def _notifications_for(db: Session, user_id: str):
    return db.query(ActivityEvent).filter(ActivityEvent.type == "mention",
                                          ActivityEvent.meta["target"].as_string() == user_id)


@router.get("/notifications")
def notifications(db: Session = Depends(get_db), user: User = Depends(current_user), limit: int = 30):
    """The current user's mention / reply notifications, newest first, with the unread count."""
    base = _notifications_for(db, user.id)
    rows = base.order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc()).limit(max(1, min(limit, 100))).all()
    unread = base.filter(ActivityEvent.meta["read"].as_boolean().isnot(True)).count()
    users = _users(db)
    ids = {e.research_id for e in rows if e.research_id}
    titles = {rid: t for rid, t in db.query(Research.id, Research.title).filter(Research.id.in_(ids))} if ids else {}
    items = []
    for e in rows:
        m = e.meta or {}
        items.append({"id": e.id, "kind": m.get("kind", "mention"), "research_id": e.research_id,
                      "research_title": titles.get(e.research_id, ""), "section": m.get("section"),
                      "section_label": section_label(m.get("section")) if m.get("section") else "General",
                      "comment_id": m.get("comment_id"), "thread_id": m.get("thread_id"), "message": e.message,
                      "by": user_dict(users.get(e.user_id)), "created_at": iso(e.created_at), "read": bool(m.get("read"))})
    return {"unread": unread, "items": items}


class NotificationsRead(BaseModel):
    ids: list[int] = []  # empty: mark all read


@router.post("/notifications/read")
def notifications_read(body: NotificationsRead, db: Session = Depends(get_db), user: User = Depends(current_user)):
    q = _notifications_for(db, user.id)
    if body.ids:
        q = q.filter(ActivityEvent.id.in_(body.ids))
    n = 0
    for e in q.all():
        if not (e.meta or {}).get("read"):
            e.meta = {**(e.meta or {}), "read": True}
            n += 1
    db.commit()
    return {"marked": n}


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
        "record": refresh_coverage_gaps(db, backfill_provenance(copy.deepcopy(r.record or {})), r.workspace_ids or []), "seed": r.seed,
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
    old = r.record or {}
    rec.update(body.changes)
    _stamp_edited_items(old, rec, body.changes)
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
        # Grounding gate (spec §12): unsupported statements cannot be published unedited.
        ready = _readiness(db, r)
        if not ready["ready"]:
            return JSONResponse(status_code=409, content={"detail": guardrails.blocking_message(ready), **ready})
        r.status = "published"
        r.reviewed_by = user.id
        r.published_at = datetime.now(timezone.utc)
        new = copy.deepcopy(rec)
        new["status"] = "published"
        # Review states are left as the reviewers set them: bulk-approving here would silently downgrade every
        # unsupported item to a warning if the record is edited and re-reviewed later.
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


# ------------------------------------------------------------------ grounding gate & reviewer editing (B03 / B04)

LIST_SECTIONS = ("claims", "recommendations", "mitre", "industries", "threat_actors", "malware_tools", "vulnerabilities",
                 "attack_paths", "timeline", "ioas", "iocs")


def _strip_flag(x):
    return {k: v for k, v in x.items() if k != "_edited"} if isinstance(x, dict) else x


def _stamp_edited_items(old: dict, new: dict, changes: dict) -> None:
    """Mark list items that a wholesale section save added or changed with `_edited: true`, so the grounding gate
    knows a person wrote them. Unchanged items keep whatever flag they had."""
    for k in changes:
        if k not in LIST_SECTIONS or not isinstance(new.get(k), list):
            continue
        before = [_strip_flag(x) for x in old.get(k, []) or []]
        for item in new[k]:
            if isinstance(item, dict) and _strip_flag(item) not in before:
                item["_edited"] = True


def _run_ids(db: Session, rid: str) -> list[str]:
    return [x.id for x in db.query(Run).filter_by(research_id=rid).order_by(Run.started_at.desc().nullslast()).all()]


def _readiness(db: Session, r: Research) -> dict:
    return guardrails.readiness(r.record or {}, _run_ids(db, r.id))


@router.get("/{rid}/readiness")
def readiness(rid: str, db: Session = Depends(get_db)):
    """Grounding gate: {ready, blocking, warnings, issues:[{section, index, step?, ref?, field, kind, text, severity, anchor}]}.
    Publishing is refused (409, same body plus `detail`) while `blocking` > 0."""
    return _readiness(db, _get(db, rid))


def _check_can_edit(r: Research, user: User) -> None:
    """Hunters may edit drafts; reviewers, leads and admins may edit at any stage (except archived)."""
    if r.status == "archived":
        raise HTTPException(409, "Archived research is read-only. Restore it first.")
    if user.role not in REVIEW_ROLES and r.status not in ("draft", "failed"):
        raise HTTPException(403, "Only reviewers, leads and admins can edit research once it is in review or published.")


def _unchanged(db: Session, r: Research) -> dict:
    return {"version": r.version, "status": r.status, "record": r.record, "readiness": _readiness(db, r)}


def _save_edit(db: Session, r: Research, rec: dict, user: User, section: str, summary: str) -> dict:
    rec["_edited"] = sorted(set(rec.get("_edited", [])) | {section})  # a re-run keeps this section as edited
    review = rec.setdefault("review", {})
    if section in review:
        review[section] = "edited"
    if r.status == "published":
        r.status = "in_review"
        rec["status"] = "in_review"
        log_activity(db, r.id, "status", f"Moved back to review after edits by {user.name}", user.id)
    save_record(db, r, rec, user.id, summary)
    log_activity(db, r.id, "edited", f"v{r.version} · {summary} by {user.name}", user.id, sections=[section])
    db.commit()
    return _unchanged(db, r)


def _check_sources(rec: dict, ids: list[str]) -> list[str]:
    known = {s.get("id") for s in rec.get("sources", [])}
    bad = [s for s in ids if s not in known]
    if bad:
        raise HTTPException(422, f"Unknown source id(s): {', '.join(bad)}. Cite one of the report's sources.")
    return sort_sids(ids)


def _technique(tid: str) -> dict:
    t = attack.technique(tid or "")
    if not t:
        shown = (tid or "").strip() or "An empty id"
        raise HTTPException(422, f"{shown} is not an ATT&CK Enterprise technique in the current catalog.")
    return t


class TitleIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)


@router.patch("/{rid}/title")
def edit_title(rid: str, body: TitleIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    _check_can_edit(r, user)
    rec = copy.deepcopy(r.record or {})
    title = " ".join(body.title.split())
    if title == rec.get("title"):
        return _unchanged(db, r)
    rec["title"] = title
    return _save_edit(db, r, rec, user, "title", "Edited title")


CONFIDENCE = ("low", "moderate", "high")


class MitreIn(BaseModel):
    technique_id: str
    tactic_id: str | None = None
    procedure: str = ""
    evidence_quote: str = ""
    source_ids: list[str] = []
    confidence: str = "moderate"


def _mitre_row(body: MitreIn, rec: dict) -> dict:
    t = _technique(body.technique_id)
    if body.confidence not in CONFIDENCE:
        raise HTTPException(422, f"Confidence must be one of: {', '.join(CONFIDENCE)}.")
    if body.tactic_id and body.tactic_id not in t["tactic_ids"]:
        names = ", ".join(attack.TACTIC_BY_ID.get(x, {}).get("name", x) for x in t["tactic_ids"])
        raise HTTPException(422, f"{t['id']} does not belong to tactic {body.tactic_id}. Its tactics: {names}.")
    tactic_id = body.tactic_id or (t["tactic_ids"] or [""])[0]
    technique, sub = (t["name"].split(": ", 1) + [""])[:2] if "." in t["id"] else (t["name"], "")
    return {"tactic_id": tactic_id, "tactic": attack.TACTIC_BY_ID.get(tactic_id, {}).get("name", ""), "technique_id": t["id"],
            "technique": technique, "sub_technique": sub, "procedure": body.procedure.strip(),
            "evidence_quote": " ".join(body.evidence_quote.split()), "source_ids": _check_sources(rec, body.source_ids),
            "confidence": body.confidence, "_edited": True}


def _sort_mitre(rows: list[dict]) -> list[dict]:
    order = {t["id"]: i for i, t in enumerate(attack.TACTICS)}
    return sorted(rows, key=lambda x: (order.get(x.get("tactic_id"), 99), x.get("technique_id", "")))


def _mitre_index(rec: dict, idx: int, technique_id: str | None) -> int:
    rows = rec.get("mitre", [])
    if not 0 <= idx < len(rows):
        raise HTTPException(404, "MITRE row not found")
    if technique_id and rows[idx].get("technique_id") != technique_id.strip().upper():
        raise HTTPException(409, "The MITRE table changed since you loaded it. Reload and try again.")
    return idx


def _dup(rows: list[dict], row: dict, skip: int = -1) -> bool:
    return any(i != skip and m.get("technique_id") == row["technique_id"] and m.get("tactic_id") == row["tactic_id"]
               for i, m in enumerate(rows))


@router.post("/{rid}/mitre")
def add_mitre(rid: str, body: MitreIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    _check_can_edit(r, user)
    rec = copy.deepcopy(r.record or {})
    row = _mitre_row(body, rec)
    if _dup(rec.get("mitre", []), row):
        raise HTTPException(409, f"{row['technique_id']} is already mapped under {row['tactic']}. Edit that row instead.")
    rec["mitre"] = _sort_mitre(rec.get("mitre", []) + [row])
    return _save_edit(db, r, rec, user, "mitre", f"Added {row['technique_id']} to MITRE ATT&CK")


@router.put("/{rid}/mitre/{idx}")
def edit_mitre(rid: str, idx: int, body: MitreIn, db: Session = Depends(get_db), user: User = Depends(current_user),
               expect: str | None = None):
    """Replace one MITRE row (index into record.mitre). `expect=<technique id>` guards against editing a row that moved."""
    r = _get(db, rid)
    _check_can_edit(r, user)
    rec = copy.deepcopy(r.record or {})
    idx = _mitre_index(rec, idx, expect)
    row = _mitre_row(body, rec)
    if _dup(rec["mitre"], row, idx):
        raise HTTPException(409, f"{row['technique_id']} is already mapped under {row['tactic']}.")
    old = rec["mitre"][idx]
    rec["mitre"][idx] = row
    rec["mitre"] = _sort_mitre(rec["mitre"])
    what = row["technique_id"] if old.get("technique_id") == row["technique_id"] else f"{old.get('technique_id')} → {row['technique_id']}"
    return _save_edit(db, r, rec, user, "mitre", f"Edited MITRE row {what}")


@router.delete("/{rid}/mitre/{idx}")
def delete_mitre(rid: str, idx: int, db: Session = Depends(get_db), user: User = Depends(current_user), expect: str | None = None):
    r = _get(db, rid)
    _check_can_edit(r, user)
    rec = copy.deepcopy(r.record or {})
    idx = _mitre_index(rec, idx, expect)
    old = rec["mitre"].pop(idx)
    return _save_edit(db, r, rec, user, "mitre", f"Removed {old.get('technique_id')} from MITRE ATT&CK")


class StepIn(BaseModel):
    ref: str | None = None  # keep the ref of an existing step (detection opportunities point at it); omit for a new step
    behaviour: str = Field(min_length=1)
    technique_id: str = ""
    source_ids: list[str] = []


class PathIn(BaseModel):
    name: str | None = None
    steps: list[StepIn] | None = None  # full ordered list: add / edit / remove / reorder in one versioned save


def _path_steps(rec: dict, pid: str, old_steps: list[dict], steps: list[StepIn]) -> list[dict]:
    existing = {(s.get("ref") or f"{pid}.{j}"): s for j, s in enumerate(old_steps, 1)}
    used = {s.get("ref") for p in rec.get("attack_paths", []) for s in p.get("steps", [])}
    nums = [int(m.group(1)) for x in used if x and x.startswith(pid + ".") for m in [re.search(r"\.(\d+)$", x)] if m]
    n = max(nums + [0])
    out, seen = [], set()
    for s in steps:
        tid = s.technique_id.strip().upper()
        if tid:
            _technique(tid)
        ref = s.ref if s.ref in existing and s.ref not in seen else None
        if ref is None:
            n += 1
            while f"{pid}.{n}" in used:
                n += 1
            ref = f"{pid}.{n}"
        seen.add(ref)
        new = {"ref": ref, "behaviour": " ".join(s.behaviour.split()), "technique_id": tid,
               "source_ids": _check_sources(rec, s.source_ids)}
        prev = existing.get(ref)
        if prev is None or prev.get("_edited") or any(prev.get(k) != new[k] for k in ("behaviour", "technique_id", "source_ids")):
            new["_edited"] = True
        out.append(new)
    return out


@router.post("/{rid}/attack-paths")
def add_attack_path(rid: str, body: PathIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    _check_can_edit(r, user)
    rec = copy.deepcopy(r.record or {})
    paths = rec.setdefault("attack_paths", [])
    ids = {p.get("id") for p in paths}
    i = len(paths) + 1
    while f"AP-{i}" in ids:
        i += 1
    pid = f"AP-{i}"
    name = (body.name or "").strip() or "New attack path"
    paths.append({"id": pid, "name": name, "steps": _path_steps(rec, pid, [], body.steps or []), "_edited": True})
    return _save_edit(db, r, rec, user, "attack_paths", f"Added attack path {pid}")


@router.put("/{rid}/attack-paths/{pid}")
def edit_attack_path(rid: str, pid: str, body: PathIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Rename a path and/or replace its ordered step list (add / edit / remove / reorder). Existing steps keep their ref
    when sent back with it; new steps get a fresh ref."""
    r = _get(db, rid)
    _check_can_edit(r, user)
    rec = copy.deepcopy(r.record or {})
    path = next((p for p in rec.get("attack_paths", []) if p.get("id") == pid), None)
    if path is None:
        raise HTTPException(404, "Attack path not found")
    changed = []
    if body.name is not None and body.name.strip() and body.name.strip() != path.get("name"):
        path["name"] = body.name.strip()
        path["_edited"] = True
        changed.append("renamed")
    if body.steps is not None:
        new_steps = _path_steps(rec, pid, path.get("steps", []), body.steps)
        if [_strip_flag(s) for s in new_steps] != [_strip_flag(s) for s in path.get("steps", [])]:
            removed = {s.get("ref") for s in path.get("steps", [])} - {s["ref"] for s in new_steps}
            path["steps"] = new_steps
            path["_edited"] = True  # includes a pure reorder, which leaves every step unchanged
            changed.append("steps edited" + (f", removed {', '.join(sorted(removed))}" if removed else ""))
    if not changed:
        return _unchanged(db, r)
    return _save_edit(db, r, rec, user, "attack_paths", f"Attack path {pid} {'; '.join(changed)}")


@router.delete("/{rid}/attack-paths/{pid}")
def delete_attack_path(rid: str, pid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, rid)
    _check_can_edit(r, user)
    rec = copy.deepcopy(r.record or {})
    before = len(rec.get("attack_paths", []))
    rec["attack_paths"] = [p for p in rec.get("attack_paths", []) if p.get("id") != pid]
    if len(rec["attack_paths"]) == before:
        raise HTTPException(404, "Attack path not found")
    return _save_edit(db, r, rec, user, "attack_paths", f"Removed attack path {pid}")


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
    rec = refresh_coverage_gaps(db, backfill_provenance(copy.deepcopy(r.record or {})), r.workspace_ids or [])
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
    rows = (db.query(ActivityEvent).filter(ActivityEvent.research_id == rid, ActivityEvent.type != "mention")
            .order_by(ActivityEvent.created_at.desc()).all())
    exports = db.query(ExportLog).filter_by(research_id=rid).order_by(ExportLog.created_at.desc()).all()
    return {"events": [{"id": e.id, "type": e.type, "message": e.message, "user": user_dict(users.get(e.user_id)),
                        "created_at": iso(e.created_at), "meta": e.meta} for e in rows],
            "exports": [{"format": x.format, "workspace_id": x.workspace_id, "user": user_dict(users.get(x.user_id)),
                         "created_at": iso(x.created_at), "file_name": x.file_name} for x in exports]}


class CommentIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    section: str | None = None
    parent_id: int | None = None  # reply to a thread (any comment in it); the reply joins the root's thread and section
    mentions: list[str] = []  # user ids; "@Name" / "@id" tokens in the message are detected too


def _comment_dict(e: ActivityEvent, users: dict[str, User]) -> dict:
    m = e.meta or {}
    return {"id": e.id, "section": m.get("section"), "section_label": section_label(m.get("section")) if m.get("section") else "General",
            "parent_id": m.get("parent_id"), "message": e.message, "user": user_dict(users.get(e.user_id)),
            "created_at": iso(e.created_at), "mentions": [user_dict(users[u]) for u in m.get("mentions", []) if u in users],
            "resolved": bool(m.get("resolved")), "resolved_by": user_dict(users.get(m.get("resolved_by") or "")),
            "resolved_at": m.get("resolved_at")}


def _mentioned(message: str, explicit: list[str], users: dict[str, User]) -> list[str]:
    out = [u for u in explicit if u in users]
    for u in users.values():
        if u.id in out:
            continue
        if re.search(rf"@{re.escape(u.name)}(?!\w)", message, re.I) or re.search(rf"@{re.escape(u.id)}(?!\w)", message, re.I):
            out.append(u.id)
    return out


def _comment_event(db: Session, rid: str, cid: int) -> ActivityEvent:
    e = db.get(ActivityEvent, cid)
    if e is None or e.research_id != rid or e.type != "comment":
        raise HTTPException(404, "Comment not found")
    return e


@router.get("/{rid}/comments")
def list_comments(rid: str, db: Session = Depends(get_db), section: str | None = None):
    """Comment threads (root + replies, oldest first) and per-section counts {section: {threads, open, comments}}.
    Global comments have section null (key "" in counts)."""
    _get(db, rid)
    users = _users(db)
    rows = db.query(ActivityEvent).filter_by(research_id=rid, type="comment").order_by(ActivityEvent.created_at, ActivityEvent.id).all()
    threads: dict[int, dict] = {}
    replies: list[ActivityEvent] = []
    for e in rows:
        if (e.meta or {}).get("parent_id"):
            replies.append(e)
        else:
            threads[e.id] = {**_comment_dict(e, users), "replies": []}
    for e in replies:
        t = threads.get((e.meta or {}).get("parent_id"))
        if t is not None:
            t["replies"].append(_comment_dict(e, users))
    counts: dict[str, dict] = {}
    for t in threads.values():
        c = counts.setdefault(t["section"] or "", {"threads": 0, "open": 0, "comments": 0})
        c["threads"] += 1
        c["comments"] += 1 + len(t["replies"])
        c["open"] += 0 if t["resolved"] else 1
    items = [t for t in threads.values() if section is None or (t["section"] or "") == section]
    return {"threads": items, "counts": counts}


@router.post("/{rid}/comments")
def comment(rid: str, body: CommentIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Add a comment (global, on a section, or a reply). Mentioned users, and on a reply the thread's participants,
    get a notification (GET /api/research/notifications)."""
    _get(db, rid)
    section, parent_id, root = body.section, None, None
    if body.parent_id is not None:
        parent = _comment_event(db, rid, body.parent_id)
        parent_id = (parent.meta or {}).get("parent_id") or parent.id
        root = _comment_event(db, rid, parent_id)
        section = (root.meta or {}).get("section")
    users = _users(db)
    mentions = _mentioned(body.message, body.mentions, users)
    e = ActivityEvent(research_id=rid, type="comment", message=body.message, user_id=user.id,
                      meta={"section": section, "parent_id": parent_id, "mentions": mentions})
    db.add(e)
    db.flush()
    notify = {u: "mention" for u in mentions}
    if root is not None:
        if (root.meta or {}).get("resolved"):  # a reply reopens a resolved thread
            root.meta = {**(root.meta or {}), "resolved": False, "resolved_by": None, "resolved_at": None}
        others = db.query(ActivityEvent).filter(ActivityEvent.research_id == rid, ActivityEvent.type == "comment",
                                                ActivityEvent.meta["parent_id"].as_integer() == root.id).all()
        for p in [root.user_id] + [x.user_id for x in others]:
            if p:
                notify.setdefault(p, "reply")
    snippet = body.message if len(body.message) <= 200 else body.message[:199] + "…"
    for target, kind in notify.items():
        if target != user.id:
            db.add(ActivityEvent(research_id=rid, type="mention", message=snippet, user_id=user.id,
                                 meta={"target": target, "comment_id": e.id, "thread_id": parent_id or e.id,
                                       "section": section, "kind": kind, "read": False}))
    db.commit()
    return {"ok": True, "comment": _comment_dict(e, users), "notified": sorted(t for t in notify if t != user.id)}


class ResolveIn(BaseModel):
    resolved: bool = True


@router.post("/{rid}/comments/{cid}/resolve")
def resolve_comment(rid: str, cid: int, body: ResolveIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Resolve (or reopen with resolved=false) the thread that comment `cid` belongs to."""
    e = _comment_event(db, rid, cid)
    root = _comment_event(db, rid, (e.meta or {}).get("parent_id") or e.id)
    root.meta = {**(root.meta or {}), "resolved": body.resolved, "resolved_by": user.id if body.resolved else None,
                 "resolved_at": datetime.now(timezone.utc).isoformat() if body.resolved else None}
    sec = (root.meta or {}).get("section")
    where = section_label(sec) if sec else "the report"
    log_activity(db, rid, "comment_status", f"Thread on {where} {'resolved' if body.resolved else 'reopened'} by {user.name}",
                 user.id, section=sec, thread_id=root.id, resolved=body.resolved)
    db.commit()
    return _comment_dict(root, _users(db))


# ------------------------------------------------------------------ version diff (B27)
# Lists are matched by a stable key where the item has one; keyless lists (recommendations, claims, timeline…) are
# aligned by sequence so an edited item reads as "recommendation 3 changed" rather than one removed plus one added.

DIFF_SKIP = {"id", "version", "schema_version", "updated_at", "review", "_edited", "status", "run", "demo_note"}


def _low(v) -> str:
    return str(v or "").strip().lower()


DIFF_KEYS = {
    "iocs": lambda x: (_low(x.get("type")), _low(x.get("value"))),
    "mitre": lambda x: (x.get("technique_id"), x.get("tactic_id")),
    "hunts.queries": lambda x: (x.get("group") or x.get("id"), x.get("platform")),
    "sources": lambda x: x.get("url") or x.get("id"),
    "vulnerabilities": lambda x: _low(x.get("cve")),
    "threat_actors": lambda x: _low(x.get("name")),
    "malware_tools": lambda x: _low(x.get("name")),
    "tools_used": lambda x: _low(x.get("name")),
    "industries": lambda x: _low(x.get("industry")),
    "attack_paths": lambda x: x.get("id"),
    "ioas": lambda x: x.get("id"),
    "detection_opportunities": lambda x: x.get("id"),
    "results": lambda x: x.get("workspace_id"),
    "applicability": lambda x: x.get("workspace_id"),
    "coverage_gaps": lambda x: (x.get("workspace_id"), x.get("opportunity_id"), x.get("data_source")),
    "log_sources_required": lambda x: x.get("data_source"),
    "workflow": lambda x: x.get("step"),
    "conflicts": lambda x: x.get("topic"),
}

ITEM_NOUN = {
    "iocs": ("IoC", "IoCs"), "mitre": ("technique", "techniques"), "hunts.queries": ("query", "queries"),
    "sources": ("source", "sources"), "vulnerabilities": ("CVE", "CVEs"), "threat_actors": ("actor", "actors"),
    "malware_tools": ("tool", "tools"), "tools_used": ("tool", "tools"), "industries": ("industry", "industries"),
    "attack_paths": ("attack path", "attack paths"), "ioas": ("IoA", "IoAs"),
    "detection_opportunities": ("opportunity", "opportunities"), "recommendations": ("recommendation", "recommendations"),
    "claims": ("claim", "claims"), "timeline": ("timeline event", "timeline events"), "conflicts": ("conflict", "conflicts"),
    "results": ("result", "results"), "coverage_gaps": ("gap", "gaps"), "log_sources_required": ("log source", "log sources"),
}


def _item_label(path: str, x) -> str:
    if not isinstance(x, dict):
        return str(x)[:120]
    if path == "iocs":
        return f"{x.get('type', '')}: {x.get('value', '')}"
    if path == "mitre":
        return f"{x.get('technique_id', '')} {x.get('technique', '')} ({x.get('tactic', x.get('tactic_id', ''))})".strip()
    if path == "hunts.queries":
        return f"{x.get('group') or x.get('id')} · {x.get('platform', '')} — {x.get('title', '')}".strip(" —")
    for k in ("cve", "name", "industry", "title", "action", "statement", "event", "description", "topic", "url", "step",
              "workspace_id", "data_source", "id"):
        if x.get(k):
            return str(x[k])[:160]
    return json_short(x)


def json_short(v, n: int = 160) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[: n - 1] + "…"


def _word_ops(a: str, b: str) -> list[dict]:
    """Word-level diff of two strings: [{op: eq|add|del, text}]."""
    ta, tb = re.findall(r"\s+|[^\s]+", a), re.findall(r"\s+|[^\s]+", b)
    out: list[dict] = []

    def put(op, words):
        if not words:
            return
        if out and out[-1]["op"] == op:
            out[-1]["text"] += "".join(words)
        else:
            out.append({"op": op, "text": "".join(words)})
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, ta, tb, autojunk=False).get_opcodes():
        if tag == "equal":
            put("eq", ta[i1:i2])
        else:
            put("del", ta[i1:i2])
            put("add", tb[j1:j2])
    return out


def _as_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list) and all(isinstance(x, (str, int, float)) for x in v):
        return ", ".join(str(x) for x in v)
    return json_short(v, 4000)


def _field_changes(a, b) -> list[dict]:
    """Field-level changes between two dict items (or two scalars under field "value")."""
    if not (isinstance(a, dict) and isinstance(b, dict)):
        a, b = {"value": a}, {"value": b}
    out = []
    for k in list(dict.fromkeys([*a.keys(), *b.keys()])):
        if k.startswith("_") or k in ("lint",):
            continue
        if a.get(k) != b.get(k):
            ta, tb = _as_text(a.get(k)), _as_text(b.get(k))
            out.append({"field": k, "before": ta, "after": tb, "ops": _word_ops(ta, tb)})
    return out


def _strip(x):
    return {k: v for k, v in x.items() if not k.startswith("_")} if isinstance(x, dict) else x


def _list_diff(path: str, a: list, b: list) -> dict:
    keyf = DIFF_KEYS.get(path)
    added, removed, changed = [], [], []
    if keyf and all(isinstance(x, dict) for x in a + b):
        ka = {}
        for x in a:
            ka.setdefault(keyf(x), x)
        kb = {}
        for x in b:
            kb.setdefault(keyf(x), x)
        for i, x in enumerate(b):
            k = keyf(x)
            if kb.get(k) is not x:
                continue
            if k not in ka:
                added.append({"index": i + 1, "label": _item_label(path, x), "item": _strip(x)})
            elif _strip(ka[k]) != _strip(x):
                fields = _field_changes(_strip(ka[k]), _strip(x))
                if fields:
                    changed.append({"index": i + 1, "label": _item_label(path, x), "fields": fields})
        for i, x in enumerate(a):
            if keyf(x) not in kb and ka.get(keyf(x)) is x:
                removed.append({"index": i + 1, "label": _item_label(path, x), "item": _strip(x)})
    else:
        sa = [json.dumps(_strip(x), sort_keys=True, default=str) for x in a]
        sb = [json.dumps(_strip(x), sort_keys=True, default=str) for x in b]
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, sa, sb, autojunk=False).get_opcodes():
            if tag == "equal":
                continue
            pairs = min(i2 - i1, j2 - j1) if tag == "replace" else 0
            for n in range(pairs):
                x, y = a[i1 + n], b[j1 + n]
                changed.append({"index": j1 + n + 1, "label": _item_label(path, y), "fields": _field_changes(_strip(x), _strip(y))})
            for n in range(i1 + pairs, i2):
                removed.append({"index": n + 1, "label": _item_label(path, a[n]), "item": _strip(a[n])})
            for n in range(j1 + pairs, j2):
                added.append({"index": n + 1, "label": _item_label(path, b[n]), "item": _strip(b[n])})
    one, many = ITEM_NOUN.get(path, ("item", "items"))
    bits = []
    if added:
        bits.append(f"+{len(added)} {one if len(added) == 1 else many}")
    if removed:
        bits.append(f"−{len(removed)} {one if len(removed) == 1 else many}")
    if len(changed) == 1 and not keyf:
        bits.append(f"{one} {changed[0]['index']} changed")
    elif changed:
        bits.append(f"{len(changed)} {one if len(changed) == 1 else many} changed")
    return {"kind": "list", "added": added, "removed": removed, "changed": changed, "summary": ", ".join(bits),
            "count_before": len(a), "count_after": len(b)}


def _section_diff(key: str, a, b) -> list[dict]:
    """One or more diff entries for a top-level record key (hunts splits into its query list and settings)."""
    if key == "hunts" and isinstance(a or {}, dict) and isinstance(b or {}, dict):
        a, b = a or {}, b or {}
        out = []
        qa, qb = a.get("queries", []) or [], b.get("queries", []) or []
        if qa != qb:
            d = _list_diff("hunts.queries", qa, qb)
            if d["added"] or d["removed"] or d["changed"]:
                out.append({"section": "hunts", "label": "Hunts", **d})
        rest_a = {k: v for k, v in a.items() if k == "platforms" or k == "lookback_days"}
        rest_b = {k: v for k, v in b.items() if k == "platforms" or k == "lookback_days"}
        if rest_a != rest_b:
            fields = _field_changes(rest_a, rest_b)
            out.append({"section": "hunts", "label": "Hunt settings", "kind": "object", "fields": fields,
                        "summary": ", ".join(f"{f['field'].replace('_', ' ')} changed" for f in fields)})
        return out
    label = section_label(key)
    if isinstance(a, list) or isinstance(b, list):
        if all(not isinstance(x, dict) for x in (a or []) + (b or [])):  # list of strings (tags, geography…)
            sa, sb = [str(x) for x in a or []], [str(x) for x in b or []]
            add = [x for x in sb if x not in sa]
            rem = [x for x in sa if x not in sb]
            bits = ([f"+{len(add)}"] if add else []) + ([f"−{len(rem)}"] if rem else []) or ["reordered"]
            return [{"section": key, "label": label, "kind": "list", "summary": " ".join(bits),
                     "added": [{"index": sb.index(x) + 1, "label": x, "item": x} for x in add],
                     "removed": [{"index": sa.index(x) + 1, "label": x, "item": x} for x in rem], "changed": [],
                     "count_before": len(sa), "count_after": len(sb)}]
        d = _list_diff(key, a or [], b or [])
        return [{"section": key, "label": label, **d}] if (d["added"] or d["removed"] or d["changed"]) else []
    if isinstance(a, dict) or isinstance(b, dict):
        fields = _field_changes(_strip(a or {}), _strip(b or {}))
        if not fields:
            return []
        return [{"section": key, "label": label, "kind": "object", "fields": fields,
                 "summary": ", ".join(f"{f['field'].replace('_', ' ')} changed" for f in fields[:4]) + ("…" if len(fields) > 4 else "")}]
    ta, tb = _as_text(a), _as_text(b)
    verb = "added" if not ta else "removed" if not tb else "changed"
    return [{"section": key, "label": label, "kind": "text", "before": ta, "after": tb, "ops": _word_ops(ta, tb),
             "summary": f"{label} {verb}"}]


def record_diff(a: dict, b: dict) -> list[dict]:
    order = list(SECTION_LABELS)
    keys = [k for k in dict.fromkeys([*order, *(a or {}).keys(), *(b or {}).keys()])
            if k not in DIFF_SKIP and not k.startswith("_") and (a or {}).get(k) != (b or {}).get(k)
            and ((a or {}).get(k) not in (None, [], {}, "") or (b or {}).get(k) not in (None, [], {}, ""))]
    out = []
    for k in keys:
        out += _section_diff(k, (a or {}).get(k), (b or {}).get(k))
    return out


def _version_record(db: Session, r: Research, v: int | None) -> tuple[int, dict]:
    if v is None or v == r.version:
        return r.version, r.record or {}
    row = db.query(ResearchVersion).filter_by(research_id=r.id, version=v).order_by(ResearchVersion.id.desc()).first()
    if row is None:
        raise HTTPException(404, f"Version {v} not found")
    return v, row.record or {}


@router.get("/{rid}/diff")
def diff(rid: str, db: Session = Depends(get_db), from_: int | None = Q(default=None, alias="from"),
         to: int | None = None):
    """Structured diff between two versions (default: previous → current). Each section entry carries a summary
    ("+2 IoCs, −1 technique"), and list sections carry added / removed / changed items with field-level word diffs."""
    r = _get(db, rid)
    to_v, b = _version_record(db, r, to)
    if from_ is None:  # the latest stored version before `to` (version numbers can have gaps)
        prev = (db.query(ResearchVersion.version).filter(ResearchVersion.research_id == rid, ResearchVersion.version < to_v)
                .order_by(ResearchVersion.version.desc()).first())
        from_ = prev[0] if prev else 0
    if from_ < 1:
        from_v, a = 0, {}
    else:
        from_v, a = _version_record(db, r, from_)
    sections = record_diff(a, b)
    return {"research_id": rid, "from": from_v, "to": to_v, "sections": sections,
            "summary": "; ".join(f"{s['label']}: {s['summary']}" for s in sections if s.get("summary")) or "No differences"}


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
