"""Research record helpers: ids, versioning, library sync, applicability and coverage gaps."""

from __future__ import annotations

import copy
import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import attack
from .detection import LOG_SOURCES
from .ioc import refang
from .models import (Actor, ActivityEvent, Counter, Ioc, MalwareTool, Query, Research, ResearchLink, ResearchVersion,
                     Result, Vulnerability, Workspace)

RECORD_VERSION = "1"


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:80] or "unnamed"


def next_id(db: Session, name: str, prefix: str, width: int = 4, yearly: bool = False) -> str:
    key = f"{name}-{datetime.now(timezone.utc).year}" if yearly else name
    c = db.get(Counter, key)
    if c is None:
        c = Counter(name=key, value=0)
        db.add(c)
    c.value += 1
    db.flush()
    if yearly:
        return f"{prefix}-{datetime.now(timezone.utc).year}-{c.value:0{width}d}"
    return f"{prefix}-{c.value:0{width}d}"


def new_research_id(db: Session) -> str:
    return next_id(db, "research", "TR", yearly=True)


def log_activity(db: Session, research_id: str | None, type_: str, message: str, user_id: str | None = None, **meta) -> None:
    db.add(ActivityEvent(research_id=research_id, type=type_, message=message, user_id=user_id, meta=meta))


def build_search_text(record: dict) -> str:
    parts = [record.get("title", ""), record.get("executive_summary", "")]
    parts += [v.get("cve", "") for v in record.get("vulnerabilities", [])]
    for a in record.get("threat_actors", []):
        parts += [a.get("name", "")] + a.get("aliases", [])
    parts += [m.get("name", "") for m in record.get("malware_tools", [])]
    parts += [i.get("value", "") for i in record.get("iocs", [])]
    parts += [m.get("technique_id", "") for m in record.get("mitre", [])]
    parts += record.get("tags", [])
    return " ".join(p for p in parts if p).lower()


def _diff(old: dict, new: dict) -> dict:
    changed = [k for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k) and k not in ("version", "updated_at")]
    return {"changed_sections": changed}


def save_record(db: Session, r: Research, record: dict, user_id: str | None, summary: str, bump: bool = True) -> None:
    """Persist a new version of the record, update header columns and library links."""
    old = r.record or {}
    if bump and old:
        r.version = (r.version or 1) + 1
    record = copy.deepcopy(record)
    record["id"] = r.id
    record["version"] = r.version
    record["schema_version"] = RECORD_VERSION
    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    r.record = record
    r.title = record.get("title", r.title)[:200]
    r.severity = record.get("severity") or record.get("impact", {}).get("severity", r.severity)
    r.confidence = record.get("confidence", r.confidence)
    r.tlp = record.get("tlp", r.tlp)
    r.classification = record.get("classification", r.classification)
    r.updated_at = datetime.now(timezone.utc)
    r.search_text = build_search_text(record)
    db.add(ResearchVersion(research_id=r.id, version=r.version, record=record, changed_by=user_id, summary=summary,
                           diff=_diff(old, record)))
    sync_library(db, r)


def _upsert_link(db: Session, rid: str, et: str, key: str) -> None:
    exists = db.query(ResearchLink).filter_by(research_id=rid, entity_type=et, entity_key=key).first()
    if not exists:
        db.add(ResearchLink(research_id=rid, entity_type=et, entity_key=key))


def sync_library(db: Session, r: Research) -> None:
    """Populate the shared libraries from a research record (spec: every run feeds shared libraries)."""
    rec = r.record or {}
    now = datetime.now(timezone.utc)
    db.query(ResearchLink).filter_by(research_id=r.id).delete()
    db.flush()

    for a in rec.get("threat_actors", []):
        aid = slug(a["name"])
        row = db.get(Actor, aid)
        # Alias merge: an existing actor may already carry this name as an alias.
        if row is None:
            for cand in db.query(Actor).all():
                if a["name"].lower() in [x.lower() for x in cand.aliases] or any(
                        al.lower() == cand.name.lower() for al in a.get("aliases", [])):
                    row = cand
                    break
        if row is None:
            row = Actor(id=aid, name=a["name"], first_seen=r.created_at)
            db.add(row)
        row.aliases = sorted(set(row.aliases or []) | set(a.get("aliases", [])) - {row.name})
        row.origin = a.get("origin") or row.origin
        row.motivation = sorted(set(row.motivation or []) | set(a.get("motivation", [])))
        row.target_industries = sorted(set(row.target_industries or []) | {i["industry"] for i in rec.get("industries", [])})
        row.target_regions = sorted(set(row.target_regions or []) | set(rec.get("geography", [])))
        row.last_seen = max(filter(None, [row.last_seen, r.created_at]), default=now)
        db.flush()
        _upsert_link(db, r.id, "actor", row.id)

    for m in rec.get("malware_tools", []):
        mid = slug(m["name"])
        row = db.get(MalwareTool, mid)
        if row is None:
            row = MalwareTool(id=mid, name=m["name"], type=m.get("type", "malware"), capabilities=m.get("role", ""),
                              platforms=m.get("platforms", ["Windows"]), first_seen=r.created_at)
            db.add(row)
        elif m.get("role") and m["role"] not in (row.capabilities or ""):
            row.capabilities = (row.capabilities + " " + m["role"]).strip()[:2000]
        row.last_seen = max(filter(None, [row.last_seen, r.created_at]), default=now)
        db.flush()
        _upsert_link(db, r.id, "malware", mid)

    for v in rec.get("vulnerabilities", []):
        row = db.get(Vulnerability, v["cve"])
        if row is None:
            row = Vulnerability(cve=v["cve"])
            db.add(row)
        row.cvss = v.get("cvss") or row.cvss
        row.epss = v.get("epss") or row.epss
        row.kev_added = v.get("kev_added") or row.kev_added
        row.affected_products = v.get("affected_products") or row.affected_products
        row.patch_kb = v.get("patch_kb") or row.patch_kb
        row.description = v.get("description") or row.description
        db.flush()
        _upsert_link(db, r.id, "cve", v["cve"])

    for i in rec.get("iocs", []):
        val = refang(i["value"])
        row = db.query(Ioc).filter_by(type=i["type"], value=val).first()
        if row is None:
            row = Ioc(type=i["type"], value=val, first_seen=r.created_at)
            db.add(row)
        row.verdict = i.get("verdict", row.verdict)
        if i.get("reputation"):
            row.reputation = i["reputation"]
        ctx = [c for c in (row.context or []) if c.get("research_id") != r.id]
        ctx.append({"research_id": r.id, "context": i.get("context", ""), "role": i.get("role", ""), "sources": i.get("source_ids", [])})
        row.context = ctx[-20:]
        row.last_seen = now
        db.flush()
        _upsert_link(db, r.id, "ioc", f"{row.id}")

    for q in rec.get("hunts", {}).get("queries", []):
        row = db.get(Query, q["id"])
        if row is None:
            row = Query(id=q["id"], title=q["title"], platform=q["platform"], type=q["type"], body=q["body"])
            db.add(row)
        row.title, row.platform, row.type, row.body = q["title"], q["platform"], q["type"], q["body"]
        row.log_sources = q.get("log_sources", [])
        row.techniques = q.get("techniques", [])
        row.fp_notes = q.get("fp_notes", "")
        row.status = q.get("status", row.status)
        row.origin = q.get("origin", "generated")
        row.sigma_ref = q.get("sigma_ref")
        row.updated_at = now
        db.flush()
        _upsert_link(db, r.id, "query", q["id"])

    for m in rec.get("mitre", []):
        _upsert_link(db, r.id, "technique", m["technique_id"])


def applicability(record: dict, ws: Workspace) -> dict:
    """Is this workspace exposed? Match affected products against the workspace's technology in scope."""
    products = [p.lower() for v in record.get("vulnerabilities", []) for p in v.get("affected_products", [])]
    products += [p.lower() for p in record.get("affected_technologies", [])]
    if not products:
        return {"workspace_id": ws.id, "status": "unknown", "reason": "No affected products identified"}
    ws_products = [p.lower() for p in (ws.products or [])]
    for wp in ws_products:
        core = re.sub(r"\b(server|on-prem|on-premises|\d{4}|se|subscription edition)\b", "", wp).strip()
        if any(core and core in p for p in products) or any(p.split(" ")[0] in wp for p in products if p):
            return {"workspace_id": ws.id, "status": "exposed", "reason": f"Runs {wp}"}
    return {"workspace_id": ws.id, "status": "not_exposed", "reason": "No affected product in the workspace technology list"}


def required_categories(record: dict) -> set[str]:
    cats = set()
    for q in record.get("hunts", {}).get("queries", []):
        cats |= set(q.get("data_sources", []))
    return cats


def coverage_gaps(record: dict, ws: Workspace) -> list[dict]:
    have = set(ws.log_sources or [])
    gaps = []
    for do in record.get("detection_opportunities", []):
        for cat in do.get("data_sources", []):
            if cat not in have:
                gaps.append({"workspace_id": ws.id, "behaviour_ref": do.get("behaviour_ref"), "opportunity_id": do.get("id"),
                             "data_source": cat, "detail": f"{ws.name} has no {LOG_SOURCES.get(cat, {}).get('windows', cat)} telemetry"})
    return gaps


def ensure_results(db: Session, r: Research) -> None:
    """Create per-workspace result rows; mark not applicable when the client is not exposed."""
    for wid in r.workspace_ids or []:
        ws = db.get(Workspace, wid)
        if ws is None:
            continue
        row = db.query(Result).filter_by(research_id=r.id, workspace_id=wid).first()
        if row is None:
            app = applicability(r.record or {}, ws)
            status = "not_applicable" if app["status"] == "not_exposed" else "pending"
            summary = app["reason"] if status == "not_applicable" else ""
            db.add(Result(research_id=r.id, workspace_id=wid, status=status, summary=summary))


def tactic_rail(record: dict) -> list[dict]:
    counts = attack.tactic_counts(record.get("mitre", []))
    return [{**t, "count": counts.get(t["id"], 0)} for t in attack.TACTICS]
