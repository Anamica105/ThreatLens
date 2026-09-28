"""Research record helpers: ids, versioning, library sync, applicability and coverage gaps."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import attack
from . import detection
from .detection import LOG_SOURCES
from .ioc import refang
from .models import (Actor, ActivityEvent, Counter, Ioc, MalwareTool, Query, Research, ResearchLink, ResearchVersion,
                     Result, Setting, Vulnerability, Workspace)

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


# ------------------------------------------------------------------ source trail (provenance) helpers

QUERY_PROVENANCE = ("vendor", "derived", "generic")
_IOC_GROUP_TYPES = {"network": ("IPV4", {"ipv4", "ipv6"}), "dns": ("DOMAIN", {"domain"}), "file_hash": ("SHA256", {"sha256", "sha1", "md5"})}


def sort_sids(ids) -> list[str]:
    """Unique source ids in natural order (S2 before S10)."""
    return sorted({i for i in ids if i}, key=lambda x: (int(re.sub(r"\D", "", x) or 0), x))


def spec_key(spec: dict) -> str:
    """Canonical form of a detection spec, so two opportunities with the same logic compare equal."""
    conds = sorted((c.get("field", ""), c.get("op", "equals"), sorted(str(v).lower() for v in c.get("values", [])))
                   for c in spec.get("conditions", []))
    return json.dumps([spec.get("category", ""), conds])


def step_index(paths: list[dict]) -> dict[str, dict]:
    """{"AP-1.2": step} for attack paths as stored in the record (refs) or as synthesised (positional)."""
    out = {}
    for i, p in enumerate(paths or [], 1):
        for j, st in enumerate(p.get("steps", []), 1):
            out[st.get("ref") or f"AP-{i}.{j}"] = st
    return out


def mitre_source_ids(mitre: list[dict], techniques) -> list[str]:
    want = set(techniques or [])
    return sort_sids(s for m in mitre or [] if m.get("technique_id") in want for s in m.get("source_ids", []))


def opportunity_source_ids(o: dict, steps: dict[str, dict], mitre: list[dict]) -> list[str]:
    """Sources of the attack-path step the opportunity detects; the MITRE rows of its techniques if the step has none."""
    st = steps.get(o.get("behaviour_ref") or "") or {}
    return sort_sids(st.get("source_ids") or []) or mitre_source_ids(mitre, o.get("techniques", []))


def backfill_provenance(rec: dict) -> dict:
    """Make sure every detection opportunity has source_ids and every query has group/source_ids/provenance.

    New pipeline runs already set these; this covers records written before the fields existed and hand edits.
    Mutates and returns `rec`.
    """
    mitre = rec.get("mitre", [])
    steps = step_index(rec.get("attack_paths", []))
    opps = {}
    for o in rec.get("detection_opportunities", []) or []:
        if not isinstance(o.get("source_ids"), list):
            o["source_ids"] = opportunity_source_ids(o, steps, mitre)
        opps[o.get("id")] = o
    queries = (rec.get("hunts") or {}).get("queries", []) or []
    ttp_groups: dict[str, str] = {}
    vref = sum(1 for q in queries if str(q.get("group", "")).startswith("VREF-"))
    for q in queries:
        opp = opps.get(q.get("opportunity_id")) if q.get("opportunity_id") else None
        if q.get("provenance") not in QUERY_PROVENANCE:
            q["provenance"] = ("vendor" if q.get("origin") == "reference" else
                               "generic" if q.get("type") == "ttp" and not opp else "derived")
        if not q.get("group"):
            if opp:
                oid = str(opp.get("id", ""))
                q["group"] = "DET-" + oid.split("-", 1)[-1] if oid.startswith("DO-") else f"DET-{oid}"
            elif q["provenance"] == "vendor":
                vref += 1
                q["group"] = f"VREF-{vref}"
            elif q.get("type") == "ioc":
                cat = (q.get("data_sources") or ["network"])[0]
                q["group"] = f"IOC-{_IOC_GROUP_TYPES.get(cat, (cat.upper(), set()))[0]}"
            elif q.get("type") == "vuln":
                q["group"] = "VULN-1"
            else:
                q["group"] = ttp_groups.setdefault(q.get("title", ""), f"TTP-{len(ttp_groups) + 1}")
        if not isinstance(q.get("source_ids"), list):
            if opp:
                sids = opp.get("source_ids", [])
            elif q["provenance"] == "vendor":
                m = re.search(r"\(vendor, (S\d+)\)", q.get("title", ""))
                sids = [m.group(1)] if m else []
            elif q.get("type") == "ioc":
                types = _IOC_GROUP_TYPES.get((q.get("data_sources") or [""])[0], ("", set()))[1]
                sids = sort_sids(s for i in rec.get("iocs", []) if i.get("type") in types for s in i.get("source_ids", []))
            elif q.get("type") == "vuln":
                sids = sort_sids(s for v in rec.get("vulnerabilities", []) for s in v.get("source_ids", []))
            else:
                sids = mitre_source_ids(mitre, q.get("techniques", []))
            q["source_ids"] = list(sids)
    return rec


def relint_queries(rec: dict) -> dict:
    """Re-run lint (syntax + ATT&CK tag check against the catalog) on every generated query, with its techniques.
    Queries still at the automatic statuses move between generated / syntax_checked to match; statuses an analyst set
    (reviewed and later) are kept, with the findings visible in `lint`. Vendor reference queries are never linted.
    Mutates and returns `rec`."""
    for q in (rec.get("hunts") or {}).get("queries", []) or []:
        if q.get("origin") == "reference" or not q.get("platform"):
            continue
        q["lint"] = detection.lint(q["platform"], q.get("body", ""), q.get("techniques"))
        if q.get("status") in (None, "", "generated", "syntax_checked"):
            q["status"] = "generated" if q["lint"] else "syntax_checked"
    return rec


# ------------------------------------------------------------------ IoC verdict overrides
# An analyst's verdict set in the IoC library wins over the pipeline's verdict on every later sync or enrichment.
# Stored in Setting "ioc_verdict_overrides" as {"<ioc id>": {"verdict", "by", "at"}} (no schema change needed).

IOC_OVERRIDE_KEY = "ioc_verdict_overrides"


def ioc_overrides(db: Session) -> dict[str, dict]:
    row = db.get(Setting, IOC_OVERRIDE_KEY)
    return dict(row.value or {}) if row else {}


def set_ioc_override(db: Session, ioc_id: int, verdict: str | None, user_id: str | None) -> None:
    row = db.get(Setting, IOC_OVERRIDE_KEY)
    if row is None:
        row = Setting(key=IOC_OVERRIDE_KEY, value={})
        db.add(row)
    value = dict(row.value or {})
    if verdict is None:
        value.pop(str(ioc_id), None)
    else:
        value[str(ioc_id)] = {"verdict": verdict, "by": user_id, "at": datetime.now(timezone.utc).isoformat()}
    row.value = value
    db.flush()


def _diff(old: dict, new: dict) -> dict:
    changed = [k for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k) and k not in ("version", "updated_at")]
    return {"changed_sections": changed}


def save_record(db: Session, r: Research, record: dict, user_id: str | None, summary: str, bump: bool = True) -> None:
    """Persist a new version of the record, update header columns and library links."""
    old = r.record or {}
    if bump and old:
        r.version = (r.version or 1) + 1
    record = relint_queries(backfill_provenance(copy.deepcopy(record)))
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
    old_queries = {l.entity_key for l in db.query(ResearchLink).filter_by(research_id=r.id, entity_type="query").all()}
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

    overrides = ioc_overrides(db)
    for i in rec.get("iocs", []):
        val = refang(i["value"])
        row = db.query(Ioc).filter_by(type=i["type"], value=val).first()
        if row is None:
            row = Ioc(type=i["type"], value=val, first_seen=r.created_at)
            db.add(row)
        ov = overrides.get(str(row.id)) if row.id is not None else None
        row.verdict = ov["verdict"] if ov else i.get("verdict", row.verdict)
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
        # Never walk a library query back down the lifecycle: a status set in the library (reviewed, deployed, ...)
        # survives a re-sync from a record that still says syntax_checked. Take the more advanced of the two.
        rec_status = q.get("status") or row.status
        row.status = (detection.more_advanced_status(row.status, rec_status) if row.status else rec_status) or "generated"
        if row.deployed_workspaces and detection.status_rank(row.status) < detection.status_rank("deployed"):
            row.status = "deployed"
        row.origin = q.get("origin", "generated")
        row.sigma_ref = q.get("sigma_ref")
        row.updated_at = now
        db.flush()
        _upsert_link(db, r.id, "query", q["id"])

    # Queries replaced by a re-run of query generation: drop them from the library unless another research
    # still links them or they were deployed somewhere (those stay, as history).
    current = {q["id"] for q in rec.get("hunts", {}).get("queries", [])}
    for qid in old_queries - current:
        row = db.get(Query, qid)
        if row is None or row.deployed_workspaces:
            continue
        if db.query(ResearchLink).filter_by(entity_type="query", entity_key=qid).first() is None:
            db.delete(row)
    db.flush()

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
