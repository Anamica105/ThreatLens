from __future__ import annotations

from collections import Counter as Cnt
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import attack, osint
from ..db import get_db
from ..deps import current_user, iso
from ..ioc import defang
from ..models import Actor, Ioc, MalwareTool, Query, Research, ResearchLink, User, Vulnerability, Workspace
from ..records import ioc_overrides, set_ioc_override, tactic_rail

router = APIRouter(prefix="/api/library", tags=["library"])


def _links(db: Session, et: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for l in db.query(ResearchLink).filter_by(entity_type=et).all():
        out.setdefault(l.entity_key, []).append(l.research_id)
    return out


def _seen(db: Session, rids: list[str]) -> list[dict]:
    rows = db.query(Research).filter(Research.id.in_(rids)).all() if rids else []
    rows.sort(key=lambda r: iso(r.created_at) or "", reverse=True)
    return [{"id": r.id, "title": r.title, "severity": r.severity, "status": r.status, "created_at": iso(r.created_at)} for r in rows]


def _live(db: Session, rids: list[str]) -> list[str]:
    if not rids:
        return []
    return [r.id for r in db.query(Research.id).filter(Research.id.in_(rids), Research.status != "archived").all()]


# ------------------------------------------------------------------ provenance (source trail)
#
# Detail endpoints return `provenance`: up to PROV_DETAIL_MAX items of
#   {research_id, research_title, source_id, publisher, title, url, quote}
# one per (research, source) that mentions the entity; `quote` is the evidence/context sentence when one exists, else "".
# List endpoints return only the compact form: `source_count` (distinct research+source pairs) and `publishers`
# (distinct publisher names, first seen first). Both are computed from the research records on request.

PROV_DETAIL_MAX = 50


class _Prov:
    """Per-request cache of research records used to build provenance."""

    def __init__(self, db: Session):
        self.db = db
        self._recs: dict[str, Research | None] = {}

    def research(self, rid: str) -> Research | None:
        if rid not in self._recs:
            self._recs[rid] = self.db.get(Research, rid)
        return self._recs[rid]

    def items(self, rids: list[str], pick) -> list[dict]:
        """pick(rec) -> [(source_id, quote)] for the entity in that record."""
        out, seen = [], set()
        for rid in rids:
            r = self.research(rid)
            if r is None:
                continue
            rec = r.record or {}
            srcs = {s.get("id"): s for s in rec.get("sources", [])}
            for sid, quote in pick(rec):
                if not sid or (rid, sid) in seen:
                    continue
                seen.add((rid, sid))
                s = srcs.get(sid, {})
                out.append({"research_id": rid, "research_title": r.title, "source_id": sid, "publisher": s.get("publisher", ""),
                            "title": s.get("title", ""), "url": s.get("url", ""), "quote": quote or ""})
        return out


def _prov_summary(items: list[dict]) -> dict:
    return {"source_count": len(items), "publishers": list(dict.fromkeys(i["publisher"] for i in items if i["publisher"]))}


def _prov_detail(items: list[dict]) -> dict:
    return {**_prov_summary(items), "provenance": items[:PROV_DETAIL_MAX], "provenance_total": len(items)}


def _claim_quote(rec: dict, sid: str, names: list[str]) -> str:
    """A claim (or ATT&CK evidence quote) from this source that names the entity."""
    names = [n.lower() for n in names if n and len(n) > 2]
    for c in rec.get("claims", []):
        if sid in c.get("source_ids", []) and any(n in c.get("statement", "").lower() for n in names):
            return c["statement"]
    for m in rec.get("mitre", []):
        text = (m.get("procedure", "") + " " + m.get("evidence_quote", "")).lower()
        if sid in m.get("source_ids", []) and m.get("evidence_quote") and any(n in text for n in names):
            return m["evidence_quote"]
    return ""


def _actor_pick(a: Actor):
    names = {a.name.lower()} | {x.lower() for x in (a.aliases or [])}

    def pick(rec: dict):
        for e in rec.get("threat_actors", []):
            en = {e.get("name", "").lower()} | {x.lower() for x in e.get("aliases", [])}
            if en & names:
                for sid in e.get("source_ids", []):
                    yield sid, _claim_quote(rec, sid, [e["name"]] + e.get("aliases", []))
    return pick


def _malware_pick(m: MalwareTool):
    from ..records import slug

    def pick(rec: dict):
        for e in rec.get("malware_tools", []):
            if slug(e.get("name", "")) == m.id:
                first = e["name"].split(" ")[0].split("(")[0]
                for sid in e.get("source_ids", []):
                    yield sid, _claim_quote(rec, sid, [e["name"], first])
    return pick


def _ioc_pick(i: Ioc):
    from ..ioc import refang

    def pick(rec: dict):
        for e in rec.get("iocs", []):
            if e.get("type") == i.type and refang(e.get("value", "")).lower() == (i.value or "").lower():
                quote = (e.get("contexts") or [None])[0] or e.get("context") or ""
                for sid in e.get("source_ids", []):
                    yield sid, quote
    return pick


def _record_query(rec: dict, qid: str) -> dict | None:
    return next((q for q in rec.get("hunts", {}).get("queries", []) if q.get("id") == qid), None)


def _query_pick(qid: str):
    def pick(rec: dict):
        q = _record_query(rec, qid)
        if not q:
            return
        for sid in q.get("source_ids", []):
            quote = ""
            if q.get("provenance") != "vendor":
                if q.get("type") == "ioc":
                    quote = next(((e.get("contexts") or [None])[0] or e.get("context", "") for e in rec.get("iocs", [])
                                  if sid in e.get("source_ids", [])), "")
                else:
                    quote = next((m.get("evidence_quote", "") for m in rec.get("mitre", [])
                                  if m.get("technique_id") in q.get("techniques", []) and sid in m.get("source_ids", [])
                                  and m.get("evidence_quote")), "")
            yield sid, quote
    return pick


# ------------------------------------------------------------------ actors

def _actor_techniques(db: Session, rids: list[str]) -> Cnt:
    c: Cnt = Cnt()
    for r in db.query(Research).filter(Research.id.in_(rids)).all() if rids else []:
        for m in {m["technique_id"]: m for m in (r.record or {}).get("mitre", [])}.values():
            c[m["technique_id"]] += 1
    return c


@router.get("/actors")
def actors(db: Session = Depends(get_db), q: str | None = None, origin: str | None = None, motivation: str | None = None,
           industry: str | None = None, sort: str = "last_seen"):
    links = _links(db, "actor")
    prov = _Prov(db)
    out = []
    for a in db.query(Actor).all():
        rids = _live(db, links.get(a.id, []))
        if q and q.lower() not in (a.name + " " + " ".join(a.aliases or [])).lower():
            continue
        if origin and origin.lower() not in (a.origin or "").lower():
            continue
        if motivation and motivation not in (a.motivation or []):
            continue
        if industry and industry not in (a.target_industries or []):
            continue
        techs = _actor_techniques(db, rids)
        out.append({"id": a.id, "name": a.name, "aliases": a.aliases, "origin": a.origin, "motivation": a.motivation,
                    "target_industries": a.target_industries, "target_regions": a.target_regions, "research_count": len(rids),
                    "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
                    "top_techniques": [{"id": t, "name": (attack.technique(t) or {}).get("name", t), "count": n} for t, n in techs.most_common(3)],
                    **_prov_summary(prov.items(rids, _actor_pick(a)))})
    key = {"name": lambda x: x["name"].lower(), "research": lambda x: -x["research_count"]}.get(sort, lambda x: x["last_seen"] or "")
    out.sort(key=key, reverse=sort == "last_seen")
    return {"items": out, "facets": {"origin": sorted({x["origin"] for x in out if x["origin"]}),
                                     "motivation": sorted({m for x in out for m in x["motivation"]}),
                                     "industry": sorted({i for x in out for i in x["target_industries"]})}}


@router.get("/actors/{aid}")
def actor(aid: str, db: Session = Depends(get_db)):
    a = db.get(Actor, aid)
    if a is None:
        raise HTTPException(404, "Actor not found")
    rids = _live(db, [l.research_id for l in db.query(ResearchLink).filter_by(entity_type="actor", entity_key=aid).all()])
    techs = _actor_techniques(db, rids)
    mitre = [{"technique_id": t, "tactic_id": (attack.technique(t) or {}).get("tactic_ids", [""])[0]} for t in techs]
    tools = Cnt()
    for l in db.query(ResearchLink).filter(ResearchLink.research_id.in_(rids), ResearchLink.entity_type == "malware").all() if rids else []:
        tools[l.entity_key] += 1
    mal = {m.id: m for m in db.query(MalwareTool).filter(MalwareTool.id.in_(list(tools))).all()} if tools else {}
    return {"id": a.id, "name": a.name, "aliases": a.aliases, "origin": a.origin, "motivation": a.motivation,
            "target_industries": a.target_industries, "target_regions": a.target_regions, "description": a.description,
            "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen), "research_count": len(rids),
            "rail": tactic_rail({"mitre": mitre}),
            "techniques": [{"id": t, "name": (attack.technique(t) or {}).get("name", t), "tactic_ids": (attack.technique(t) or {}).get("tactic_ids", []), "count": n}
                           for t, n in techs.most_common()],
            "tools": [{"id": k, "name": mal[k].name, "type": mal[k].type, "count": n} for k, n in tools.most_common() if k in mal],
            "seen_in": _seen(db, rids), **_prov_detail(_Prov(db).items(rids, _actor_pick(a)))}


class ActorPatch(BaseModel):
    aliases: list[str] | None = None
    origin: str | None = None
    motivation: list[str] | None = None
    description: str | None = None
    target_regions: list[str] | None = None


@router.patch("/actors/{aid}")
def patch_actor(aid: str, body: ActorPatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    a = db.get(Actor, aid)
    if a is None:
        raise HTTPException(404, "Actor not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(a, k, v)
    db.commit()
    return actor(aid, db)


# ------------------------------------------------------------------ malware & tools

@router.get("/malware")
def malware(db: Session = Depends(get_db), q: str | None = None, type: str | None = None, sort: str = "last_seen"):
    links = _links(db, "malware")
    actor_links = _links(db, "actor")
    actor_names = {a.id: a.name for a in db.query(Actor).all()}
    prov = _Prov(db)
    out = []
    for m in db.query(MalwareTool).all():
        if q and q.lower() not in m.name.lower():
            continue
        if type and m.type != type:
            continue
        rids = _live(db, links.get(m.id, []))
        related = sorted({actor_names[aid] for aid, rs in actor_links.items() if set(rs) & set(rids) and aid in actor_names})
        cov = 0
        for r in db.query(Research).filter(Research.id.in_(rids)).all() if rids else []:
            cov += len((r.record or {}).get("hunts", {}).get("queries", []))
        out.append({"id": m.id, "name": m.name, "type": m.type, "platforms": m.platforms, "capabilities": m.capabilities,
                    "research_count": len(rids), "related_actors": related, "detection_coverage": cov,
                    "first_seen": iso(m.first_seen), "last_seen": iso(m.last_seen), **_prov_summary(prov.items(rids, _malware_pick(m)))})
    key = {"name": lambda x: x["name"].lower(), "research": lambda x: -x["research_count"]}.get(sort, lambda x: x["last_seen"] or "")
    out.sort(key=key, reverse=sort == "last_seen")
    return {"items": out, "facets": {"type": sorted({x["type"] for x in out})}}


@router.get("/malware/{mid}")
def malware_detail(mid: str, db: Session = Depends(get_db)):
    m = db.get(MalwareTool, mid)
    if m is None:
        raise HTTPException(404, "Malware or tool not found")
    rids = _live(db, [l.research_id for l in db.query(ResearchLink).filter_by(entity_type="malware", entity_key=mid).all()])
    actors = sorted({l.entity_key for l in db.query(ResearchLink).filter(ResearchLink.research_id.in_(rids), ResearchLink.entity_type == "actor").all()}) if rids else []
    names = {a.id: a.name for a in db.query(Actor).filter(Actor.id.in_(actors)).all()} if actors else {}
    hashes = []
    for r in db.query(Research).filter(Research.id.in_(rids)).all() if rids else []:
        for i in (r.record or {}).get("iocs", []):
            if i["type"] in ("sha256", "md5", "sha1") and m.name.split(" ")[0].lower() in (i.get("context", "") + i.get("role", "")).lower():
                hashes.append(i["value"])
    return {"id": m.id, "name": m.name, "type": m.type, "platforms": m.platforms, "capabilities": m.capabilities,
            "hashes": sorted(set(hashes) | set(m.hashes or [])), "first_seen": iso(m.first_seen), "last_seen": iso(m.last_seen),
            "related_actors": [{"id": a, "name": names.get(a, a)} for a in actors], "seen_in": _seen(db, rids), "research_count": len(rids),
            **_prov_detail(_Prov(db).items(rids, _malware_pick(m)))}


class MalwarePatch(BaseModel):
    type: str | None = None
    platforms: list[str] | None = None
    capabilities: str | None = None


@router.patch("/malware/{mid}")
def patch_malware(mid: str, body: MalwarePatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    m = db.get(MalwareTool, mid)
    if m is None:
        raise HTTPException(404, "Not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(m, k, v)
    db.commit()
    return malware_detail(mid, db)


# ------------------------------------------------------------------ queries

def _query_record_entry(qr: Query, rids: list[str], prov: _Prov) -> tuple[str | None, dict]:
    for rid in rids:
        r = prov.research(rid)
        rq = _record_query((r.record or {}) if r else {}, qr.id)
        if rq:
            return rid, rq
    return None, {}


def _ws_mappings(db: Session, ws: str | None) -> dict | None:
    """Field mappings of workspace `ws` (None when no workspace was asked for); 404 for an unknown workspace."""
    if not ws or ws == "all":
        return None
    w = db.get(Workspace, ws)
    if w is None:
        raise HTTPException(404, "Workspace not found")
    return w.field_mappings or {}


def _query_dict(qr: Query, rids: list[str], prov: _Prov, detail: bool = False, trail: bool = True,
                mappings: dict | None = None) -> dict:
    """Library query. From the research record it came from: `group` (shared by the platform variants of one detection,
    unique within that research), `group_id` ("<research_id>/<group>", unique across the library), `source_ids` and
    `provenance_kind` (vendor/derived/generic; the record calls this field `provenance`). `provenance` here is the
    source-trail list (detail only; lists get the compact source_count/publishers)."""
    rid0, rq = _query_record_entry(qr, rids, prov)
    out = {"id": qr.id, "title": qr.title, "platform": qr.platform, "type": qr.type, "body": qr.body, "log_sources": qr.log_sources,
           "techniques": qr.techniques, "fp_notes": qr.fp_notes, "status": qr.status, "version": qr.version, "origin": qr.origin,
           "sigma_ref": qr.sigma_ref, "deployed_workspaces": qr.deployed_workspaces, "last_hit": iso(qr.last_hit),
           "updated_at": iso(qr.updated_at), "research_count": len(rids), "research_ids": rids,
           "group": rq.get("group"), "group_id": f"{rid0}/{rq['group']}" if rq.get("group") else None,
           "source_ids": rq.get("source_ids", []),
           "provenance_kind": rq.get("provenance") or ("vendor" if qr.origin == "reference" else None)}
    if mappings is not None:
        from ..detection import map_query
        out.update(map_query({"body": qr.body, "platform": qr.platform, "origin": qr.origin, "techniques": qr.techniques},
                             mappings))
    if trail:
        items = prov.items(rids, _query_pick(qr.id))
        out.update(_prov_detail(items) if detail else _prov_summary(items))
    return out


@router.get("/queries")
def queries(db: Session = Depends(get_db), q: str | None = None, platform: str | None = None, type: str | None = None,
            status: str | None = None, technique: str | None = None, origin: str | None = None, group_id: str | None = None,
            provenance_kind: str | None = None, page: int = 1, page_size: int = 50, ws: str | None = None):
    """With `ws=<workspace id>` every item also carries mapped_body / mapped_lint / mapping_applied (that workspace's
    field mappings applied server-side, lint re-run on the mapped text)."""
    mappings = _ws_mappings(db, ws)
    links = _links(db, "query")
    prov = _Prov(db)
    rows = db.query(Query)
    if platform:
        rows = rows.filter(Query.platform == platform)
    if type:
        rows = rows.filter(Query.type == type)
    if status:
        rows = rows.filter(Query.status == status)
    if origin:
        rows = rows.filter(Query.origin == origin)
    items = []
    for qr in rows.order_by(Query.updated_at.desc(), Query.id.desc()).all():
        if technique and technique.upper() not in (qr.techniques or []):
            continue
        if q and q.lower() not in (qr.title + " " + qr.body + " " + qr.id).lower():
            continue
        items.append((qr, links.get(qr.id, [])))
    if group_id or provenance_kind:
        keep = []
        for qr, rids in items:
            d = _query_dict(qr, rids, prov, trail=False)
            if (not group_id or d["group_id"] == group_id) and (not provenance_kind or d["provenance_kind"] == provenance_kind):
                keep.append((qr, rids))
        items = keep
    total = len(items)
    page_items = [_query_dict(qr, rids, prov, mappings=mappings) for qr, rids in items[(page - 1) * page_size: page * page_size]]
    return {"total": total, "items": page_items,
            "facets": {"platform": sorted({x.platform for x in db.query(Query).all()})}}


@router.get("/queries/{qid}")
def query_detail(qid: str, db: Session = Depends(get_db), ws: str | None = None):
    """`ws=<workspace id>` adds mapped_body / mapped_lint / mapping_applied."""
    mappings = _ws_mappings(db, ws)
    qr = db.get(Query, qid)
    if qr is None:
        raise HTTPException(404, "Query not found")
    rids = [l.research_id for l in db.query(ResearchLink).filter_by(entity_type="query", entity_key=qid).all()]
    prov = _Prov(db)
    d = _query_dict(qr, rids, prov, detail=True, mappings=mappings)
    siblings = []
    if d["group_id"]:
        # All platform variants of the same detection (same research, same group).
        rid, group = d["group_id"].split("/", 1)
        r = prov.research(rid)
        for s in (r.record or {}).get("hunts", {}).get("queries", []) if r else []:
            if s.get("group") == group and s["id"] != qr.id:
                siblings.append({"id": s["id"], "platform": s["platform"], "status": s.get("status")})
    elif qr.sigma_ref or qr.platform == "sigma":
        ref = qr.sigma_ref or qr.id
        for s in db.query(Query).filter((Query.sigma_ref == ref) | (Query.id == ref)).all():
            if s.id != qr.id:
                siblings.append({"id": s.id, "platform": s.platform, "status": s.status})
    return {**d, "seen_in": _seen(db, rids), "siblings": siblings}


class QueryLibPatch(BaseModel):
    status: str | None = None
    body: str | None = None
    fp_notes: str | None = None
    deployed_workspaces: list[str] | None = None


@router.patch("/queries/{qid}")
def patch_lib_query(qid: str, body: QueryLibPatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Status must be one of detection.QUERY_STATUSES (generated, syntax_checked, reviewed, lab_tested, deployed,
    reference, deprecated); 422 otherwise, 409 when the query fails lint and the status needs a clean lint."""
    from ..detection import check_status_change, lint

    qr = db.get(Query, qid)
    if qr is None:
        raise HTTPException(404, "Query not found")
    data = body.model_dump(exclude_none=True)
    new_body = data.get("body", qr.body)
    issues = [] if qr.origin == "reference" else lint(qr.platform, new_body, qr.techniques)
    if "status" in data:
        why = check_status_change(data["status"], origin=qr.origin, lint_issues=issues)
        if why:
            raise HTTPException(422 if "Unknown query status" in why else 409, why)
    if "body" in data and data["body"] != qr.body:
        qr.version += 1
        if "status" not in data and qr.origin != "reference":
            data["status"] = "generated" if issues else "syntax_checked"
    for k, v in data.items():
        setattr(qr, k, v)
    if qr.deployed_workspaces and qr.status not in ("deployed", "deprecated") and "deployed_workspaces" in data:
        qr.status = "deployed"
    qr.updated_at = datetime.now(timezone.utc)
    db.commit()
    return query_detail(qid, db)


# ------------------------------------------------------------------ IoCs

def _ioc_dict(i: Ioc, rids: list[str], prov: _Prov, detail: bool = False, overrides: dict | None = None) -> dict:
    """`verdict_override` = {verdict, by, at} when an analyst set the verdict in the library (it then survives re-runs and
    enrichment), else null."""
    srcs = sorted({s for c in (i.context or []) for s in c.get("sources", [])})
    return {"id": i.id, "type": i.type, "value": defang(i.value, i.type), "verdict": i.verdict, "reputation": i.reputation,
            "reputation_summary": osint.reputation_summary(i.reputation or {}), "context": i.context,
            "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "enriched_at": iso(i.enriched_at),
            "expires_at": iso(i.expires_at), "research_count": len(rids), "source_count": len(srcs),
            "verdict_override": (overrides or {}).get(str(i.id)),
            **(_prov_detail if detail else _prov_summary)(prov.items(rids, _ioc_pick(i)))}


@router.get("/iocs")
def iocs(db: Session = Depends(get_db), q: str | None = None, type: str | None = None, verdict: str | None = None,
         page: int = 1, page_size: int = 100):
    from ..ioc import refang

    links = _links(db, "ioc")
    rows = db.query(Ioc)
    if type:
        rows = rows.filter(Ioc.type == type)
    if verdict:
        rows = rows.filter(Ioc.verdict == verdict)
    if q:
        rows = rows.filter(Ioc.value.ilike(f"%{refang(q)}%"))
    all_rows = rows.order_by(Ioc.last_seen.desc(), Ioc.id.desc()).all()
    prov = _Prov(db)
    page_rows = all_rows[(page - 1) * page_size: page * page_size]
    ov = ioc_overrides(db)
    items = [_ioc_dict(i, links.get(str(i.id), []), prov, overrides=ov) for i in page_rows]
    return {"total": len(all_rows), "items": items,
            "facets": {"type": sorted({i.type for i in db.query(Ioc).all()}), "verdict": ["malicious", "suspicious", "benign", "unknown", "expired"]}}


@router.get("/iocs/{iid}")
def ioc_detail(iid: int, db: Session = Depends(get_db)):
    i = db.get(Ioc, iid)
    if i is None:
        raise HTTPException(404, "Indicator not found")
    rids = [l.research_id for l in db.query(ResearchLink).filter_by(entity_type="ioc", entity_key=str(iid)).all()]
    return {**_ioc_dict(i, rids, _Prov(db), detail=True, overrides=ioc_overrides(db)), "seen_in": _seen(db, rids)}


@router.post("/iocs/{iid}/enrich")
def enrich_ioc(iid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    i = db.get(Ioc, iid)
    if i is None:
        raise HTTPException(404, "Indicator not found")
    keys = osint.get_keys(db)
    if not any(keys.values()):
        raise HTTPException(409, "No OSINT API keys configured. Add them in Settings > OSINT API keys.")
    rep = osint.enrich(i.type, i.value, keys)
    i.reputation = rep
    i.enriched_at = datetime.now(timezone.utc)
    reliable = any(c.get("role") for c in (i.context or []))
    ov = ioc_overrides(db).get(str(i.id))
    i.verdict = ov["verdict"] if ov else osint.verdict(i.type, rep, reliable, "B" if reliable else None, i.first_seen)
    db.commit()
    return ioc_detail(iid, db)


class IocPatch(BaseModel):
    verdict: str | None = None
    clear_override: bool = False  # drop the analyst override; the verdict is recomputed on the next sync/enrichment


@router.patch("/iocs/{iid}")
def patch_ioc(iid: int, body: IocPatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Setting a verdict here records an analyst override that later research syncs and enrichment do not clobber."""
    if not body.clear_override and body.verdict not in ("malicious", "suspicious", "benign", "unknown", "expired"):
        raise HTTPException(422, "Invalid verdict")
    i = db.get(Ioc, iid)
    if i is None:
        raise HTTPException(404, "Indicator not found")
    if body.clear_override:
        set_ioc_override(db, iid, None, user.id)
    else:
        i.verdict = body.verdict
        set_ioc_override(db, iid, body.verdict, user.id)
    db.commit()
    return ioc_detail(iid, db)


# ------------------------------------------------------------------ CVEs (used by search and chips)

@router.get("/cves/{cve}")
def cve_detail(cve: str, db: Session = Depends(get_db)):
    v = db.get(Vulnerability, cve.upper())
    if v is None:
        raise HTTPException(404, "CVE not in the library")
    rids = [l.research_id for l in db.query(ResearchLink).filter_by(entity_type="cve", entity_key=v.cve).all()]
    return {"cve": v.cve, "cvss": v.cvss, "epss": v.epss, "kev_added": v.kev_added, "description": v.description,
            "affected_products": v.affected_products, "patch_kb": v.patch_kb, "seen_in": _seen(db, rids)}
