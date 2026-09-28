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
from ..models import Actor, Ioc, MalwareTool, Query, Research, ResearchLink, User, Vulnerability
from ..records import tactic_rail

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
                    "top_techniques": [{"id": t, "name": (attack.technique(t) or {}).get("name", t), "count": n} for t, n in techs.most_common(3)]})
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
            "seen_in": _seen(db, rids)}


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
                    "first_seen": iso(m.first_seen), "last_seen": iso(m.last_seen)})
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
            "related_actors": [{"id": a, "name": names.get(a, a)} for a in actors], "seen_in": _seen(db, rids), "research_count": len(rids)}


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

def _query_dict(qr: Query, rids: list[str]) -> dict:
    return {"id": qr.id, "title": qr.title, "platform": qr.platform, "type": qr.type, "body": qr.body, "log_sources": qr.log_sources,
            "techniques": qr.techniques, "fp_notes": qr.fp_notes, "status": qr.status, "version": qr.version, "origin": qr.origin,
            "sigma_ref": qr.sigma_ref, "deployed_workspaces": qr.deployed_workspaces, "last_hit": iso(qr.last_hit),
            "updated_at": iso(qr.updated_at), "research_count": len(rids), "research_ids": rids}


@router.get("/queries")
def queries(db: Session = Depends(get_db), q: str | None = None, platform: str | None = None, type: str | None = None,
            status: str | None = None, technique: str | None = None, origin: str | None = None, page: int = 1, page_size: int = 50):
    links = _links(db, "query")
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
        items.append(_query_dict(qr, links.get(qr.id, [])))
    total = len(items)
    return {"total": total, "items": items[(page - 1) * page_size: page * page_size],
            "facets": {"platform": sorted({x.platform for x in db.query(Query).all()})}}


@router.get("/queries/{qid}")
def query_detail(qid: str, db: Session = Depends(get_db)):
    qr = db.get(Query, qid)
    if qr is None:
        raise HTTPException(404, "Query not found")
    rids = [l.research_id for l in db.query(ResearchLink).filter_by(entity_type="query", entity_key=qid).all()]
    siblings = []
    if qr.sigma_ref or qr.platform == "sigma":
        ref = qr.sigma_ref or qr.id
        for s in db.query(Query).filter((Query.sigma_ref == ref) | (Query.id == ref)).all():
            if s.id != qr.id:
                siblings.append({"id": s.id, "platform": s.platform, "status": s.status})
    return {**_query_dict(qr, rids), "seen_in": _seen(db, rids), "siblings": siblings}


class QueryLibPatch(BaseModel):
    status: str | None = None
    body: str | None = None
    fp_notes: str | None = None
    deployed_workspaces: list[str] | None = None


@router.patch("/queries/{qid}")
def patch_lib_query(qid: str, body: QueryLibPatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    from ..detection import lint

    qr = db.get(Query, qid)
    if qr is None:
        raise HTTPException(404, "Query not found")
    data = body.model_dump(exclude_none=True)
    if "body" in data and data["body"] != qr.body:
        qr.version += 1
        issues = lint(qr.platform, data["body"])
        if issues and "status" not in data:
            data["status"] = "generated"
    for k, v in data.items():
        setattr(qr, k, v)
    if qr.deployed_workspaces and qr.status not in ("deployed", "deprecated") and "deployed_workspaces" in data:
        qr.status = "deployed"
    qr.updated_at = datetime.now(timezone.utc)
    db.commit()
    return query_detail(qid, db)


# ------------------------------------------------------------------ IoCs

def _ioc_dict(i: Ioc, rids: list[str]) -> dict:
    srcs = sorted({s for c in (i.context or []) for s in c.get("sources", [])})
    return {"id": i.id, "type": i.type, "value": defang(i.value, i.type), "verdict": i.verdict, "reputation": i.reputation,
            "reputation_summary": osint.reputation_summary(i.reputation or {}), "context": i.context,
            "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "enriched_at": iso(i.enriched_at),
            "expires_at": iso(i.expires_at), "research_count": len(rids), "source_count": len(srcs)}


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
    items = [_ioc_dict(i, links.get(str(i.id), [])) for i in all_rows]
    return {"total": len(items), "items": items[(page - 1) * page_size: page * page_size],
            "facets": {"type": sorted({i.type for i in db.query(Ioc).all()}), "verdict": ["malicious", "suspicious", "benign", "unknown", "expired"]}}


@router.get("/iocs/{iid}")
def ioc_detail(iid: int, db: Session = Depends(get_db)):
    i = db.get(Ioc, iid)
    if i is None:
        raise HTTPException(404, "Indicator not found")
    rids = [l.research_id for l in db.query(ResearchLink).filter_by(entity_type="ioc", entity_key=str(iid)).all()]
    return {**_ioc_dict(i, rids), "seen_in": _seen(db, rids)}


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
    i.verdict = osint.verdict(i.type, rep, reliable, "B" if reliable else None, i.first_seen)
    db.commit()
    return ioc_detail(iid, db)


class IocPatch(BaseModel):
    verdict: str


@router.patch("/iocs/{iid}")
def patch_ioc(iid: int, body: IocPatch, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if body.verdict not in ("malicious", "suspicious", "benign", "unknown", "expired"):
        raise HTTPException(422, "Invalid verdict")
    i = db.get(Ioc, iid)
    if i is None:
        raise HTTPException(404, "Indicator not found")
    i.verdict = body.verdict
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
