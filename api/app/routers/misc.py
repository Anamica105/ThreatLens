from __future__ import annotations

import base64
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import attack, detection, llm, osint
from ..config import get_settings
from ..db import get_db
from ..deps import current_user, iso, user_dict, workspace_dict
from ..exports import render
from ..exports.context import SEV, RESULT, fmt_utc
from ..ioc import detect_type, refang
from ..models import Actor, ExportLog, Ioc, MalwareTool, Query, Research, Result, Setting, User, Vulnerability, Workspace
from ..records import slug
from ..sources import VENDORS
from .dashboard import _aware, dashboard, period_bounds

router = APIRouter(prefix="/api", tags=["misc"])


# ------------------------------------------------------------------ meta & users

@router.get("/meta")
def meta(db: Session = Depends(get_db)):
    s = get_settings()
    sync = (db.get(Setting, "attack_sync") or Setting(value={})).value or {}
    return {
        "platforms": detection.PLATFORMS, "categories": detection.CATEGORIES, "tactics": attack.TACTICS,
        "vendors": [{"id": v["id"], "name": v["name"], "reliability": v["reliability"]} for v in VENDORS],
        "osint_providers": [{"id": p["id"], "name": p["name"], "types": p["types"]} for p in osint.PROVIDERS],
        "llm": {"available": llm.available(), "model": s.llm_model}, "search": {"available": bool(s.brave_search_api_key)},
        "attack": {"version": sync.get("version") or "bundled subset", "techniques": len(attack.all_techniques())},
        "users": [user_dict(u) for u in db.query(User).order_by(User.name).all()],
    }


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {**user_dict(user), "preferences": user.preferences or {}}


class Prefs(BaseModel):
    preferences: dict


@router.patch("/me")
def patch_me(body: Prefs, db: Session = Depends(get_db), user: User = Depends(current_user)):
    u = db.get(User, user.id)
    u.preferences = {**(u.preferences or {}), **body.preferences}
    db.commit()
    return {**user_dict(u), "preferences": u.preferences}


@router.get("/attack/techniques")
def techniques():
    return {"tactics": attack.TACTICS, "techniques": attack.all_techniques()}


# ------------------------------------------------------------------ workspaces

class WorkspaceIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    industry: str = ""
    color: str = "#5249A8"
    platforms: list[str] = []
    field_mappings: dict = {}
    log_sources: list[str] = []
    products: list[str] = []
    branding: dict = {}
    default_tlp: str = "AMBER"


@router.get("/workspaces")
def list_workspaces(db: Session = Depends(get_db)):
    out = []
    for w in db.query(Workspace).order_by(Workspace.name).all():
        n = sum(1 for r in db.query(Research).all() if w.id in (r.workspace_ids or []))
        out.append({**workspace_dict(w), "research_count": n})
    return out


@router.get("/workspaces/{wid}")
def get_workspace(wid: str, db: Session = Depends(get_db)):
    w = db.get(Workspace, wid)
    if w is None:
        raise HTTPException(404, "Workspace not found")
    return workspace_dict(w)


def _validate_ws(body: WorkspaceIn):
    bad = [p for p in body.platforms if p not in detection.PLATFORM_IDS]
    if bad:
        raise HTTPException(422, f"Unknown platform(s): {', '.join(bad)}")
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", body.color):
        raise HTTPException(422, "Colour must be a hex value like #5249A8")


@router.post("/workspaces")
def create_workspace(body: WorkspaceIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    _validate_ws(body)
    wid = slug(body.name)[:40]
    if db.get(Workspace, wid):
        raise HTTPException(409, "A workspace with this name already exists")
    w = Workspace(id=wid, **body.model_dump())
    db.add(w)
    db.commit()
    return workspace_dict(w)


@router.put("/workspaces/{wid}")
def update_workspace(wid: str, body: WorkspaceIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    _validate_ws(body)
    w = db.get(Workspace, wid)
    if w is None:
        raise HTTPException(404, "Workspace not found")
    logo = (w.branding or {}).get("logo_data_uri")
    for k, v in body.model_dump().items():
        setattr(w, k, v)
    if logo and not body.branding.get("remove_logo"):
        w.branding = {**body.branding, "logo_data_uri": logo}
    db.commit()
    return workspace_dict(w)


@router.post("/workspaces/{wid}/logo")
async def upload_logo(wid: str, file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    w = db.get(Workspace, wid)
    if w is None:
        raise HTTPException(404, "Workspace not found")
    if file.content_type not in ("image/png", "image/jpeg"):
        raise HTTPException(422, "Upload a PNG or JPEG logo (exports inline it as base64)")
    data = await file.read()
    if len(data) > 200_000:
        raise HTTPException(422, "Logo must be under 200 KB so email exports stay small")
    w.branding = {**(w.branding or {}), "logo_data_uri": f"data:{file.content_type};base64,{base64.b64encode(data).decode()}"}
    db.commit()
    return workspace_dict(w)


# ------------------------------------------------------------------ settings

@router.get("/settings/osint-keys")
def get_keys(db: Session = Depends(get_db)):
    keys = osint.get_keys(db)
    stored = (db.get(Setting, "osint_keys") or Setting(value={})).value or {}
    return [{"id": p["id"], "name": p["name"], "types": p["types"], "configured": bool(keys.get(p["id"])),
             "source": "settings" if stored.get(p["id"]) else ("environment" if keys.get(p["id"]) else None),
             "hint": ("•••• " + keys[p["id"]][-4:]) if keys.get(p["id"]) else ""} for p in osint.PROVIDERS]


class KeysIn(BaseModel):
    keys: dict[str, str | None]


@router.put("/settings/osint-keys")
def put_keys(body: KeysIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if user.role not in ("admin", "lead"):
        raise HTTPException(403, "Only leads and admins can change OSINT keys")
    row = db.get(Setting, "osint_keys") or Setting(key="osint_keys", value={})
    val = dict(row.value or {})
    for k, v in body.keys.items():
        if k not in {p["id"] for p in osint.PROVIDERS}:
            continue
        if v:
            val[k] = v.strip()
        else:
            val.pop(k, None)
    row.value = val
    db.merge(row)
    db.commit()
    return get_keys(db)


@router.get("/settings/system")
def system(db: Session = Depends(get_db)):
    s = get_settings()
    sync = (db.get(Setting, "attack_sync") or Setting(value={})).value or {}
    return {"llm": {"available": llm.available(), "model": s.llm_model}, "search": {"available": bool(s.brave_search_api_key)},
            "database": s.database_url.split(":")[0], "attack": {"version": sync.get("version") or "bundled subset",
                                                                   "techniques": len(attack.all_techniques())}}


@router.post("/settings/attack-sync")
def attack_sync(db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        return attack.sync_from_mitre(db)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Could not download ATT&CK data from MITRE ({type(e).__name__}). Check network access.")


# ------------------------------------------------------------------ global search

@router.get("/search")
def search(q: str, db: Session = Depends(get_db)):
    q = q.strip()
    if not q:
        return {"groups": [], "jump": None}
    ql = refang(q).lower()
    jump = None
    t = detect_type(q)
    if t == "cve" or re.fullmatch(r"cve-\d{4}-\d{4,7}", ql):
        if db.get(Vulnerability, q.upper()):
            jump = {"kind": "cve", "id": q.upper(), "href": f"/research?cve={q.upper()}"}
    elif t in ("ipv4", "domain", "url", "sha256", "sha1", "md5"):
        hit = db.query(Ioc).filter(Ioc.value.ilike(ql)).first()
        if hit:
            jump = {"kind": "ioc", "id": hit.id, "href": f"/library/iocs/{hit.id}"}
    if re.fullmatch(r"tr-\d{4}-\d{4}", ql):
        r = db.get(Research, q.upper())
        if r:
            jump = {"kind": "research", "id": r.id, "href": f"/research/{r.id}"}

    research = [{"id": r.id, "title": r.title, "sub": f"{r.id} · {r.status.replace('_', ' ')}", "href": f"/research/{r.id}"}
                for r in db.query(Research).filter(Research.status != "archived").all()
                if ql in (r.search_text or "") or ql in r.id.lower()][:6]
    actors = [{"id": a.id, "title": a.name, "sub": ", ".join(a.aliases or [])[:60], "href": f"/library/actors/{a.id}"}
              for a in db.query(Actor).all() if ql in (a.name + " " + " ".join(a.aliases or [])).lower()][:5]
    malware = [{"id": m.id, "title": m.name, "sub": m.type, "href": f"/library/malware/{m.id}"}
               for m in db.query(MalwareTool).all() if ql in m.name.lower()][:5]
    iocs = [{"id": i.id, "title": i.value, "sub": f"{i.type} · {i.verdict}", "href": f"/library/iocs/{i.id}", "ioc_type": i.type}
            for i in db.query(Ioc).filter(Ioc.value.ilike(f"%{ql}%")).limit(5).all()]
    queries = [{"id": x.id, "title": x.title, "sub": f"{x.id} · {x.platform}", "href": f"/library/queries/{x.id}"}
               for x in db.query(Query).all() if ql in (x.title + " " + x.id).lower()][:5]
    groups = [g for g in [
        {"label": "Research", "items": research}, {"label": "Threat actors", "items": actors},
        {"label": "Malware & tools", "items": malware}, {"label": "IoCs", "items": iocs}, {"label": "Queries", "items": queries},
    ] if g["items"]]
    return {"groups": groups, "jump": jump}


# ------------------------------------------------------------------ period exports

class PeriodIn(BaseModel):
    ws: str | None = None
    period: str = "month"
    date_from: str | None = None
    date_to: str | None = None
    format: str = "xlsx"  # xlsx, csv, pdf


@router.post("/exports/period")
def period_export(body: PeriodIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    start, end, label = period_bounds(body.period, body.date_from, body.date_to)
    ws = db.get(Workspace, body.ws) if body.ws and body.ws != "all" else None
    users = {u.id: u.name for u in db.query(User).all()}
    ws_names = {w.id: w.name for w in db.query(Workspace).all()}
    rs = [r for r in db.query(Research).all() if start <= _aware(r.created_at) <= end and (ws is None or ws.id in (r.workspace_ids or []))]
    rs.sort(key=lambda r: iso(r.created_at) or "")
    results = db.query(Result).all()
    rows, ttps, iocs, queries = [], [], [], []
    for r in rs:
        rec = r.record or {}
        rr = [x for x in results if x.research_id == r.id and (ws is None or x.workspace_id == ws.id)]
        rows.append({"id": r.id, "title": r.title, "status": r.status, "created": fmt_utc(r.created_at), "published": fmt_utc(r.published_at),
                     "workspaces": ", ".join(ws_names.get(w, w) for w in r.workspace_ids or []), "severity": r.severity,
                     "classification": ", ".join(r.classification or []), "actors": ", ".join(a["name"] for a in rec.get("threat_actors", [])),
                     "cves": ", ".join(v["cve"] for v in rec.get("vulnerabilities", [])),
                     "results": "; ".join(f"{ws_names.get(x.workspace_id, x.workspace_id)}: {x.status.replace('_', ' ')}" for x in rr),
                     "analyst": users.get(r.created_by, "")})
        for m in rec.get("mitre", []):
            ttps.append({"research_id": r.id, "tactic": m["tactic"], "technique_id": m["technique_id"], "technique": m.get("sub_technique") or m["technique"], "confidence": m.get("confidence")})
        for i in rec.get("iocs", []):
            iocs.append({"research_id": r.id, "type": i["type"], "value": i["value"], "verdict": i.get("verdict"), "sources": " ".join(i.get("source_ids", []))})
        for q in rec.get("hunts", {}).get("queries", []):
            queries.append({"research_id": r.id, "query_id": q["id"], "type": q["type"], "platform": q["platform"], "title": q["title"], "status": q.get("status")})
    scope = ws.name if ws else "All workspaces"
    stamp = f"{start.date().isoformat()}_{end.date().isoformat()}"
    base = f"threatlens-{ws.id if ws else 'all'}-{stamp}"
    if body.format == "xlsx":
        data = render.period_xlsx(rows, ttps, iocs, queries, {"Scope": scope, "Period": label, "From": start.date(), "To": end.date(),
                                                               "Generated": fmt_utc(datetime.now(timezone.utc)), "Generated by": user.name})
        mime, name = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", base + ".xlsx"
    elif body.format == "csv":
        data, mime, name = render.period_csv(rows), "text/csv; charset=utf-8", base + ".csv"
    elif body.format == "pdf":
        d = dashboard(db, body.ws, body.period, body.date_from, body.date_to)
        k = d["kpis"]
        total = max(1, sum(x["count"] for x in d["severity_mix"]))
        vm = {"scope": scope, "label": label, "now": fmt_utc(datetime.now(timezone.utc)), "rows": rows,
              "kpis": [{"label": "Research runs completed", "value": k["runs"]}, {"label": "Published reports", "value": k["published"]},
                       {"label": "Median time to publish", "value": f"{k['median_hours_to_publish']} h" if k["median_hours_to_publish"] is not None else "—"},
                       {"label": "Hunts with findings", "value": k["findings"]}, {"label": "IoCs added", "value": k["iocs"]},
                       {"label": "Queries generated", "value": k["queries"]}],
              "severity": [{"label": SEV[x["severity"]]["label"], "count": x["count"], "pct": round(100 * x["count"] / total),
                            "color": SEV[x["severity"]]["solid"]} for x in d["severity_mix"]],
              "results": [{"label": RESULT[x["status"]]["label"], "count": x["count"]} for x in d["results_by_status"]],
              "actors": d["top_actors"]}
        try:
            data = render.period_summary_pdf(vm)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(500, f"PDF rendering failed ({e}). Run 'python -m playwright install chromium' on the API host.")
        mime, name = "application/pdf", base + "-summary.pdf"
    else:
        raise HTTPException(422, "Format must be xlsx, csv or pdf")
    db.add(ExportLog(research_id=None, workspace_id=body.ws, format=body.format, scope="period",
                     params={"period": body.period, "from": start.date().isoformat(), "to": end.date().isoformat(), "count": len(rows)},
                     user_id=user.id, file_name=name))
    db.commit()
    return Response(content=data, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/exports/history")
def export_history(db: Session = Depends(get_db), limit: int = 100):
    users = {u.id: u for u in db.query(User).all()}
    ws_names = {w.id: w.name for w in db.query(Workspace).all()}
    rows = db.query(ExportLog).order_by(ExportLog.created_at.desc()).limit(limit).all()
    return [{"id": x.id, "research_id": x.research_id, "workspace": ws_names.get(x.workspace_id or "", "All workspaces"),
             "format": x.format, "scope": x.scope, "params": x.params, "file_name": x.file_name, "user": user_dict(users.get(x.user_id)),
             "created_at": iso(x.created_at)} for x in rows]
