"""Request dependencies and serializers shared by routers.

Auth: the spec calls for SSO (Entra ID / Okta via OIDC) with roles only. In this build
the web app sends the signed-in user's id in `X-User`; put an OIDC-validating proxy
(e.g. oauth2-proxy) in front of the API in production and map its identity header here.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .db import get_db
from .models import Research, Result, User, Workspace
from .records import tactic_rail

REVIEW_ROLES = {"reviewer", "lead", "admin"}


def current_user(x_user: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    user = db.get(User, x_user) if x_user else None
    if user is None:
        user = db.query(User).order_by(User.id).first()
    if user is None:
        raise HTTPException(401, "No users configured")
    return user


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def user_dict(u: User | None) -> dict | None:
    if u is None:
        return None
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "initials": u.initials}


def workspace_dict(w: Workspace) -> dict:
    return {"id": w.id, "name": w.name, "industry": w.industry, "color": w.color, "platforms": w.platforms,
            "field_mappings": w.field_mappings, "log_sources": w.log_sources, "products": w.products,
            "branding": {k: v for k, v in (w.branding or {}).items() if k != "logo_data_uri"} | {"has_logo": bool((w.branding or {}).get("logo_data_uri"))},
            "default_tlp": w.default_tlp}


def research_summary(r: Research, results: list[Result], users: dict[str, User], ws_id: str | None = None) -> dict:
    rec = r.record or {}
    by_ws = {x.workspace_id: x for x in results}
    res = by_ws.get(ws_id) if ws_id else None
    queries = [q for q in rec.get("hunts", {}).get("queries", []) if q.get("origin") != "reference"]
    return {
        "id": r.id, "title": r.title, "status": r.status, "severity": r.severity, "confidence": r.confidence, "tlp": r.tlp,
        "classification": r.classification, "workspace_ids": r.workspace_ids,
        "actors": [a["name"] for a in rec.get("threat_actors", [])],
        "cves": [v["cve"] for v in rec.get("vulnerabilities", [])],
        "malware": [m["name"] for m in rec.get("malware_tools", [])],
        "industries": [i["industry"] for i in rec.get("industries", [])],
        "counts": {"ttps": len({m["technique_id"] for m in rec.get("mitre", [])}), "iocs": len(rec.get("iocs", [])),
                   "queries": len(queries), "sources": len(rec.get("sources", []))},
        "platforms": rec.get("hunts", {}).get("platforms", []),
        "result": {"workspace_id": res.workspace_id, "status": res.status, "summary": res.summary} if res else None,
        "results": [{"workspace_id": x.workspace_id, "status": x.status} for x in results],
        "created_at": iso(r.created_at), "updated_at": iso(r.updated_at), "published_at": iso(r.published_at),
        "author": user_dict(users.get(r.created_by)), "rail": tactic_rail(rec), "version": r.version,
        "summary": (rec.get("executive_summary") or "")[:280],
    }
