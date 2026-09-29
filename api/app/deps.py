"""Request dependencies and serializers shared by routers.

Auth (spec section 12: SSO via OIDC, roles only) is selected with `AUTH_MODE`:
  dev    - (default) trust the `X-User` user id sent by the web app's user switcher; unknown/missing falls back to the
           first user. Only for local development.
  header - trust the identity header `AUTH_HEADER` (default X-Forwarded-Email) set by an OIDC-validating reverse proxy
           (e.g. oauth2-proxy), and only when the TCP peer is in `AUTH_TRUSTED_PROXIES`. The email maps to `user.email`
           (case-insensitive). `X-User` is ignored. Missing header -> 401; untrusted peer -> 401; unknown email -> 403.
  oidc   - native bearer-token validation; not implemented (501). Keys reserved: OIDC_ISSUER, OIDC_AUDIENCE,
           OIDC_JWKS_URL, OIDC_EMAIL_CLAIM, OIDC_ROLE_CLAIM.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Research, Result, User, Workspace
from .records import tactic_rail

REVIEW_ROLES = {"reviewer", "lead", "admin"}


AUTH_MODES = ("dev", "header", "oidc")


def _trusted(peer: str | None, proxies: str) -> bool:
    if not peer:
        return False
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        ip = None
    for p in (x.strip() for x in proxies.split(",")):
        if not p:
            continue
        if p == peer:  # exact match, also covers non-IP peers such as unix sockets
            return True
        if ip is None:
            continue
        try:
            if ip in ipaddress.ip_network(p, strict=False):
                return True
        except ValueError:
            continue
    return False


def resolve_user(db: Session, headers, peer: str | None) -> User:
    """Identify the caller from request headers and the TCP peer address according to AUTH_MODE.
    Raises HTTPException (401/403/501/500). Shared by `current_user` and anything else that needs the caller
    outside a dependency (e.g. the view-audit middleware)."""
    s = get_settings()
    mode = (s.auth_mode or "dev").lower()
    if mode == "dev":
        x_user = headers.get("x-user")
        user = db.get(User, x_user) if x_user else None
        if user is None:
            user = db.query(User).order_by(User.id).first()
        if user is None:
            raise HTTPException(401, "No users configured")
        return user
    if mode == "header":
        if not _trusted(peer, s.auth_trusted_proxies):
            raise HTTPException(401, "Request did not come through a trusted authentication proxy")
        email = (headers.get(s.auth_header) or "").strip().lower()
        if not email:
            raise HTTPException(401, f"Not signed in (missing {s.auth_header} header from the authentication proxy)")
        user = db.query(User).filter(func.lower(User.email) == email).first()
        if user is None:
            raise HTTPException(403, "Your account is signed in but has no ThreatLens role. Ask an admin to add you.")
        return user
    if mode == "oidc":
        raise HTTPException(501, "AUTH_MODE=oidc is not implemented yet. Use AUTH_MODE=header behind an OIDC proxy "
                                 "(e.g. oauth2-proxy setting X-Forwarded-Email), or configure OIDC_ISSUER, OIDC_AUDIENCE, "
                                 "OIDC_JWKS_URL, OIDC_EMAIL_CLAIM and OIDC_ROLE_CLAIM once native OIDC lands.")
    raise HTTPException(500, f"Unknown AUTH_MODE {mode!r}; expected one of {', '.join(AUTH_MODES)}")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    return resolve_user(db, request.headers, request.client.host if request.client else None)


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
