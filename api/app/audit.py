"""View audit log (spec section 13: "audit log of views, edits, exports").

Edits and exports are already recorded (activity_event, research_version, export_log). This module records who
opened what: GET /api/research/{id} and the library detail endpoints. It is a small ASGI middleware, so routers do
not change; it writes after the response is sent, only for 200s, and at most once per user + entity per
`audit_dedupe_minutes` (10 min).

`GET /api/audit` lists the log for leads and admins.
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import get_settings
from .db import SessionLocal, get_db
from .deps import current_user, iso, resolve_user, user_dict
from .models import AuditEvent, User

log = logging.getLogger(__name__)

AUDIT_ROLES = {"lead", "admin"}
VIEW_ROUTES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^/api/research/([^/]+)/?$"), "research"),
    (re.compile(r"^/api/library/actors/([^/]+)/?$"), "actor"),
    (re.compile(r"^/api/library/malware/([^/]+)/?$"), "malware"),
    (re.compile(r"^/api/library/queries/([^/]+)/?$"), "query"),
    (re.compile(r"^/api/library/iocs/([^/]+)/?$"), "ioc"),
    (re.compile(r"^/api/library/cves/([^/]+)/?$"), "cve"),
]
_NOT_ENTITIES = {"check-duplicates", "bulk"}

_recent: dict[tuple[str, str, str], float] = {}
_recent_lock = threading.Lock()


def match_view(method: str, path: str) -> tuple[str, str] | None:
    """(entity_type, entity_id) when this request is a detail view worth auditing."""
    if method != "GET":
        return None
    for rx, etype in VIEW_ROUTES:
        m = rx.match(path)
        if m:
            eid = unquote(m.group(1))
            if eid in _NOT_ENTITIES:
                return None
            return etype, eid.upper() if etype == "cve" else eid
    return None


def _resolve_user(db: Session, header: str | None) -> str | None:
    """Same rule as deps.current_user: the X-User id if it exists, else the first configured user."""
    if header:
        u = db.get(User, header)
        if u:
            return u.id
    u = db.query(User).order_by(User.id).first()
    return u.id if u else None


def record_view(user_header: str | None, etype: str, eid: str, path: str, *, db: Session | None = None,
                at: datetime | None = None) -> bool:
    """Insert a view row unless the same user viewed the same entity within the dedupe window. Returns True if written."""
    at = at or datetime.now(timezone.utc)
    window = timedelta(minutes=get_settings().audit_dedupe_minutes)
    own = db is None
    db = db or SessionLocal()
    try:
        uid = _resolve_user(db, user_header)
        key = (uid or "", etype, eid)
        with _recent_lock:
            last = _recent.get(key)
            if last is not None and at.timestamp() - last < window.total_seconds():
                return False
            _recent[key] = at.timestamp()  # reserve, so concurrent requests do not both write
            if len(_recent) > 20_000:  # keep the in-memory index small
                cutoff = at.timestamp() - window.total_seconds()
                for k in [k for k, v in _recent.items() if v < cutoff]:
                    _recent.pop(k, None)
        # The DB check covers restarts and multiple API workers.
        prior = (db.query(AuditEvent.created_at)
                 .filter(AuditEvent.user_id == uid, AuditEvent.entity_type == etype, AuditEvent.entity_id == eid,
                         AuditEvent.action == "view", AuditEvent.created_at >= at - window)
                 .order_by(AuditEvent.created_at.desc()).first())
        if prior:
            ts = prior[0] if prior[0].tzinfo else prior[0].replace(tzinfo=timezone.utc)
            with _recent_lock:
                _recent[key] = ts.timestamp()  # the window runs from the recorded view, not from this request
            return False
        db.add(AuditEvent(action="view", user_id=uid, entity_type=etype, entity_id=eid[:600], path=path[:600], created_at=at))
        db.commit()
        return True
    except Exception as e:  # noqa: BLE001 - auditing must never break a read
        log.warning("view audit failed for %s %s: %s", etype, eid, e)
        db.rollback()
        return False
    finally:
        if own:
            db.close()


def reset_cache() -> None:
    with _recent_lock:
        _recent.clear()


class ViewAuditMiddleware:
    """Pure ASGI middleware: records successful detail GETs after the response has been sent."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        hit = match_view(scope.get("method", ""), scope.get("path", "")) if scope["type"] == "http" else None
        if hit is None:
            await self.app(scope, receive, send)
            return
        status: dict[str, int] = {}

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        await self.app(scope, receive, _send)
        if status.get("code") == 200:
            peer = (scope.get("client") or (None,))[0]
            user = await run_in_threadpool(_caller_id, Headers(scope=scope), peer)
            await run_in_threadpool(record_view, user, hit[0], hit[1], scope.get("path", ""))


def _caller_id(headers: Headers, peer: str | None) -> str | None:
    """The caller's user id under the configured AUTH_MODE (same rule as deps.current_user)."""
    with SessionLocal() as db:
        try:
            return resolve_user(db, headers, peer).id
        except HTTPException:
            return None


# ------------------------------------------------------------------ API

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit(entity: str | None = None, user: str | None = None, type: str | None = None, action: str | None = None,
               limit: int = 100, offset: int = 0, db: Session = Depends(get_db), me: User = Depends(current_user)):
    """Audit log for leads and admins. `entity` is an id (TR-2026-0142, CVE-2025-53770, 12) or `type:id`."""
    if me.role not in AUDIT_ROLES:
        raise HTTPException(403, "The audit log is available to leads and admins")
    q = db.query(AuditEvent)
    if entity:
        if ":" in entity and entity.split(":", 1)[0] in {t for _, t in VIEW_ROUTES}:
            type, entity = entity.split(":", 1)
        q = q.filter(AuditEvent.entity_id.in_({entity, entity.upper()}))
    if type:
        q = q.filter(AuditEvent.entity_type == type)
    if user:
        q = q.filter(AuditEvent.user_id == user)
    if action:
        q = q.filter(AuditEvent.action == action)
    total = q.count()
    rows = q.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).offset(max(0, offset)).limit(max(1, min(limit, 500))).all()
    users = {u.id: u for u in db.query(User).all()}
    return {"total": total, "items": [
        {"id": x.id, "action": x.action, "entity_type": x.entity_type, "entity_id": x.entity_id, "path": x.path,
         "created_at": iso(x.created_at), "user": user_dict(users.get(x.user_id)) or ({"id": x.user_id} if x.user_id else None)}
        for x in rows]}
