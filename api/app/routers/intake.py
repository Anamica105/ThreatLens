"""Email intake API (spec section 3 P1 "Email intake (forward-to-run)").

POST /api/intake/email          .eml upload (multipart field `file`) or a raw RFC 822 body -> parsed intake item.
                                 ?create=true (default) also saves a DRAFT run when a workspace is known (routing map or
                                 ?workspace_id=); ?create=false only previews + stores the item for the intake page.
POST /api/intake/inbound        inbound-mail webhook (Postmark JSON best supported; SendGrid Inbound Parse and Mailgun
                                 routes as JSON or form posts). Needs INTAKE_WEBHOOK_SECRET: header `X-Intake-Secret`,
                                 or HTTP Basic auth whose password is the secret (Postmark/SendGrid cannot add headers:
                                 configure https://intake:<secret>@host/api/intake/inbound).
GET  /api/intake                recent items; GET /api/intake/{id} one item.
POST /api/intake/{id}/draft     create the draft run from an item with the hunter's choices (workspaces, platforms, URLs).
POST /api/intake/{id}/dismiss   mark an item dismissed.
GET|PUT /api/intake/routing     sender domain / +tag -> workspace map (PUT: lead/admin).

Email content is untrusted: it is parsed and stored as data, links are never fetched here, and the run pipeline treats
the seed like any hunter-typed seed (guardrails apply there).
"""

from __future__ import annotations

import base64
import hmac
import json
import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import detection, intake
from ..db import get_db
from ..deps import current_user
from ..models import User, Workspace
from ..records import log_activity
from . import research as research_router

router = APIRouter(prefix="/api/intake", tags=["intake"])

TLPS = ("CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED")


def _platforms_for(db: Session, ws_ids: list[str]) -> list[str]:
    out: list[str] = []
    for w in db.query(Workspace).filter(Workspace.id.in_(ws_ids)).all():
        out += [p for p in (w.platforms or []) if p in detection.PLATFORM_IDS and p not in out]
    return out or (["sigma"] if "sigma" in detection.PLATFORM_IDS else detection.PLATFORM_IDS[:1])


def _create_draft(db: Session, item: dict, user: User, ws_ids: list[str], platforms: list[str] | None = None,
                  seed: str | None = None, seed_urls: list[str] | None = None, tlp: str | None = None) -> dict:
    """Save a draft run through the same code path as POST /api/research (draft=True), then link it to the item."""
    if item.get("research_id"):
        raise HTTPException(409, f"A draft already exists for this email: {item['research_id']}")
    ws_rows = db.query(Workspace).filter(Workspace.id.in_(ws_ids)).all()
    if not ws_rows or len(ws_rows) != len(set(ws_ids)):
        raise HTTPException(422, "Pick at least one existing workspace")
    urls = seed_urls if seed_urls is not None else [u["url"] for u in item.get("urls", []) if u.get("include")]
    tlp = tlp or item.get("tlp") or ws_rows[0].default_tlp or "AMBER"
    body = research_router.NewRun(
        seed=(seed or item.get("seed") or "")[: intake.MAX_SEED_CHARS + 10], seed_urls=urls[:25], workspace_ids=ws_ids,
        platforms=platforms or _platforms_for(db, ws_ids), tlp=tlp if tlp in TLPS else "AMBER", draft=True)
    out = research_router.create_research(body, db=db, user=user)
    log_activity(db, out["id"], "created", f"Created from email intake {item['id']}"
                 + (f" ({item.get('subject')})" if item.get("subject") else ""), user.id, intake_id=item["id"])
    db.commit()
    intake.update_item(db, item["id"], status="draft_created", research_id=out["id"], run_id=out["run_id"],
                       workspace_ids=ws_ids, error=None)
    return out


def _ingest(db: Session, raw: bytes, via: str, user: User | None, create: bool, workspace_id: str | None,
            extra_rcpts: list[str] | None = None) -> dict:
    try:
        parsed = intake.parse_email(raw, db)
    except ValueError as e:
        raise HTTPException(422, str(e))
    dup = intake.find_duplicate(db, parsed["dedup_key"])
    if dup:
        return {"item": dup, "duplicate": True, "draft": None}
    suggested = intake.suggest_workspace(db, parsed, extra_rcpts)
    if workspace_id:
        w = db.get(Workspace, workspace_id)
        if w is None:
            raise HTTPException(422, f"Unknown workspace: {workspace_id}")
        suggested = {"id": w.id, "name": w.name, "reason": "Chosen at upload"}
    item = intake.save_item(db, parsed, via, suggested)
    draft = None
    if create and user is not None:
        if suggested:
            draft = _create_draft(db, item, user, [suggested["id"]])
        else:
            intake.update_item(db, item["id"], status="needs_workspace")
    item = intake.get_item(db, item["id"]) or item
    return {"item": item, "duplicate": False, "draft": draft}


@router.post("/email")
async def upload_email(request: Request, create: bool = True, workspace_id: str | None = None, db: Session = Depends(get_db),
                       user: User = Depends(current_user)):
    ctype = request.headers.get("content-type", "").lower()
    if ctype.startswith("multipart/form-data"):
        form = await request.form()
        f = form.get("file")
        if f is None or not hasattr(f, "read"):
            raise HTTPException(422, "Attach the .eml file in the form field 'file'")
        raw = await f.read(intake.MAX_RAW_BYTES + 1)
    else:
        raw = await request.body()
    if not raw.strip():
        raise HTTPException(422, "Empty email")
    if len(raw) > intake.MAX_RAW_BYTES:
        raise HTTPException(413, "Email is larger than 10 MB")
    return _ingest(db, raw, "upload", user, create, workspace_id)


def _secret_ok(request: Request) -> None:
    secret = os.environ.get("INTAKE_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(503, "Inbound email is not configured (set INTAKE_WEBHOOK_SECRET on the API host)")
    given = request.headers.get("x-intake-secret", "")
    auth = request.headers.get("authorization", "")
    if not given and auth.lower().startswith("basic "):
        try:
            given = base64.b64decode(auth[6:]).decode("utf-8", "replace").partition(":")[2]
        except ValueError:
            given = ""
    if not given or not hmac.compare_digest(given.encode(), secret.encode()):
        raise HTTPException(401, "Bad or missing intake secret")


def _service_user(db: Session) -> User | None:
    uid = intake.get_routing(db).get("user_id")
    u = db.get(User, uid) if uid else None
    return u or db.query(User).filter(User.role.in_(["lead", "admin"])).order_by(User.id).first() or db.query(User).order_by(User.id).first()


@router.post("/inbound")
async def inbound(request: Request, db: Session = Depends(get_db)):
    _secret_ok(request)
    ctype = request.headers.get("content-type", "").lower()
    body = await request.body()
    if len(body) > intake.MAX_RAW_BYTES * 2:  # base64 attachments inflate JSON
        raise HTTPException(413, "Payload too large")
    if "json" in ctype:
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            raise HTTPException(422, "Invalid JSON")
    elif ctype.startswith(("multipart/form-data", "application/x-www-form-urlencoded")):
        form = await request.form()
        payload = {}
        for k, v in form.multi_items():
            payload[k] = (await v.read()).decode("utf-8", "replace") if hasattr(v, "read") else v
    elif ctype.startswith(("message/rfc822", "text/plain")):
        payload = {"raw": body.decode("utf-8", "replace")}
    else:
        raise HTTPException(415, "Send JSON, a form post or message/rfc822")
    if not isinstance(payload, dict):
        raise HTTPException(422, "Expected a JSON object")
    try:
        raw, provider = intake.webhook_to_mime(payload)
    except ValueError as e:
        raise HTTPException(422, str(e))
    rcpts = [str(payload.get(k)) for k in ("OriginalRecipient", "recipient", "to", "To") if payload.get(k)]
    rcpts = [a.strip().lower() for r in rcpts for a in r.replace(";", ",").split(",") if "@" in a]
    rcpts = [a.split("<")[-1].rstrip(">") for a in rcpts]
    out = _ingest(db, raw, f"webhook:{provider}", _service_user(db), True, None, rcpts)
    return {"id": out["item"]["id"], "status": out["item"]["status"], "duplicate": out["duplicate"],
            "research_id": out["item"].get("research_id")}


@router.get("", dependencies=[Depends(current_user)])
def list_items(db: Session = Depends(get_db), limit: int = 50):
    return {"items": [intake.item_summary(x) for x in intake.list_items(db, max(1, min(limit, 200)))]}


class RoutingIn(BaseModel):
    domains: dict[str, str] = {}
    tags: dict[str, str] = {}
    user_id: str | None = None


@router.get("/routing", dependencies=[Depends(current_user)])
def get_routing(db: Session = Depends(get_db)):
    return intake.get_routing(db) | {"webhook_configured": bool(os.environ.get("INTAKE_WEBHOOK_SECRET"))}


@router.put("/routing")
def put_routing(body: RoutingIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if user.role not in ("lead", "admin"):
        raise HTTPException(403, "Only a lead or admin can change intake routing")
    if body.user_id and db.get(User, body.user_id) is None:
        raise HTTPException(422, "Unknown user")
    try:
        return intake.set_routing(db, body.domains, body.tags, body.user_id)
    except ValueError as e:
        raise HTTPException(422, str(e))


@router.get("/{iid}", dependencies=[Depends(current_user)])
def get_item(iid: str, db: Session = Depends(get_db)):
    item = intake.get_item(db, iid)
    if item is None:
        raise HTTPException(404, "Intake item not found")
    return item


class DraftIn(BaseModel):
    workspace_ids: list[str] = Field(min_length=1)
    platforms: list[str] | None = None
    seed: str | None = Field(default=None, min_length=3)
    seed_urls: list[str] | None = None
    tlp: str | None = None


@router.post("/{iid}/draft")
def create_draft(iid: str, body: DraftIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    item = get_item(iid, db)
    if item.get("status") == "dismissed":
        raise HTTPException(409, "This email was dismissed")
    out = _create_draft(db, item, user, body.workspace_ids, body.platforms, body.seed, body.seed_urls, body.tlp)
    return {**out, "item": intake.item_summary(intake.get_item(db, iid) or item)}


@router.post("/{iid}/dismiss", dependencies=[Depends(current_user)])
def dismiss(iid: str, db: Session = Depends(get_db)):
    item = get_item(iid, db)
    if item.get("research_id"):
        raise HTTPException(409, "A draft was already created from this email")
    return intake.item_summary(intake.update_item(db, iid, status="dismissed"))
