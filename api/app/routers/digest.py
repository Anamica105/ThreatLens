"""Daily emerging-threat digest: status, preview and send-now (app/digest.py does the work)."""

from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from .. import digest
from ..db import get_db
from ..deps import current_user
from ..models import User

router = APIRouter(prefix="/api/digest", tags=["digest"])
ADMIN_ROLES = {"lead", "admin"}


@router.get("")
def digest_status(db: Session = Depends(get_db)):
    return digest.status(db)


@router.get("/preview", response_class=HTMLResponse)
def digest_preview(user: User = Depends(current_user)):
    """Rank today's feed items and render the email without researching, sending or marking anything as sent."""
    out = digest.run_digest(dry_run=True)
    if not out.get("ok"):
        raise HTTPException(409 if "already running" in out.get("error", "") else 502, out.get("error"))
    return HTMLResponse(out["html"])


@router.post("/run", status_code=202)
def digest_run(user: User = Depends(current_user)):
    """Send today's digest now, in the background (researches the top threats first when auto-research is on)."""
    if user.role not in ADMIN_ROLES:
        raise HTTPException(403, "Only a lead or admin can send the digest")
    threading.Thread(target=digest.run_digest, name="digest-manual", daemon=True).start()
    return {"started": True}
