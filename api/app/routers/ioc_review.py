"""Per-record IoC review (spec §2 step 8 "Remove false positives", §9) and IoC expiry settings.

PATCH /api/research/{rid}/iocs records analyst decisions on a record's indicators (false positive, benign, excluded
from hunts, restore), saves a new record version, logs activity, optionally propagates the verdict to the IoC library
(an override that later runs respect), and regenerates ONLY the record's IoC retro-hunt groups (IOC-IPV4 / IOC-DOMAIN /
IOC-SHA256) so hidden indicators drop out of the hunt queries. Every other query group is left untouched.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import osint
from ..db import get_db
from ..deps import current_user
from ..ioc import refang
from ..models import Ioc, Research, User
from ..pipeline.stages import regenerate_ioc_queries, workspace_platforms
from ..records import (apply_ioc_review, ioc_key, library_intel_first_seen, library_overrides_by_key, log_activity,
                       save_record, set_ioc_override)

router = APIRouter(prefix="/api", tags=["ioc-review"])

ReviewVerdict = Literal["malicious", "suspicious", "benign", "false_positive"]
_LABEL = {"malicious": "malicious", "suspicious": "suspicious", "benign": "benign", "false_positive": "false positive"}


class IocDecision(BaseModel):
    type: str
    value: str  # defanged or refanged
    verdict: ReviewVerdict | None = None
    excluded: bool | None = None  # True = leave out of hunt queries whatever the verdict; False = include again
    note: str | None = Field(default=None, max_length=1000)
    restore: bool = False  # drop the analyst decision: back to the pipeline (or library) verdict, included in hunts


class IocReviewIn(BaseModel):
    items: list[IocDecision] = []
    propagate: bool = False  # also write the verdict as a library override (restore clears it)
    include_expired: bool | None = None  # hunter opt-in: keep expired infrastructure in the retro-hunts
    summary: str | None = None


def _describe(items: list[IocDecision]) -> str:
    if all(i.restore for i in items):
        return "restored"
    verdicts = {i.verdict for i in items if i.verdict}
    if len(verdicts) == 1 and not any(i.restore for i in items):
        return "marked " + _LABEL[verdicts.pop()]
    if all(i.excluded for i in items) and not verdicts:
        return "excluded from hunts"
    if all(i.excluded is False for i in items) and not verdicts:
        return "included in hunts again"
    return "reviewed"


@router.patch("/research/{rid}/iocs")
def review_iocs(rid: str, body: IocReviewIn | list[IocDecision] = Body(...), db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    """Body: {items: [{type, value, verdict?, excluded?, note?, restore?}], propagate?, include_expired?} (a bare list of
    items is accepted too). Returns {version, record, iocs, changes: [{group, before, after}], hidden_count, updated,
    propagated}. 404 unknown record / indicator, 409 archived, 422 empty request."""
    if isinstance(body, list):
        body = IocReviewIn(items=body)
    r = db.get(Research, rid)
    if r is None:
        raise HTTPException(404, "This research doesn't exist. It may have been archived or the link is wrong.")
    if r.status == "archived":
        raise HTTPException(409, "Archived research is read-only. Restore it first.")
    if not body.items and body.include_expired is None:
        raise HTTPException(422, "Nothing to change: send at least one indicator decision or include_expired.")

    rec = copy.deepcopy(r.record or {})
    by_key = {ioc_key(i.get("type", ""), i.get("value", "")): i for i in rec.get("iocs", []) or []}
    missing = [f"{d.type} {d.value}" for d in body.items if ioc_key(d.type, d.value) not in by_key]
    if missing:
        raise HTTPException(404, f"Not an indicator of {rid}: {', '.join(missing[:5])}")

    review = dict(rec.get("ioc_review") or {})
    decisions = dict(review.get("decisions") or {})
    now = datetime.now(timezone.utc).isoformat()
    for d in body.items:
        k = ioc_key(d.type, d.value)
        if d.restore:
            decisions.pop(k, None)
            continue
        cur = dict(decisions.get(k) or {})
        if d.verdict is not None:
            cur["verdict"] = d.verdict
        if d.excluded is not None:
            cur["excluded"] = d.excluded
        if d.note is not None:
            cur["note"] = d.note.strip()
        if not cur.get("verdict") and not cur.get("excluded"):
            decisions.pop(k, None)  # nothing left to record (e.g. included again with no verdict)
            continue
        cur.update(by=user.id, by_name=user.name, at=now)
        decisions[k] = cur
    review["decisions"] = decisions
    if body.include_expired is not None:
        review["include_expired"] = body.include_expired
    rec["ioc_review"] = review

    propagated = 0
    if body.propagate:
        for d in body.items:
            if not d.restore and d.verdict is None:
                continue  # exclusion is a per-record hunt decision; nothing to propagate
            row = db.query(Ioc).filter_by(type=d.type, value=refang(d.value)).first()
            if row is None:
                continue
            set_ioc_override(db, row.id, None if d.restore else d.verdict, user.id, note=d.note, research_id=rid, by_name=user.name)
            if not d.restore:
                row.verdict = d.verdict
            propagated += 1

    apply_ioc_review(rec, library_overrides_by_key(db))
    changes = regenerate_ioc_queries(db, rec, fallback_platforms=workspace_platforms(db, r.workspace_ids or []))
    review_state = rec.setdefault("review", {})
    if "iocs" in review_state:
        review_state["iocs"] = "edited"

    what = _describe(body.items) if body.items else ("expired indicators " + ("included in" if body.include_expired else "left out of") + " retro-hunts")
    n = len(body.items)
    regen = ("; retro-hunt queries regenerated: " + ", ".join(f"{c['group']} {c['before']}→{c['after']}" for c in changes)) if changes else ""
    summary = body.summary or (f"{n} indicator{'s' if n != 1 else ''} {what}" if n else what[:1].upper() + what[1:])
    if r.status == "published":
        r.status = "in_review"
        log_activity(db, rid, "status", f"Moved back to review after IoC review by {user.name}", user.id)
    save_record(db, r, rec, user.id, summary + regen)
    log_activity(db, rid, "ioc_review", f"{summary} by {user.name}{regen}", user.id,
                 iocs=[{"type": d.type, "value": d.value, "verdict": d.verdict, "excluded": d.excluded, "restore": d.restore}
                       for d in body.items][:100],
                 note=next((d.note for d in body.items if d.note), None), propagate=body.propagate, changes=changes)
    db.commit()
    saved = r.record or {}
    iocs = saved.get("iocs", [])
    return {"version": r.version, "record": saved, "iocs": iocs, "changes": changes, "updated": n, "propagated": propagated,
            "hidden_count": sum(1 for i in iocs if i.get("hidden_from_hunts"))}


# ------------------------------------------------------------------ expiry settings (Settings > OSINT)

class ExpiryIn(BaseModel):
    days: dict[str, int | None]


def _expiry_out(db: Session) -> dict:
    return {"days": osint.get_expiry(db), "defaults": osint.EXPIRY_DEFAULTS,
            "note": "Counted from the indicator's intel first-seen (earliest source publication date or OSINT first-seen). "
                    "Empty = never expires."}


@router.get("/settings/ioc-expiry")
def get_ioc_expiry(db: Session = Depends(get_db)):
    return _expiry_out(db)


@router.put("/settings/ioc-expiry")
def put_ioc_expiry(body: ExpiryIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if user.role not in ("admin", "lead"):
        raise HTTPException(403, "Only leads and admins can change IoC expiry")
    try:
        osint.set_expiry(db, body.days)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    # Re-derive expires_at for library rows from their intel first-seen (never from when ThreatLens stored them).
    exp = osint.get_expiry(db)
    for row in db.query(Ioc).filter(Ioc.type.in_(list(exp))).all():
        row.expires_at = osint.expires_at(row.type, library_intel_first_seen(row), exp)
    db.commit()
    return _expiry_out(db)
