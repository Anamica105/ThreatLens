"""On-demand CVE re-enrichment of a research record (NVD, CISA KEV, FIRST EPSS)."""

from __future__ import annotations

import copy

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import vulns
from ..db import get_db
from ..deps import current_user
from ..models import Research, User
from ..records import log_activity, save_record

router = APIRouter(prefix="/api/research", tags=["enrichment"])


def _comparable(vs: list[dict]) -> list[dict]:
    out = []
    for v in vs:
        v = dict(v)
        if isinstance(v.get("enrichment"), dict):
            v["enrichment"] = {k: x for k, x in v["enrichment"].items() if k not in ("checked_at", "nvd", "kev", "epss")}
        out.append(v)
    return out


@router.post("/{rid}/enrich-cves")
def enrich_cves(rid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = db.get(Research, rid)
    if r is None:
        raise HTTPException(404, "Research not found")
    if r.status == "archived":
        raise HTTPException(409, "Archived research is read-only")
    rec = copy.deepcopy(r.record or {})
    before = rec.get("vulnerabilities") or []
    if not before:
        return {"research_id": rid, "version": r.version, "changed": False, "vulnerabilities": [], "summary": {"checked": 0}}
    after, summary = vulns.enrich(before)  # own session + short timeouts; never raises on network failure
    changed = _comparable(after) != _comparable(before)
    if changed:
        rec["vulnerabilities"] = after
        rec["affected_technologies"] = sorted(set(rec.get("affected_technologies") or [])
                                              | {p for v in after for p in v.get("affected_products", [])})
        save_record(db, r, rec, user.id, "CVE enrichment refreshed (NVD, CISA KEV, EPSS)")
        db.flush()
        vulns.update_library(db, after)
        flagged = summary.get("not_found", []) + summary.get("rejected", []) + summary.get("invalid", [])
        log_activity(db, rid, "edited", f"CVE enrichment refreshed by {user.name}"
                     + (f" · not found in NVD: {', '.join(flagged)}" if flagged else ""), user.id, sources=summary.get("sources"))
        db.commit()
    return {"research_id": rid, "version": r.version, "changed": changed, "vulnerabilities": after, "summary": summary}
