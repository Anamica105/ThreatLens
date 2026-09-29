"""Interoperability exports (spec section 3 P2): GET /api/research/{id}/export/stix -> STIX 2.1 bundle download.

Registered before the research router so this path wins over research.py's generic /{rid}/export/{fmt}.
"""

from __future__ import annotations

import copy
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import current_user
from ..exports import stix
from ..models import ExportLog, Research, User
from ..records import apply_ioc_review, library_overrides_by_key, log_activity

router = APIRouter(prefix="/api/research", tags=["interop"])


@router.get("/{rid}/export/stix")
def export_stix(rid: str, db: Session = Depends(get_db), user: User = Depends(current_user), inline: bool = False):
    r = db.get(Research, rid)
    if r is None:
        raise HTTPException(404, "Research not found")
    if not r.record:
        raise HTTPException(409, "No report yet; wait for the run to finish.")
    # Apply the current analyst / library IoC decisions so false positives removed since the last save stay out.
    rec = apply_ioc_review(copy.deepcopy(r.record), library_overrides_by_key(db))
    bundle = stix.build_bundle(r, rec, base_url=get_settings().web_base_url)
    problems = stix.validate(bundle)
    if problems:
        raise HTTPException(500, "STIX bundle failed validation: " + "; ".join(problems[:5]))
    name = f"{rid}-stix.json"
    if not inline:
        n_ind = sum(1 for o in bundle["objects"] if o["type"] == "indicator")
        db.add(ExportLog(research_id=rid, workspace_id=None, format="stix", user_id=user.id, file_name=name,
                         params={"objects": len(bundle["objects"]), "indicators": n_ind}))
        log_activity(db, rid, "exported", f"Exported {rid} as STIX 2.1 bundle ({n_ind} indicators)", user.id, format="stix")
        db.commit()
    disp = "inline" if inline else "attachment"
    return Response(content=json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8"), media_type="application/stix+json;version=2.1",
                    headers={"Content-Disposition": f'{disp}; filename="{name}"'})
