import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import attack, audit, digest
from .config import get_settings
from .db import Base, SessionLocal, engine
from .deps import current_user
from .models import Run
from .routers import dashboard, digest as digest_router, enrichment, intake, interop, ioc_review, library, misc, research, runs
from .seed import seed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    startup()
    yield


app = FastAPI(title="ThreatLens API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[get_settings().web_base_url, "http://localhost:3000", "http://127.0.0.1:3000"],
                   allow_methods=["*"], allow_headers=["*"], expose_headers=["Content-Disposition"])

app.add_middleware(audit.ViewAuditMiddleware)

# interop before research: its /{rid}/export/stix must win over research's /{rid}/export/{fmt}.
# Every route requires an authenticated caller. intake is the exception: its /inbound webhook authenticates with
# INTAKE_WEBHOOK_SECRET, so its other routes declare current_user themselves.
for r in (interop.router, research.router, intake.router, ioc_review.router, runs.router, library.router, dashboard.router, misc.router, enrichment.router,
          audit.router, digest_router.router):
    app.include_router(r, dependencies=[] if r is intake.router else [Depends(current_user)])


def startup() -> None:
    if (get_settings().auth_mode or "dev").lower() == "dev":
        logging.getLogger("threatlens.auth").warning(
            "AUTH_MODE=dev: any caller can act as any user (X-User header). Keep the app on localhost; "
            "use AUTH_MODE=header behind an OIDC proxy for shared deployments.")
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        attack.load_catalog(db)
        seed(db)
        # Runs interrupted by a restart cannot resume in-process; mark them failed so the hunter can retry the stage.
        for run in db.query(Run).filter(Run.status.in_(["running", "queued"])).all():
            run.status = "failed"
            ss = dict(run.stage_status or {})
            for k, v in ss.items():
                if v.get("state") == "running":
                    ss[k] = {**v, "state": "failed", "message": "Interrupted by an API restart. Retry this stage."}
            run.stage_status = ss
        db.commit()
    digest.start_scheduler()


@app.get("/api/health")
def health():
    return {"ok": True}
