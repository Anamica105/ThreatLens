import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import attack, audit
from .config import get_settings
from .db import Base, SessionLocal, engine
from .models import Run
from .routers import dashboard, enrichment, ioc_review, library, misc, research, runs
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

for r in (research.router, ioc_review.router, runs.router, library.router, dashboard.router, misc.router, enrichment.router,
          audit.router):
    app.include_router(r)


def startup() -> None:
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


@app.get("/api/health")
def health():
    return {"ok": True}
