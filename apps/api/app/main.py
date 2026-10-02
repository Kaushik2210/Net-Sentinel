import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from alembic.config import Config
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from alembic import command
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.middleware import SecurityHeadersMiddleware
from app.core.ratelimit import limiter
from app.db.session import SessionLocal
from app.ml.service import get_model
from app.services.bus import bus
from app.services.detection_loop import run_detection_loop
from app.services.ingest import run_ingest
from app.services.seed import seed_detection, seed_network, seed_users

log = logging.getLogger("netsentinel.app")
settings = get_settings()


def run_migrations() -> None:
    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent.parent / "alembic"))
    command.upgrade(cfg, "head")


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    await asyncio.to_thread(run_migrations)
    with SessionLocal() as db:
        seed_users(db)
        seed_network(db)
        seed_detection(db)
    await asyncio.to_thread(get_model)  # train once at startup (~2 s) so the first request is fast
    tasks = [asyncio.create_task(run_ingest(), name="telemetry-ingest"), asyncio.create_task(run_detection_loop(), name="detection-loop")]
    log.info("NetSentinel %s started (env=%s, telemetry=%s)", settings.app_version, settings.environment, settings.telemetry_mode)
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t


app = FastAPI(
    title="NetSentinel API",
    version=settings.app_version,
    description=(
        "Explainable network digital twin and security investigation platform. "
        "Telemetry in SIMULATION mode is synthetic and clearly labelled as such."
    ),
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(api_router)


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception) -> JSONResponse:
    # Detail goes to the log; the client only gets a generic message.
    log.exception("unhandled error: %s", exc)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


@app.get("/health", tags=["system"])
def health() -> dict:
    return {
        "status": "ok",
        "version": settings.app_version,
        "telemetry_mode": settings.telemetry_mode,
        "live_subscribers": bus.subscriber_count,
    }
