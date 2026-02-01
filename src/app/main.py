from fastapi import FastAPI, Depends, Response
import os
from .api.routers import router
from .core.config import Settings
from .core.db import init_db

# observability
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import sentry_sdk

settings = Settings()
SENTRY_DSN = os.getenv("SENTRY_DSN", "")

# init Sentry if provided
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.1)

app = FastAPI(title="security-compliance-platform - scanner API")
app.include_router(router, prefix="/api/v1")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
