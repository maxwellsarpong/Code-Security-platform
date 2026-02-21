from fastapi import FastAPI, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
import os
from .api.routers import router
from .core.config import Settings
from .core.db import init_db, engine
from sqlmodel import Session, text
import time

# observability
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import sentry_sdk

settings = Settings()
SENTRY_DSN = os.getenv("SENTRY_DSN", "")

# init Sentry if provided
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.1)

app = FastAPI(title="security-compliance-platform - scanner API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"],  # Allows all headers
)

app.include_router(router, prefix="/api/v1")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health")
def health(response: Response):
    """
    Advanced health check verifying Database and Redis connectivity.
    """
    status = {
        "status": "ok",
        "timestamp": time.time(),
        "services": {
            "database": "unknown",
            "redis": "unknown",
            "workers": "unknown"
        }
    }
    
    # 1. Check Database
    try:
        with Session(engine) as session:
            session.exec(text("SELECT 1"))
            status["services"]["database"] = "ok"
    except Exception as e:
        status["services"]["database"] = f"error: {str(e)}"
        status["status"] = "error"

    # 2. Check Redis & Workers
    try:
        from redis import Redis
        from rq import Worker, Queue
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        conn = Redis.from_url(redis_url, socket_connect_timeout=1)
        
        if conn.ping():
            status["services"]["redis"] = "ok"
            # Check for active workers on 'scans' queue
            q = Queue("scans", connection=conn)
            workers = Worker.all(connection=conn)
            scans_workers = [w for w in workers if "scans" in w.queue_names()]
            status["services"]["workers"] = {
                "count": len(scans_workers),
                "status": "ok" if scans_workers else "no_workers_found"
            }
        else:
            status["services"]["redis"] = "failed_ping"
            status["status"] = "error"
    except Exception as e:
        status["services"]["redis"] = f"error: {str(e)}"
        # Redis failure is critical for scanning but maybe not for the whole API?
        # For now, mark as error to be safe.
        status["status"] = "error"

    if status["status"] != "ok":
        response.status_code = 503
        
    return status


@app.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
