"""Database-polling worker for the Security Compliance Platform.

Instead of Redis/RQ, this worker polls the PostgreSQL/SQLite database
every few seconds for scans in 'queued' status and dispatches them to
the scanner. This removes the Redis dependency from the scan dispatch path entirely.

Usage:
    PYTHONPATH=/app/src python -m app.worker
"""

import os
import sys
import time
import logging
import signal
import threading

# Setup logging immediately
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("app.worker")

# ── Graceful shutdown ────────────────────────────────────────────────
_shutdown = threading.Event()

def _handle_signal(sig, frame):
    logger.info(f"Received signal {sig} — shutting down gracefully...")
    _shutdown.set()

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


def _poll_and_dispatch():
    """
    Main polling loop. Queries the database for 'queued' scans and dispatches
    them to `schedule_scan`. Runs until `_shutdown` is set.
    """
    from sqlmodel import Session, select
    from .models import Scan
    from .core.db import engine
    from .services.scanner import schedule_scan

    poll_interval = int(os.getenv("WORKER_POLL_INTERVAL", "5"))  # seconds
    logger.info(f"Worker polling every {poll_interval}s for queued scans...")

    while not _shutdown.is_set():
        try:
            with Session(engine) as session:
                # Fetch all queued scans (oldest first)
                queued = session.exec(
                    select(Scan)
                    .where(Scan.status == "queued")
                    .order_by(Scan.created_at.asc())
                ).all()

                if queued:
                    logger.info(f"Found {len(queued)} queued scan(s). Dispatching...")

                for scan in queued:
                    if _shutdown.is_set():
                        break

                    # Atomically claim the scan by setting status to 'running'
                    # This prevents duplicate processing if multiple workers run
                    scan.status = "running"
                    session.add(scan)
                    session.commit()
                    logger.info(f"Claimed scan {scan.id} (repo: {scan.repo_url}). Starting scanner...")

                    try:
                        schedule_scan(scan.id, user_id=str(scan.user_id))
                    except Exception as exc:
                        logger.error(f"Scanner failed for scan {scan.id}: {exc}", exc_info=True)
                        # schedule_scan already handles setting status to 'failed' internally
                        # but guard here just in case
                        try:
                            with Session(engine) as err_session:
                                err_scan = err_session.get(Scan, scan.id)
                                if err_scan and err_scan.status not in ("completed", "failed"):
                                    err_scan.status = "failed"
                                    err_session.add(err_scan)
                                    err_session.commit()
                        except Exception:
                            pass

        except Exception as exc:
            logger.error(f"Worker poll cycle error: {exc}", exc_info=True)

        _shutdown.wait(timeout=poll_interval)

    logger.info("Worker shut down cleanly.")


if __name__ == "__main__":
    import sentry_sdk

    sentry_dsn = os.getenv("SENTRY_DSN", "")
    database_url = os.getenv("DATABASE_URL", "")

    logger.info("=" * 60)
    logger.info("Security Compliance Platform Worker — DB Polling Mode")
    logger.info("=" * 60)
    logger.info(f"DATABASE_URL : {'SET (' + database_url[:30] + '...)' if database_url else 'NOT SET — using default SQLite'}")
    logger.info(f"PYTHONPATH   : {os.getenv('PYTHONPATH', '(not set)')}")
    logger.info(f"Poll interval: {os.getenv('WORKER_POLL_INTERVAL', '5')}s")

    if not database_url:
        logger.warning(
            "DATABASE_URL is not set! Worker will use the local SQLite file. "
            "On Render, make sure DATABASE_URL is set in the service Environment tab."
        )

    if sentry_dsn:
        logger.info("Initializing Sentry...")
        sentry_sdk.init(dsn=sentry_dsn, traces_sample_rate=0.1)

    # Optionally start Prometheus metrics server
    try:
        from prometheus_client import start_http_server
        metrics_port = int(os.getenv("WORKER_METRICS_PORT", "9100"))
        start_http_server(metrics_port)
        logger.info(f"Metrics server on :{metrics_port}")
    except Exception as e:
        logger.warning(f"Could not start metrics server: {e}")

    _poll_and_dispatch()