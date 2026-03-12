"""Convenience entrypoint to run an RQ worker locally or in production.

Usage (from project root):
    REDIS_URL=redis://localhost:6379 python -m app.worker
"""

import os
import sys
import logging
import time

# Setup basic logging to stdout immediately (before any imports that might fail)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("app.worker")


def _redact_url(url: str) -> str:
    """Redact password/token from Redis URL for safe logging."""
    if "@" in url:
        prefix = url.rsplit("@", 1)[0]
        suffix = url.rsplit("@", 1)[1]
        scheme = prefix.split("://")[0]
        return f"{scheme}://***@{suffix}"
    return url


def _build_redis_conn(redis_url: str):
    """Build a Redis connection supporting plain redis:// and TLS rediss://."""
    from redis import Redis
    kwargs = {}
    if redis_url.startswith("rediss://"):
        logger.info("TLS detected (rediss://) — disabling cert verification for Render internal Redis.")
        kwargs["ssl_cert_reqs"] = None
    return Redis.from_url(redis_url, **kwargs)


def _wait_for_redis(redis_url: str, retries: int = 10, delay: int = 3):
    """Attempt to connect to Redis with retries. Dies after all retries exhausted."""
    safe_url = _redact_url(redis_url)
    for attempt in range(1, retries + 1):
        try:
            conn = _build_redis_conn(redis_url)
            conn.ping()
            logger.info(f"[attempt {attempt}/{retries}] Redis connected at {safe_url}")
            return conn
        except Exception as exc:
            logger.warning(
                f"[attempt {attempt}/{retries}] Redis not ready at {safe_url}: {exc}"
            )
            if attempt < retries:
                logger.info(f"Retrying in {delay}s...")
                time.sleep(delay)
    logger.error(f"CRITICAL: Could not connect to Redis after {retries} attempts. Exiting.")
    sys.exit(1)


if __name__ == "__main__":
    from redis import Redis
    from rq import Worker, Queue, Connection
    import sentry_sdk
    from prometheus_client import start_http_server

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    sentry_dsn = os.getenv("SENTRY_DSN", "")
    metrics_port = int(os.getenv("WORKER_METRICS_PORT", "9100"))

    logger.info("=" * 60)
    logger.info("Security Compliance Platform Worker — Starting Up")
    logger.info("=" * 60)
    logger.info(f"Target Redis  : {_redact_url(redis_url)}")
    logger.info(f"DATABASE_URL  : {'SET' if os.getenv('DATABASE_URL') else 'NOT SET (will use default)'}")
    logger.info(f"PYTHONPATH    : {os.getenv('PYTHONPATH', '(not set)')}")
    logger.info(f"WORKER_SYNC   : {os.getenv('WORKER_SYNC', 'false')}")

    # Validate critical env
    if not os.getenv("REDIS_URL"):
        logger.error("REDIS_URL is not set! Worker cannot proceed without a Redis URL.")
        sys.exit(1)

    # init Sentry for the worker process
    if sentry_dsn:
        logger.info("Initializing Sentry...")
        sentry_sdk.init(dsn=sentry_dsn, traces_sample_rate=0.1)

    # Start prometheus metrics HTTP server for the worker
    try:
        logger.info(f"Starting metrics server on port {metrics_port}...")
        start_http_server(metrics_port)
    except Exception as e:
        logger.warning(f"Could not start metrics server: {e}")

    # Wait for Redis to be ready (handles cold-start race on Render)
    conn = _wait_for_redis(redis_url, retries=10, delay=3)

    queues = ["emails", "scans", "resolutions"]
    logger.info(f"Listening on queues: {queues}")
    logger.info("Worker ready. Waiting for jobs...")

    import uuid
    worker_name = f"scp-worker-{os.uname().nodename}-{uuid.uuid4().hex[:6]}"
    logger.info(f"Worker Name: {worker_name}")
    with Connection(conn):
        worker = Worker(queues, name=worker_name)
        worker.work(with_scheduler=False)