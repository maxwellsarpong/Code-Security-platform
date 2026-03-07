"""Convenience entrypoint to run an RQ worker locally or in production.

Usage (from project root):
    REDIS_URL=redis://localhost:6379 python -m app.worker
"""

if __name__ == "__main__":
    # import lazily so running `python -m app.worker` without deps fails clearly
    from redis import Redis
    from rq import Worker, Queue, Connection
    import os
    import sys
    import logging
    import sentry_sdk
    from prometheus_client import start_http_server

    # Setup basic logging to stdout so it appears in Render logs
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout
    )
    logger = logging.getLogger("app.worker")

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    sentry_dsn = os.getenv("SENTRY_DSN", "")
    metrics_port = int(os.getenv("WORKER_METRICS_PORT", "9100"))

    logger.info("Starting Security Compliance Platform Worker...")
    
    # Redact password for logging
    redacted_url = redis_url
    if "@" in redis_url:
        prefix = redis_url.split("@")[0]
        suffix = redis_url.split("@")[1]
        if ":" in prefix:
            scheme_user = prefix.split(":")[0] + "://" + prefix.split(":")[1].split("//")[1]
            redacted_url = f"{scheme_user}:****@{suffix}"
    
    logger.info(f"Target Redis: {redacted_url}")

    # init Sentry for the worker process
    if sentry_dsn:
        logger.info("Initializing Sentry...")
        sentry_sdk.init(dsn=sentry_dsn, traces_sample_rate=0.1)

    # start prometheus metrics HTTP server for the worker
    try:
        logger.info(f"Starting metrics server on port {metrics_port}...")
        start_http_server(metrics_port)
    except Exception as e:
        logger.warning(f"Could not start metrics server: {e}")

    # TLS-safe connection helper
    def get_conn():
        kwargs = {}
        # Render managed Redis usually uses rediss:// for TLS
        if redis_url.startswith("rediss://"):
            logger.info("Using TLS connection (rediss:// detected)")
            kwargs["ssl_cert_reqs"] = None
        return Redis.from_url(redis_url, **kwargs)

    try:
        conn = get_conn()
        logger.info("Pinging Redis...")
        if conn.ping():
            logger.info("Redis connectivity confirmed.")
        else:
            logger.error("Redis ping failed (returned False).")
    except Exception as e:
        logger.error(f"CRITICAL: Failed to connect to Redis: {e}")
        sys.exit(1)

    queues = ["scans", "resolutions"]
    logger.info(f"Listening on queues: {queues}")
    
    with Connection(conn):
        worker = Worker(queues, name=f"scp-worker-{os.uname().nodename}")
        logger.info(f"Worker {worker.name} started and waiting for jobs...")
        worker.work()