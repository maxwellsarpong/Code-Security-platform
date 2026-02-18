"""Convenience entrypoint to run an RQ worker locally (developer-friendly).

Usage (from project root):
    REDIS_URL=redis://localhost:6379 python -m app.worker

In Docker Compose the service already runs `rq worker` directly.
"""

if __name__ == "__main__":
    # import lazily so running `python -m app.worker` without deps fails clearly
    from redis import Redis
    from rq import Worker, Queue, Connection
    import os
    import sentry_sdk
    from prometheus_client import start_http_server

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    sentry_dsn = os.getenv("SENTRY_DSN", "")
    metrics_port = int(os.getenv("WORKER_METRICS_PORT", "9100"))

    # init Sentry for the worker process
    if sentry_dsn:
        sentry_sdk.init(dsn=sentry_dsn, traces_sample_rate=0.1)

    # start prometheus metrics HTTP server for the worker
    start_http_server(metrics_port)

    conn = Redis.from_url(redis_url)
    q = Queue("scans", connection=conn)
    with Connection(conn):
        worker = Worker([q], name="scp-worker")
        worker.work()