"""Simple per-tenant rate limiter + quota enforcement with Redis primary and in-memory fallback.

Policy (scaffold):
- Rate: fixed-window per-minute counter (configurable per-tenant)
- Quota: fixed monthly counter
- In Redis: use INCR + EXPIRE for atomic counters
- Fallback: in-process dict (only for single-process dev/CI)

This is intentionally small and auditable; replace with a distributed token-bucket (or use 3rd-party SaaS) for production.
"""
import os
import time
from typing import Optional
from fastapi import HTTPException

try:
    from redis import Redis
except Exception:
    Redis = None

_anon = {"rate": 5}

# simple in-memory store for tests/dev when Redis is missing
_memory_counters = {}

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


def _now_month_key():
    return time.strftime("%Y-%m")


def _incr_redis(key: str, window_seconds: int):
    conn = Redis.from_url(REDIS_URL) if Redis is not None else None
    if conn is None:
        return None
    val = conn.incr(key)
    if conn.ttl(key) == -1:
        conn.expire(key, window_seconds)
    return val


def _incr_memory(key: str, window_seconds: int):
    now = int(time.time())
    bucket = _memory_counters.get(key)
    if not bucket or bucket[1] < now:
        # reset
        _memory_counters[key] = [1, now + window_seconds]
        return 1
    bucket[0] += 1
    return bucket[0]


def check_rate_limit(tenant_id: str, route: str = "default", rate: int = 10, quota_per_month: Optional[int] = None):
    """Raises HTTPException(429) when rate limit or quota is exceeded.

    - tenant_id: string (use '__anon__' for anonymous)
    - rate: allowed requests per minute
    - quota_per_month: allowed scans per month (optional)
    """
    # rate (per-minute)
    window = 60
    minute_key = f"rl:{tenant_id}:{route}:{int(time.time()//60)}"
    try:
        val = _incr_redis(minute_key, window) if Redis is not None else None
    except Exception:
        val = None
    if val is None:
        val = _incr_memory(minute_key, window)

    if val > rate:
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    # monthly quota check (only for scans route)
    if quota_per_month is not None and route == "scans":
        month = _now_month_key()
        quota_key = f"quota:{tenant_id}:{month}"
        try:
            qv = _incr_redis(quota_key, 60 * 60 * 24 * 31) if Redis is not None else None
        except Exception:
            qv = None
        if qv is None:
            qv = _incr_memory(quota_key, 60 * 60 * 24 * 31)
        if qv > quota_per_month:
            raise HTTPException(status_code=403, detail="monthly quota exceeded")

    return True


def reset_monthly_quota(tenant_id: str):
    """Resets the monthly quota for a tenant by deleting the quota key in Redis or memory."""
    month = _now_month_key()
    quota_key = f"quota:{tenant_id}:{month}"
    
    # Reset in Redis
    try:
        conn = Redis.from_url(REDIS_URL) if Redis is not None else None
        if conn:
            conn.delete(quota_key)
    except Exception:
        pass
        
    # Reset in Memory
    if quota_key in _memory_counters:
        del _memory_counters[quota_key]
    
    return True
