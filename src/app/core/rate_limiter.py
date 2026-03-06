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


def check_rate_limit(
    user_id: str,
    route: str = "default",
    rate: int = 10,
    quota_per_month: Optional[int] = None,
    resolve_quota_per_month: Optional[int] = None,
    peek_quota_only: bool = False,
):
    """Raises HTTPException(429) when rate limit or quota is exceeded.

    - user_id: string (use '__anon__' for anonymous)
    - rate: allowed requests per minute
    - quota_per_month: allowed scans per month (enforced on route='scans')
    - resolve_quota_per_month: allowed resolves per month (enforced on route='resolve')
    - peek_quota_only: if True, monthly quotas are checked but not incremented.
    """
    # rate (per-minute)
    window = 60
    minute_key = f"rl:{user_id}:{route}:{int(time.time()//60)}"
    try:
        val = _incr_redis(minute_key, window) if Redis is not None else None
    except Exception:
        val = None
    if val is None:
        val = _incr_memory(minute_key, window)

    if val > rate:
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    # monthly scan quota check
    if quota_per_month is not None and route == "scans":
        month = _now_month_key()
        quota_key = f"quota:scan:{user_id}:{month}"
        try:
            if peek_quota_only:
                conn = Redis.from_url(REDIS_URL, decode_responses=True) if Redis is not None else None
                qv_raw = conn.get(quota_key) if conn else None
                qv = int(qv_raw) if qv_raw else 0
            else:
                qv = _incr_redis(quota_key, 60 * 60 * 24 * 31) if Redis is not None else None
        except Exception:
            qv = None
        
        if qv is None:
            if peek_quota_only:
                bucket = _memory_counters.get(quota_key)
                qv = bucket[0] if bucket else 0
            else:
                qv = _incr_memory(quota_key, 60 * 60 * 24 * 31)

        if qv > quota_per_month:
            raise HTTPException(status_code=403, detail="monthly scan quota exceeded — upgrade your plan to continue scanning")

    # monthly resolve quota check
    if resolve_quota_per_month is not None and route == "resolve":
        month = _now_month_key()
        quota_key = f"quota:resolve:{user_id}:{month}"
        try:
            if peek_quota_only:
                conn = Redis.from_url(REDIS_URL, decode_responses=True) if Redis is not None else None
                qv_raw = conn.get(quota_key) if conn else None
                qv = int(qv_raw) if qv_raw else 0
            else:
                qv = _incr_redis(quota_key, 60 * 60 * 24 * 31) if Redis is not None else None
        except Exception:
            qv = None

        if qv is None:
            if peek_quota_only:
                bucket = _memory_counters.get(quota_key)
                qv = bucket[0] if bucket else 0
            else:
                qv = _incr_memory(quota_key, 60 * 60 * 24 * 31)

        if qv > resolve_quota_per_month:
            raise HTTPException(status_code=403, detail="monthly resolve quota exceeded — upgrade your plan to continue resolving findings")

    return True


def reset_monthly_quota(user_id: str, quota_type: str = "scan"):
    """Resets the monthly scan or resolve quota for a user.

    quota_type: 'scan' (default) or 'resolve'
    """
    month = _now_month_key()
    quota_key = f"quota:{quota_type}:{user_id}:{month}"

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


def increment_quota_usage(user_id: str, quota_type: str = "scan"):
    """Manually increments the monthly scan or resolve quota for a user.
    
    Used when an operation is confirmed successful (e.g. Scan created).
    """
    month = _now_month_key()
    quota_key = f"quota:{quota_type}:{user_id}:{month}"
    window = 60 * 60 * 24 * 31

    try:
        _incr_redis(quota_key, window)
    except Exception:
        _incr_memory(quota_key, window)

    return True
def get_usage_count(user_id: str, quota_type: str = "scan") -> int:
    """Returns the current monthly usage count for a user without incrementing it."""
    month = _now_month_key()
    quota_key = f"quota:{quota_type}:{user_id}:{month}"
    
    try:
        conn = Redis.from_url(REDIS_URL, decode_responses=True) if Redis is not None else None
        if conn:
            val = conn.get(quota_key)
            return int(val) if val else 0
    except Exception:
        pass
        
    bucket = _memory_counters.get(quota_key)
    if bucket:
        now = int(time.time())
        if bucket[1] >= now:
            return bucket[0]
            
    return 0
