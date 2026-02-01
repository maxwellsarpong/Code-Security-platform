from fastapi import Header, HTTPException, Depends
from sqlmodel import Session, select
from typing import Optional
from ..models import APIKey, Tenant
from ..core.db import get_session
from ..core.rate_limiter import check_rate_limit


def get_tenant_from_api_key(x_api_key: Optional[str] = Header(None), session: Session = Depends(get_session)) -> Optional[Tenant]:
    """Resolve API key to Tenant and enforce rate limits/quotas.

    - If `x-api-key` is provided, look up the tenant and enforce limits.
    - If missing, return None (anonymous) but still apply a low global limit via check_rate_limit.
    """
    if not x_api_key:
        # anonymous requests counted under special 'anonymous' tenant id
        check_rate_limit(tenant_id="__anon__", route="global")
        return None

    statement = select(APIKey).where(APIKey.key == x_api_key, APIKey.revoked == False)
    row = session.exec(statement).one_or_none()
    if not row:
        raise HTTPException(status_code=401, detail="invalid api key")
    api_key = row
    tenant = session.get(Tenant, api_key.tenant_id)
    if not tenant:
        raise HTTPException(status_code=401, detail="tenant not found")

    # enforce per-tenant rate limit and quota (raises HTTPException 429 when exceeded)
    check_rate_limit(tenant_id=str(tenant.id), route="scans", rate=tenant.rate_limit_per_minute, quota_per_month=tenant.quota_per_month)
    return tenant
