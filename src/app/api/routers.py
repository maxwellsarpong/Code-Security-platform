from fastapi import APIRouter, Depends, HTTPException, Header, Response
from sqlmodel import Session, select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID
from datetime import date
from ..schemas import ScanCreate, ScanRead, ResolutionRequest, ResolutionResponse, FindingRead, UsageRead, TenantUsageResponse
from ..models import Scan, Tenant, APIKey, Usage, Finding
from ..core.db import get_session
from ..services.scanner import enqueue_scan, get_scan_result
from ..services.resolution import ResolutionService
from ..services.billing import renew_subscription
from .deps import get_tenant_from_api_key, get_tenant_no_quota, get_tenant_enforce_scan_quota
import secrets
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from . import auth

def normalize_id(target_id: UUID) -> str:
    """Standardize UUID to non-hyphenated string for SQLite compatibility."""
    return str(target_id).replace("-", "")

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["auth"])


@router.post("/tenants", status_code=201)
def create_tenant(name: str, rate_limit_per_minute: int = 10, quota_per_month: int = 100, session: Session = Depends(get_session)):
    tenant = Tenant(name=name, rate_limit_per_minute=rate_limit_per_minute, quota_per_month=quota_per_month)
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    # create an API key for convenience (scaffold — in prod hash/store securely)
    raw = secrets.token_urlsafe(24)
    apikey = APIKey(tenant_id=tenant.id, key=raw)
    session.add(apikey)
    session.commit()
    return {"tenant_id": str(tenant.id), "api_key": raw}


@router.get("/tenants", response_model=List[Tenant])
def list_tenants(session: Session = Depends(get_session)):
    """List all tenants in the system."""
    tenants = session.exec(select(Tenant)).all()
    return tenants


@router.get('/tenants/{tenant_id}/usage', response_model=TenantUsageResponse)
def get_tenant_usage(tenant_id: UUID, session: Session = Depends(get_session), tenant: Tenant = Depends(get_tenant_from_api_key)):
    # Enforce isolation: can only view own usage
    if not tenant:
        raise HTTPException(status_code=401, detail="Authentication required")
    if tenant.id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")
    
    # Get all usage records for history
    stmt = select(Usage).where(Usage.tenant_id == tenant_id).order_by(Usage.date.desc())
    rows = session.exec(stmt).all()
    
    # Calculate current month's usage
    today = date.today()
    first_of_month = today.replace(day=1)
    
    monthly_stmt = select(Usage).where(Usage.tenant_id == tenant_id, Usage.date >= first_of_month)
    monthly_rows = session.exec(monthly_stmt).all()
    
    month_usage = sum((r.scans_count or 0) + (r.resolutions_count or 0) for r in monthly_rows)
    quota = tenant.quota_per_month or 100 # default fallback
    
    percentage_left = max(0.0, ((quota - month_usage) / quota) * 100)
    
    return {
        "usage": rows,
        "percentage_credit_left": round(percentage_left, 2),
        "quota_limit": quota,
        "current_month_usage": month_usage
    }


@router.post("/scans", response_model=ScanRead, status_code=201)
def create_scan(payload: ScanCreate, tenant: Tenant = Depends(get_tenant_enforce_scan_quota), session: Session = Depends(get_session)):
    if not tenant:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    scan_data = payload.model_dump(mode='json')
    scan_data["tenant_id"] = tenant.id
    scan = Scan.model_validate(scan_data)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    response = ScanRead.model_validate(scan)
    enqueue_scan(scan.id, tenant_id=str(tenant.id))
    return response


@router.get("/scans", response_model=List[ScanRead])
def list_scans(session: Session = Depends(get_session), tenant: Tenant = Depends(get_tenant_from_api_key)):
    """Fetch a list of all scans for the current tenant."""
    if not tenant:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    stmt = select(Scan).where(Scan.tenant_id == tenant.id).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc())
    scans = session.exec(stmt).all()
    return scans


@router.get("/scans/{scan_id}", response_model=ScanRead)
def read_scan(scan_id: UUID, session: Session = Depends(get_session), tenant: Tenant = Depends(get_tenant_from_api_key)):
    if not tenant:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    stmt = select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
    scan = session.exec(stmt).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    
    if scan.tenant_id != tenant.id:
        raise HTTPException(status_code=403, detail="Forbidden")
        
    return ScanRead.model_validate(scan)


@router.post("/findings/{target_id}/resolve", response_model=ResolutionResponse)
def resolve_finding(
    target_id: UUID, 
    payload: Optional[ResolutionRequest] = None,
    force_sync: bool = False,
    session: Session = Depends(get_session),
    tenant: Tenant = Depends(get_tenant_enforce_scan_quota)
):
    """
    Resolve vulnerabilities. Accepts either a Finding ID (to fix one) or a Scan ID (to fix all).
    """
    if not tenant:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    search_id_str = normalize_id(target_id)
    
    # 1. Check Finding
    finding = session.get(Finding, target_id)
    if not finding:
        # Fallback for string comparison in SQLite
        findings = session.exec(select(Finding).where(Finding.tenant_id == tenant.id)).all()
        finding = next((f for f in findings if normalize_id(f.id) == search_id_str), None)

    if finding:
        if finding.tenant_id != tenant.id:
            raise HTTPException(status_code=403, detail="Forbidden")
        
    else:
        # 2. Check Scan
        scan = session.get(Scan, target_id)
        if not scan:
             scans = session.exec(select(Scan).where(Scan.tenant_id == tenant.id)).all()
             scan = next((s for s in scans if normalize_id(s.id) == search_id_str), None)

        if scan:
            if scan.tenant_id != tenant.id:
                raise HTTPException(status_code=403, detail="Forbidden")
        else:
            raise HTTPException(
                status_code=404, 
                detail=f"Resource not found. ID {target_id} (normalized: {search_id_str}) does not match any Finding or Scan associated with your tenant."
            )

    github_token = payload.github_token if payload else None
    if not github_token:
        github_token = tenant.github_token
        
    service = ResolutionService(session)
    response = service.resolve_finding(target_id, github_token=github_token, force_sync=force_sync)
    
    if response.status == "failed":
        if "not found" in response.message:
            raise HTTPException(status_code=404, detail=response.message)
        if "severity" in response.message:
            raise HTTPException(status_code=400, detail=response.message)
        raise HTTPException(status_code=500, detail=response.message)
    
    return response


@router.get("/findings/fixed", response_model=List[FindingRead])
def list_fixed_findings(session: Session = Depends(get_session), tenant: Tenant = Depends(get_tenant_from_api_key)):
    """Fetch all vulnerabilities that have been successfully resolved with a PR."""
    if not tenant:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    stmt = select(Finding).where(Finding.is_fixed == True, Finding.tenant_id == tenant.id)
    findings = session.exec(stmt).all()
    return findings


@router.post("/tenants/subscription/renew")
def renew_monthly_quota_subscription(
    amount: float = 100.0,
    session: Session = Depends(get_session),
    tenant: Tenant = Depends(get_tenant_no_quota)
):
    """
    Manually renew the monthly quota subscription for the current tenant.
    """
    if not tenant:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    renew_subscription(tenant.id, amount, session)
    session.commit()
    
    return {"status": "success", "message": f"Monthly quota renewed for tenant {tenant.name}"}


@router.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
