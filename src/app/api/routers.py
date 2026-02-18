from fastapi import APIRouter, Depends, HTTPException, Header
from sqlmodel import Session, select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID
from ..schemas import ScanCreate, ScanRead, ResolutionRequest, ResolutionResponse, FindingRead
from ..models import Scan, Tenant, APIKey, Usage, Finding
from ..core.db import get_session
from ..services.scanner import enqueue_scan, get_scan_result
from ..services.resolution import ResolutionService
from .deps import get_tenant_from_api_key
import secrets

router = APIRouter()


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


@router.get('/tenants/{tenant_id}/usage')
def get_tenant_usage(tenant_id: UUID, session: Session = Depends(get_session)):
    stmt = select(Usage).where(Usage.tenant_id == tenant_id)
    rows = session.exec(stmt).all()
    return rows


@router.post("/scans", response_model=ScanRead, status_code=201)
def create_scan(payload: ScanCreate, tenant = Depends(get_tenant_from_api_key), session: Session = Depends(get_session)):
    scan = Scan.model_validate(payload.model_dump(mode='json'))
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # Validate response model before enqueueing task to avoid DetachedInstanceError 
    # if the worker runs synchronously and affects the session/object state.
    response = ScanRead.model_validate(scan)

    tenant_id = str(tenant.id) if tenant is not None else None
    # enqueue scan (uses RQ when REDIS_URL is present; falls back to synchronous run for dev/test)
    enqueue_scan(scan.id, tenant_id=tenant_id)

    return response


@router.get("/scans", response_model=List[ScanRead])
def list_scans(session: Session = Depends(get_session)):
    """Fetch a list of all scans."""
    stmt = select(Scan).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc())
    scans = session.exec(stmt).all()
    return scans


@router.get("/scans/{scan_id}", response_model=ScanRead)
def read_scan(scan_id: UUID, session: Session = Depends(get_session)):
    stmt = select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
    scan = session.exec(stmt).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return ScanRead.model_validate(scan)


@router.post("/findings/{finding_id}/resolve", response_model=ResolutionResponse)
def resolve_finding(
    finding_id: UUID, 
    payload: Optional[ResolutionRequest] = None,
    session: Session = Depends(get_session),
    tenant = Depends(get_tenant_from_api_key)
):
    """
    Resolve a specific finding using AI and create a pull request.
    """
    github_token = payload.github_token if payload else None
    service = ResolutionService(session)
    response = service.resolve_finding(finding_id, github_token=github_token)
    
    if response.status == "failed":
        if "not found" in response.message:
            raise HTTPException(status_code=404, detail=response.message)
        raise HTTPException(status_code=500, detail=response.message)
    
    return response


@router.get("/findings/fixed", response_model=List[FindingRead])
def list_fixed_findings(session: Session = Depends(get_session)):
    """Fetch all vulnerabilities that have been successfully resolved with a PR."""
    stmt = select(Finding).where(Finding.is_fixed == True)
    findings = session.exec(stmt).all()
    return findings
