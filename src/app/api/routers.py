from fastapi import APIRouter, Depends, HTTPException, Header, Response
from sqlmodel import Session, select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID
from datetime import date
from ..schemas import ScanCreate, ScanRead, ResolutionRequest, ResolutionResponse, FindingRead, UsageRead, UserUsageResponse, UserProfileRead
from ..models import Scan, User, APIKey, Usage, Finding
from ..core.db import get_session
from ..services.scanner import enqueue_scan, get_scan_result
from ..services.resolution import ResolutionService
from ..services.billing import renew_subscription
from .deps import get_user_from_api_key, get_user_no_quota, get_user_enforce_scan_quota
import secrets
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from . import auth

def normalize_id(target_id: UUID) -> str:
    """Standardize UUID to non-hyphenated string for SQLite compatibility."""
    return str(target_id).replace("-", "")

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["auth"])


@router.post("/user/api-key", status_code=201)
def create_api_key(session: Session = Depends(get_session), user: User = Depends(get_user_no_quota)):
    """Generate a new API key for the authenticated user."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    raw = secrets.token_urlsafe(24)
    apikey = APIKey(user_id=user.id, key=raw)
    session.add(apikey)
    session.commit()
    return {"api_key": raw}

@router.get("/user/profile", response_model=UserProfileRead)
def get_user_profile(user: User = Depends(get_user_from_api_key)):
    """Get the authenticated user's profile and quota information."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.get('/user/usage', response_model=UserUsageResponse)
def get_user_usage(session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Get all usage records for history
    stmt = select(Usage).where(Usage.user_id == user.id).order_by(Usage.date.desc())
    rows = session.exec(stmt).all()
    
    # Calculate current month's usage
    today = date.today()
    first_of_month = today.replace(day=1)
    
    monthly_stmt = select(Usage).where(Usage.user_id == user.id, Usage.date >= first_of_month)
    monthly_rows = session.exec(monthly_stmt).all()
    
    month_usage = sum((r.scans_count or 0) + (r.resolutions_count or 0) for r in monthly_rows)
    quota = user.quota_per_month or 100 # default fallback
    
    percentage_left = max(0.0, ((quota - month_usage) / quota) * 100)
    
    return {
        "usage": rows,
        "percentage_credit_left": round(percentage_left, 2),
        "quota_limit": quota,
        "current_month_usage": month_usage
    }


@router.post("/scans", response_model=ScanRead, status_code=201)
def create_scan(payload: ScanCreate, user: User = Depends(get_user_enforce_scan_quota), session: Session = Depends(get_session)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    scan_data = payload.model_dump(mode='json')
    scan_data["user_id"] = user.id
    scan = Scan.model_validate(scan_data)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    response = ScanRead.model_validate(scan)
    enqueue_scan(scan.id, user_id=str(user.id))
    return response


@router.get("/scans", response_model=List[ScanRead])
def list_scans(session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    """Fetch a list of all scans for the current user."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    stmt = select(Scan).where(Scan.user_id == user.id).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc())
    scans = session.exec(stmt).all()
    return scans


@router.get("/scans/{scan_id}", response_model=ScanRead)
def read_scan(scan_id: UUID, session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    stmt = select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
    scan = session.exec(stmt).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    
    if scan.user_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
        
    return ScanRead.model_validate(scan)


@router.post("/findings/{target_id}/resolve", response_model=ResolutionResponse)
def resolve_finding(
    target_id: UUID, 
    payload: Optional[ResolutionRequest] = None,
    force_sync: bool = False,
    session: Session = Depends(get_session),
    user: User = Depends(get_user_enforce_scan_quota)
):
    """
    Resolve vulnerabilities. Accepts either a Finding ID (to fix one) or a Scan ID (to fix all).
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    search_id_str = normalize_id(target_id)
    
    # 1. Check Finding
    finding = session.get(Finding, target_id)
    if not finding:
        # Fallback for string comparison in SQLite
        findings = session.exec(select(Finding).where(Finding.user_id == user.id)).all()
        finding = next((f for f in findings if normalize_id(f.id) == search_id_str), None)

    if finding:
        if finding.user_id != user.id:
            raise HTTPException(status_code=403, detail="Forbidden")
        
    else:
        # 2. Check Scan
        scan = session.get(Scan, target_id)
        if not scan:
             scans = session.exec(select(Scan).where(Scan.user_id == user.id)).all()
             scan = next((s for s in scans if normalize_id(s.id) == search_id_str), None)

        if scan:
            if scan.user_id != user.id:
                raise HTTPException(status_code=403, detail="Forbidden")
        else:
            raise HTTPException(
                status_code=404, 
                detail=f"Resource not found. ID {target_id} (normalized: {search_id_str}) does not match any Finding or Scan associated with your user."
            )

    github_token = payload.github_token if payload else None
    if not github_token:
        github_token = user.github_token
        
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
def list_fixed_findings(session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    """Fetch all vulnerabilities that have been successfully resolved with a PR."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    stmt = select(Finding).where(Finding.is_fixed == True, Finding.user_id == user.id)
    findings = session.exec(stmt).all()
    return findings


@router.post("/user/subscription/renew")
def renew_monthly_quota_subscription(
    amount: float = 100.0,
    session: Session = Depends(get_session),
    user: User = Depends(get_user_no_quota)
):
    """
    Manually renew the monthly quota subscription for the current user.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    renew_subscription(user.id, amount, session)
    session.commit()
    
    return {"status": "success", "message": f"Monthly quota renewed for user {user.email}"}


@router.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
