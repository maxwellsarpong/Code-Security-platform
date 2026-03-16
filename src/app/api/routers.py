from fastapi import APIRouter, Depends, HTTPException, Header, Response, File, UploadFile
from sqlmodel import Session, select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID, uuid4
from datetime import date
from ..schemas import ScanCreate, ScanRead, ResolutionRequest, ResolutionResponse, FindingRead, UsageRead, UserUsageResponse, UserProfileRead, UserProfileUpdate, APIKeyRead
from ..models import Scan, User, APIKey, Usage, Finding
from ..core.db import get_session
from ..core.billing_plans import get_plan
from ..services.scanner import enqueue_scan, get_scan_result
from ..services.resolution import ResolutionService
from ..services.billing import renew_subscription, subscribe_user_to_plan
from .deps import get_user_from_api_key, get_user_no_quota, get_user_enforce_scan_quota, get_user_enforce_resolve_quota
from ..core.rate_limiter import get_usage_count, increment_quota_usage
from ..core.auth import generate_api_key
import secrets
import shutil
import os
from pathlib import Path
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from . import auth, admin

def normalize_id(target_id: UUID) -> str:
    """Standardize UUID to non-hyphenated string for SQLite compatibility."""
    return str(target_id).replace("-", "")

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(admin.router, prefix="/admin", tags=["admin"])


@router.post("/user/api-key", response_model=APIKeyRead, status_code=201)
def create_api_key(session: Session = Depends(get_session), user: User = Depends(get_user_no_quota)):
    """Generate a new API key for the authenticated user."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    raw = generate_api_key()
    apikey = APIKey(user_id=user.id, key=raw)
    session.add(apikey)
    session.commit()
    session.refresh(apikey)
    return apikey

@router.get("/user/api-keys", response_model=List[APIKeyRead])
def list_api_keys(session: Session = Depends(get_session), user: User = Depends(get_user_no_quota)):
    """List all API keys associated with the authenticated user."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    statement = select(APIKey).where(APIKey.user_id == user.id, APIKey.revoked == False)
    results = session.exec(statement).all()
    return results

@router.get("/user/profile", response_model=UserProfileRead)
def get_user_profile(user: User = Depends(get_user_from_api_key)):
    """Get the authenticated user's profile and quota information."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.put("/user/profile", response_model=UserProfileRead)
def update_user_profile(
    payload: UserProfileUpdate,
    session: Session = Depends(get_session),
    user: User = Depends(get_user_from_api_key)
):
    """
    Update the authenticated user's integration settings (Slack, Jira, Git tokens).
    Protected fields like 'plan', 'is_superuser' and 'quotas' are strictly inaccessible here.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)
        
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.get('/user/usage', response_model=UserUsageResponse)
def get_user_usage(session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Get all usage records for history
    stmt = select(Usage).where(Usage.user_id == user.id).order_by(Usage.date.desc())
    rows = session.exec(stmt).all()
    
    # Fetch real-time usage from rate limiter (Redis/Memory)
    real_scans = get_usage_count(str(user.id), "scan")
    real_resolves = get_usage_count(str(user.id), "resolve")
    real_total = real_scans + real_resolves

    plan_config = get_plan(user.plan)
    scan_quota = user.scan_quota_per_month if user.scan_quota_per_month is not None else plan_config["scan_quota"]
    resolve_quota = user.resolve_quota_per_month if user.resolve_quota_per_month is not None else plan_config["resolve_quota"]
    combined_quota = scan_quota + resolve_quota

    percentage_left = max(0.0, ((combined_quota - real_total) / combined_quota) * 100) if combined_quota > 0 else 0.0

    return {
        "usage": rows,
        "percentage_credit_left": round(percentage_left, 2),
        "scan_quota_limit": scan_quota,
        "resolve_quota_limit": resolve_quota,
        "current_month_usage": real_total,
        "scans_used": real_scans,
        "resolutions_used": real_resolves
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

    # Increment monthly scan quota ONLY after successful 201 creation
    increment_quota_usage(str(user.id), "scan")

    response = ScanRead.model_validate(scan)

    try:
        enqueue_scan(scan.id, user_id=str(user.id))
    except Exception as exc:
        # Mark the scan as failed so it doesn't sit as QUEUED forever
        scan.status = "failed"
        session.add(scan)
        session.commit()
        raise HTTPException(
            status_code=503,
            detail=(
                f"Scan created but could not be dispatched to the worker queue: {exc}. "
                "Check that REDIS_URL is set correctly in your Render environment variables."
            )
        )

    return response


@router.post("/scans/local", response_model=ScanRead, status_code=201)
async def create_local_scan(
    file: UploadFile = File(...),
    user: User = Depends(get_user_enforce_scan_quota),
    session: Session = Depends(get_session)
):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    # Read binary content for shared database storage (compatible with multi-service deployments)
    try:
        zip_binary = await file.read()
        if not zip_binary:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read uploaded file: {e}")

    # Create scan record with binary data
    scan = Scan(
        user_id=user.id,
        is_local=True,
        zip_data=zip_binary,
        status="queued"
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # Increment monthly scan quota
    increment_quota_usage(str(user.id), "scan")

    try:
        enqueue_scan(scan.id, user_id=str(user.id))
    except Exception as exc:
        scan.status = "failed"
        session.add(scan)
        session.commit()
        raise HTTPException(status_code=503, detail=f"Scan created but could not be dispatched: {exc}")

    return scan


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


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: UUID, session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    """Remove a scan item that is currently in 'queued' state."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if scan.user_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
        
    if scan.status != "queued":
        raise HTTPException(status_code=400, detail="Only queued scans can be removed")
        
    session.delete(scan)
    session.commit()
    return {"status": "success", "message": f"Scan {scan_id} removed from queue"}


@router.post("/findings/{target_id}/resolve", response_model=ResolutionResponse)
def resolve_finding(
    target_id: UUID,
    payload: Optional[ResolutionRequest] = None,
    force_sync: bool = False,
    session: Session = Depends(get_session),
    user: User = Depends(get_user_enforce_resolve_quota)
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
    
    # Increment monthly resolution quota ONLY after successful resolution
    increment_quota_usage(str(user.id), "resolve")
    
    return response


@router.get("/findings/fixed", response_model=List[FindingRead])
def list_fixed_findings(session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    """Fetch all vulnerabilities that have been successfully resolved with a PR."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    stmt = select(Finding).where(Finding.is_fixed == True, Finding.user_id == user.id)
    findings = session.exec(stmt).all()
    return findings


@router.get("/findings/{finding_id}", response_model=FindingRead)
def read_finding(finding_id: UUID, session: Session = Depends(get_session), user: User = Depends(get_user_from_api_key)):
    """Fetch details of a specific finding by its ID."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    finding = session.get(Finding, finding_id)
    if not finding:
        # Fallback for string comparison in SQLite
        search_id_str = normalize_id(finding_id)
        findings = session.exec(select(Finding).where(Finding.user_id == user.id)).all()
        finding = next((f for f in findings if normalize_id(f.id) == search_id_str), None)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if finding.user_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
        
    return finding


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


@router.post("/user/subscription/team")
def subscribe_team_plan(
    session: Session = Depends(get_session),
    user: User = Depends(get_user_no_quota)
):
    """
    Subscribe the current user to the TEAM plan.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    subscribe_user_to_plan(user.id, "team", session)
    session.commit()

    return {"status": "success", "message": f"User {user.email} successfully subscribed to TEAM plan."}


@router.post("/user/subscription/enterprise")
def subscribe_enterprise_plan(
    session: Session = Depends(get_session),
    user: User = Depends(get_user_no_quota)
):
    """
    Subscribe the current user to the ENTERPRISE plan.
    """
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    subscribe_user_to_plan(user.id, "enterprise", session)
    session.commit()

    return {"status": "success", "message": f"User {user.email} successfully subscribed to ENTERPRISE plan."}


@router.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
