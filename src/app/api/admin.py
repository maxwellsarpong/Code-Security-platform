from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select, func
from typing import List
from uuid import UUID

from ..schemas import UserProfileRead, AdminUserUpdate, ScanRead, FindingRead, AdminHealthStats, EventRead
from ..models import User, Scan, Finding, BillingEvent
from ..core.db import get_session
from .deps import get_current_superuser

router = APIRouter()


@router.get("/users", response_model=List[UserProfileRead])
def list_users(
    session: Session = Depends(get_session),
    superuser: User = Depends(get_current_superuser)
):
    """
    List all users on the platform. Accessible only to superusers.
    """
    stmt = select(User).order_by(User.created_at.desc())
    users = session.exec(stmt).all()
    return users


@router.put("/users/{user_id}", response_model=UserProfileRead)
def update_user(
    user_id: str, # SQLite uses hyphenless UUID strings frequently, but we'll try to find it
    payload: AdminUserUpdate,
    session: Session = Depends(get_session),
    superuser: User = Depends(get_current_superuser)
):
    """
    Update a user's plan, quota, or superuser status. Accessible only to superusers.
    """
    # SQLite ID handling where hyphens are stripped out
    normalized_id = user_id.replace("-", "") if isinstance(user_id, str) else str(user_id).replace("-", "")
    
    # Brute force search to match normalized ID due to SQLite nuances in this project
    users = session.exec(select(User)).all()
    target_user = next((u for u in users if str(u.id).replace("-", "") == normalized_id), None)
    
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if payload.plan is not None:
        target_user.plan = payload.plan
    if payload.is_superuser is not None:
        target_user.is_superuser = payload.is_superuser
    if payload.scan_quota_per_month is not None:
        target_user.scan_quota_per_month = payload.scan_quota_per_month
    if payload.resolve_quota_per_month is not None:
        target_user.resolve_quota_per_month = payload.resolve_quota_per_month
        
    session.add(target_user)
    session.commit()
    session.refresh(target_user)
    

    return target_user


@router.get("/scans", response_model=List[ScanRead])
def list_all_scans(
    session: Session = Depends(get_session),
    superuser: User = Depends(get_current_superuser)
):
    """
    List all security scans on the platform. Accessible only to superusers.
    """
    stmt = select(Scan).order_by(Scan.created_at.desc())
    scans = session.exec(stmt).all()
    return scans


@router.get("/findings/fixed", response_model=List[FindingRead])
def list_all_fixed_findings(
    session: Session = Depends(get_session),
    superuser: User = Depends(get_current_superuser)
):
    """
    List all fixed vulnerabilities across the platform. Accessible only to superusers.
    """
    stmt = select(Finding).where(Finding.is_fixed == True).order_by(Finding.id.desc())
    findings = session.exec(stmt).all()
    return findings


@router.get("/health/stats", response_model=AdminHealthStats)
def get_system_health_stats(
    session: Session = Depends(get_session),
    superuser: User = Depends(get_current_superuser)
):
    """
    Calculate and return the overall system health percentage.
    Accessible only to superusers.
    """
    # 1. Aggregates for findings
    total_findings = session.exec(select(func.count(Finding.id))).one()
    total_fixed = session.exec(select(func.count(Finding.id)).where(Finding.is_fixed == True)).one()
    
    # 2. Aggregates for scans
    total_scans = session.exec(select(func.count(Scan.id))).one()
    avg_risk = session.exec(select(func.avg(Scan.risk_score))).one() or 0.0
    
    # 3. Calculations
    res_rate = (total_fixed / total_findings * 100) if total_findings > 0 else 100.0
    posture_score = 100.0 - (float(avg_risk) * 10.0)
    
    health_pct = (res_rate + posture_score) / 2.0
    
    return {
        "system_health_percentage": round(health_pct, 2),
        "total_scans": total_scans,
        "total_findings": total_findings,
        "total_fixed_findings": total_fixed,
        "average_risk_score": round(float(avg_risk), 2)
    }


@router.get("/events", response_model=List[EventRead])
def list_platform_events(
    offset: int = 0,
    limit: int = 3,
    session: Session = Depends(get_session),
    superuser: User = Depends(get_current_superuser)
):
    """
    List all platform events globally with pagination. 
    Accessible only to superusers.
    """
    stmt = select(BillingEvent).order_by(BillingEvent.created_at.desc()).offset(offset).limit(limit)
    events = session.exec(stmt).all()
    return events
