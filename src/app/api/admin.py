from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from typing import List
from uuid import UUID

from ..schemas import UserProfileRead, AdminUserUpdate
from ..models import User
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
