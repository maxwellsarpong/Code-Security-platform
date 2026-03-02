from sqlmodel import Session, select
from ..core.config import Settings
from ..models import Usage, BillingEvent
import os
from datetime import date
from uuid import UUID


def record_usage(user_id: str, scans: int = 0, resolutions: int = 0, billable_units: int = 0, session: Session | None = None):
    """Record usage for user — increments daily Usage and creates a BillingEvent.

    If a session is provided the function will use it; otherwise it will open its own.
    """
    today = date.today()
    own_session = False
    
    # Ensure user_id is UUID
    if isinstance(user_id, str):
        user_id = UUID(user_id)
        
    if session is None:
        from ..core.db import engine
        session = Session(engine)
        own_session = True

    try:
        stmt = select(Usage).where(Usage.user_id == user_id, Usage.date == today)
        row = session.exec(stmt).one_or_none()
        if not row:
            row = Usage(
                user_id=user_id, 
                date=today, 
                scans_count=scans, 
                resolutions_count=resolutions,
                billable_units=billable_units
            )
            session.add(row)
        else:
            row.scans_count = (row.scans_count or 0) + scans
            row.resolutions_count = (row.resolutions_count or 0) + resolutions
            row.billable_units = (row.billable_units or 0) + billable_units
            session.add(row)

        # create billing event
        event_type = "scan_completed" if scans > 0 else "resolution_completed"
        evt = BillingEvent(
            user_id=user_id, 
            event_type=event_type, 
            amount=0.0, 
            meta={"scans": scans, "resolutions": resolutions, "units": billable_units}
        )
        session.add(evt)
        if own_session:
            session.commit()
        return True
    finally:
        if own_session:
            session.close()


def renew_subscription(user_id: UUID, amount: float, session: Session):
    """Renews a user's subscription by resetting both monthly quotas and recording a billing event."""
    from ..core.rate_limiter import reset_monthly_quota

    # 1. Reset both quota counters
    reset_monthly_quota(str(user_id), quota_type="scan")
    reset_monthly_quota(str(user_id), quota_type="resolve")

    # 2. Record the renewal event
    evt = BillingEvent(
        user_id=user_id,
        event_type="subscription_renewed",
        amount=amount,
        meta={"action": "monthly_manual_renewal"}
    )
    session.add(evt)
    # We assume the caller will commit the session
    return True


def subscribe_user_to_plan(user_id: UUID, plan_name: str, session: Session):
    """Updates a user's plan and resets their monthly quotas."""
    from ..models import User
    from ..core.rate_limiter import reset_monthly_quota

    user = session.get(User, user_id)
    if not user:
        return False

    # 1. Update User Plan and clear custom quotas to force plan-based fallback
    user.plan = plan_name
    user.scan_quota_per_month = None
    user.resolve_quota_per_month = None
    session.add(user)

    # 2. Reset Redis quota counters
    reset_monthly_quota(str(user_id), quota_type="scan")
    reset_monthly_quota(str(user_id), quota_type="resolve")

    # 3. Record billing event
    evt = BillingEvent(
        user_id=user_id,
        event_type="subscription_upgraded",
        amount=0.0, # Placeholder for payment logic
        meta={"new_plan": plan_name, "action": "tier_subscription"}
    )
    session.add(evt)
    return True

