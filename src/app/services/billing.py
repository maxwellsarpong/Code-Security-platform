from sqlmodel import Session, select
from ..core.config import Settings
from ..models import Usage, BillingEvent
import os
from datetime import date
from uuid import UUID


def record_usage(tenant_id: str, scans: int = 0, resolutions: int = 0, billable_units: int = 0, session: Session | None = None):
    """Record usage for tenant — increments daily Usage and creates a BillingEvent.

    If a session is provided the function will use it; otherwise it will open its own.
    """
    today = date.today()
    own_session = False
    
    # Ensure tenant_id is UUID
    if isinstance(tenant_id, str):
        tenant_id = UUID(tenant_id)
        
    if session is None:
        from ..core.db import engine
        session = Session(engine)
        own_session = True

    try:
        stmt = select(Usage).where(Usage.tenant_id == tenant_id, Usage.date == today)
        row = session.exec(stmt).one_or_none()
        if not row:
            row = Usage(
                tenant_id=tenant_id, 
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
            tenant_id=tenant_id, 
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


def renew_subscription(tenant_id: UUID, amount: float, session: Session):
    """Renews a tenant's subscription by resetting their quota and recording a billing event."""
    from ..core.rate_limiter import reset_monthly_quota
    
    # 1. Reset the rate limiter quota
    reset_monthly_quota(str(tenant_id))
    
    # 2. Record the renewal event
    evt = BillingEvent(
        tenant_id=tenant_id, 
        event_type="subscription_renewed", 
        amount=amount, 
        meta={"action": "monthly_manual_renewal"}
    )
    session.add(evt)
    # We assume the caller will commit the session
    return True
