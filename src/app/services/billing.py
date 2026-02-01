from sqlmodel import Session, select
from ..core.config import Settings
from ..models import Usage, BillingEvent
import os
from datetime import date
from uuid import UUID


def record_usage(tenant_id: str, scans: int = 0, billable_units: int = 0, session: Session | None = None):
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
            row = Usage(tenant_id=tenant_id, date=today, scans_count=scans, billable_units=billable_units)
            session.add(row)
        else:
            row.scans_count = (row.scans_count or 0) + scans
            row.billable_units = (row.billable_units or 0) + billable_units
            session.add(row)

        # create billing event (simple metering event)
        evt = BillingEvent(tenant_id=tenant_id, event_type="scan_completed", amount=0.0, meta={"scans": scans, "units": billable_units})
        session.add(evt)
        if own_session:
            session.commit()
        return True
    finally:
        if own_session:
            session.close()
