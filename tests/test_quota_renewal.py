import pytest
from uuid import UUID
from sqlmodel import Session, select
from app.models import User, BillingEvent
from app.core.rate_limiter import check_rate_limit, _incr_memory

def test_quota_renewal_flow(auth_client, session: Session):
    # 1. Setup: Get the user for this auth_client
    # The auth_client uses cross-api-key header for 'testuser@example.com'
    stmt = select(User).where(User.email == "testuser@example.com")
    user = session.exec(stmt).first()
    assert user is not None
    
    # 2. Exhaust the quota (simulate)
    # free plan has 100 quota_per_month by default in models.py
    # We'll set it to something small for testing
    user.quota_per_month = 2
    session.add(user)
    session.commit()
    session.refresh(user)
    
    # Use the rate limiter to exhaust quota
    # 1st scan
    check_rate_limit(str(user.id), route="scans", quota_per_month=user.quota_per_month)
    # 2nd scan
    check_rate_limit(str(user.id), route="scans", quota_per_month=user.quota_per_month)
    
    # 3rd scan should fail
    with pytest.raises(Exception) as excinfo:
        check_rate_limit(str(user.id), route="scans", quota_per_month=user.quota_per_month)
    assert "monthly quota exceeded" in str(excinfo.value)
    
    # 3. Call the renewal endpoint
    response = auth_client.post("/api/v1/user/subscription/renew", params={"amount": 50.0})
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    
    # 4. Verify quota is reset (the 3rd scan should now succeed)
    # Note: we need to pass the rate/quota again as check_rate_limit uses injected values
    assert check_rate_limit(str(user.id), route="scans", quota_per_month=user.quota_per_month) is True
    
    # 5. Verify BillingEvent was created
    stmt = select(BillingEvent).where(
        BillingEvent.user_id == user.id, 
        BillingEvent.event_type == "subscription_renewed"
    )
    event = session.exec(stmt).first()
    assert event is not None
    assert event.amount == 50.0
    assert event.meta["action"] == "monthly_manual_renewal"
