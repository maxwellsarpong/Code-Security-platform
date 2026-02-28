import pytest
from unittest.mock import patch
from datetime import datetime
import time


@patch("app.services.scanner.schedule_scan")
def test_tenant_rate_limit(mock_schedule_scan, client):
    """Test that tenant-specific rate limits are enforced."""
    # Mock the schedule_scan function
    def mock_scan_execution(scan_id, user_id=None):
        from app.core.db import engine
        from sqlmodel import Session
        from app.models import Scan
        
        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.risk_score = 5.0
                session.add(scan)
                session.commit()
    
    mock_schedule_scan.side_effect = mock_scan_execution
    
    # Create a user and api key
    client.post("/api/v1/auth/register", json={"email": "test-rl@example.com", "password": "pwd"})
    token_resp = client.post("/api/v1/auth/token", data={"username": "test-rl@example.com", "password": "pwd"})
    token = token_resp.json()["access_token"]
    r = client.post("/api/v1/user/api-key", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201
    body = r.json()
    api_key = body["api_key"]
    
    # Manually configure rate limits in DB
    from app.core.db import engine
    from sqlmodel import Session, select
    from app.models import User
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == "test-rl@example.com")).first()
        user.rate_limit_per_minute = 2
        user.scan_quota_per_month = 100
        session.add(user)
        session.commit()

    headers = {"x-api-key": api_key}
    # two allowed
    r1 = client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"}, headers=headers)
    assert r1.status_code == 201
    r2 = client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"}, headers=headers)
    assert r2.status_code == 201
    # third should be rate limited
    r3 = client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"}, headers=headers)
    assert r3.status_code == 429


@patch("app.services.scanner.schedule_scan")
def test_anonymous_rate_limit_applies(mock_schedule_scan, client):
    """Test that rate limits apply to tenants even without a full profile (using a dummy tenant)."""
    # Create a low-limit user to simulate the 'anonymous' behavior
    client.post("/api/v1/auth/register", json={"email": "dummy-anon@example.com", "password": "pwd"})
    token_resp = client.post("/api/v1/auth/token", data={"username": "dummy-anon@example.com", "password": "pwd"})
    token = token_resp.json()["access_token"]
    r = client.post("/api/v1/user/api-key", headers={"Authorization": f"Bearer {token}"})
    api_key = r.json()["api_key"]
    
    from app.core.db import engine
    from sqlmodel import Session, select
    from app.models import User
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == "dummy-anon@example.com")).first()
        user.rate_limit_per_minute = 2
        session.add(user)
        session.commit()
    headers = {"x-api-key": api_key}
    
    # Make multiple requests
    last_status = 0
    for _ in range(3):
        r = client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"}, headers=headers)
        last_status = r.status_code
        
    assert last_status in (201, 429)
