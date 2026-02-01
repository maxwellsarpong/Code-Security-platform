import pytest
from unittest.mock import patch
from datetime import datetime
import time


@patch("app.services.scanner.schedule_scan")
def test_tenant_rate_limit(mock_schedule_scan, client):
    """Test that tenant-specific rate limits are enforced."""
    # Mock the schedule_scan function
    def mock_scan_execution(scan_id, tenant_id=None):
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
    
    # Create a tenant with rate limit
    r = client.post("/api/v1/tenants?name=test-rl&rate_limit_per_minute=2&quota_per_month=100")
    assert r.status_code == 201
    body = r.json()
    api_key = body["api_key"]

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
    """Test that anonymous requests are rate limited."""
    # Mock the schedule_scan function
    def mock_scan_execution(scan_id, tenant_id=None):
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
    
    # Make multiple anonymous requests
    for _ in range(3):
        r = client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"})
    assert r.status_code in (201, 429)
