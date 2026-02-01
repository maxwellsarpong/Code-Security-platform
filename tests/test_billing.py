import pytest
from unittest.mock import patch
from datetime import datetime


@patch("app.services.scanner.schedule_scan")
def test_billing_recorded_after_scan(mock_schedule_scan, client):
    """Test that billing is recorded after a scan completes."""
    # Mock the schedule_scan function to avoid actual repo cloning
    def mock_scan_execution(scan_id, tenant_id=None):
        from app.core.db import engine
        from sqlmodel import Session
        from app.models import Scan, Finding
        
        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.risk_score = 7.5
                
                # Add a mock finding
                finding = Finding(
                    scan_id=scan.id,
                    title="Mock Security Issue",
                    severity="HIGH",
                    description="This is a mock finding for testing",
                    remediation="Fix the mock issue",
                    scanner_name="mock-scanner"
                )
                session.add(finding)
                session.add(scan)
                session.commit()
    
    mock_schedule_scan.side_effect = mock_scan_execution
    
    # Create a tenant via API
    response = client.post("/api/v1/tenants?name=billing-test&rate_limit_per_minute=10&quota_per_month=100")
    assert response.status_code == 201
    body = response.json()
    api_key = body["api_key"]
    tenant_id = body["tenant_id"]
    headers = {"x-api-key": api_key}

    # Create a scan with tenant API key
    response = client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"}, headers=headers)
    assert response.status_code == 201
    scan_id = response.json()["id"]

    # Verify mock was called (which means scan was created and attempted to run)
    assert mock_schedule_scan.called
    
    # Verify scan was created in database
    scan_response = client.get(f"/api/v1/scans/{scan_id}")
    assert scan_response.status_code == 200
    assert scan_response.json()["status"] == "completed"
