import pytest
from unittest.mock import patch
from datetime import datetime


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"  # API returns "ok", not "healthy"



@patch("app.services.scanner.schedule_scan")
def test_create_and_poll_scan(mock_schedule_scan, client):
    """Test scan creation and polling with mocked scanner."""
    # Mock the schedule_scan function to avoid actual repo cloning
    # It should update the scan status in the database
    def mock_scan_execution(scan_id, tenant_id=None):
        from app.core.db import engine
        from sqlmodel import Session
        from app.models import Scan, Finding
        
        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.risk_score = 5.5
                
                # Add a mock finding
                finding = Finding(
                    scan_id=scan.id,
                    title="Mock Security Issue",
                    severity="MEDIUM",
                    description="This is a mock finding for testing",
                    remediation="Fix the mock issue",
                    scanner_name="mock-scanner",
                    file_path="test.py",
                    line_number=42
                )
                session.add(finding)
                session.add(scan)
                session.commit()
    
    mock_schedule_scan.side_effect = mock_scan_execution
    
    # Create a scan
    response = client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"})
    assert response.status_code == 201  # API returns 201 Created
    data = response.json()
    assert "id" in data
    assert data["repo_url"] == "https://github.com/example/repo"
    assert data["status"] in ["queued", "running", "completed", "failed"]

    scan_id = data["id"]

    # Poll the scan
    response = client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scan_id
    assert data["status"] == "completed"
    assert "risk_score" in data
    
    # Verify mock was called
    assert mock_schedule_scan.called
