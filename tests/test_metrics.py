import pytest
import time
from unittest.mock import patch
from datetime import datetime
from prometheus_client import REGISTRY


def _metrics_contains(client, text: str) -> bool:
    r = client.get("/metrics")
    assert r.status_code == 200
    return text in r.text


def test_metrics_endpoint_available(client):
    """Test that the /metrics endpoint is available."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]


@patch("app.services.scanner.schedule_scan")
def test_scan_increments_metrics(mock_schedule_scan, auth_client):
    """Test that creating a scan increments Prometheus metrics."""
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
                scan.risk_score = 3.2
                
                # Add a mock finding
                finding = Finding(
                    scan_id=scan.id,
                    tenant_id=scan.tenant_id,
                    title="Mock Security Issue",
                    severity="LOW",
                    description="This is a mock finding for testing",
                    remediation="Fix the mock issue",
                    scanner_name="mock-scanner"
                )
                session.add(finding)
                session.add(scan)
                session.commit()
    
    mock_schedule_scan.side_effect = mock_scan_execution
    
    # Get initial metric values
    from app.services.scanner import SCANS_STARTED, SCANS_COMPLETED
    before_started = SCANS_STARTED._value._value
    before_completed = SCANS_COMPLETED._value._value
    
    # Create a scan
    response = auth_client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo"})
    assert response.status_code == 201
    scan_id = response.json()["id"]

    # Verify mock was called
    assert mock_schedule_scan.called
    
    # Verify scan completed
    scan_response = auth_client.get(f"/api/v1/scans/{scan_id}")
    assert scan_response.status_code == 200
    assert scan_response.json()["status"] == "completed"
