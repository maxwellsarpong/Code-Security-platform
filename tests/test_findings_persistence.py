import pytest
from unittest.mock import patch
from datetime import datetime
from uuid import UUID

@patch("app.services.scanner.schedule_scan")
def test_findings_persistence_and_api_response(mock_schedule_scan, auth_client):
    """Test that findings are persisted and returned in the API response."""
    
    def mock_scan_execution(scan_id, tenant_id=None):
        from app.core.db import engine
        from sqlmodel import Session
        from app.models import Scan, Finding
        
        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.risk_score = 8.5
                
                # Add a mock finding with full metadata
                finding = Finding(
                    scan_id=scan.id,
                    tenant_id=scan.tenant_id,
                    title="Insecure Cryptographic Algorithm",
                    severity="HIGH",
                    description="The application uses MD5 which is insecure.",
                    remediation="Upgrade to SHA-256 or better.",
                    scanner_name="bandit",
                    file_path="src/crypto_utils.py",
                    line_number=42,
                    confidence="HIGH"
                )
                session.add(finding)
                session.add(scan)
                session.commit()
    
    mock_schedule_scan.side_effect = mock_scan_execution
    
    # 1. Create a scan
    response = auth_client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/vulnerable-repo"})
    assert response.status_code == 201
    scan_id = response.json()["id"]
    
    # 2. Fetch the scan details
    response = auth_client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    data = response.json()
    
    # 3. Verify findings are present
    assert data["status"] == "completed"
    assert data["risk_score"] == 8.5
    assert "findings" in data
    assert len(data["findings"]) == 1
    
    finding = data["findings"][0]
    assert finding["title"] == "Insecure Cryptographic Algorithm"
    assert finding["severity"] == "HIGH"
    assert finding["description"] == "The application uses MD5 which is insecure."
    assert finding["remediation"] == "Upgrade to SHA-256 or better."
    # Optional: Verify new scanner metadata fields if they were added to the schema
    # (Note: I should check if FindingRead schema was updated)
