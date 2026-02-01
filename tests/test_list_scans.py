import pytest
from uuid import UUID

from unittest.mock import patch

@patch("app.services.scanner.schedule_scan")
def test_list_scans(mock_schedule_scan, client):
    """Test that listing scans returns a list of results."""
    # 1. Create a couple of scans
    client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo1"})
    client.post("/api/v1/scans", json={"repo_url": "https://github.com/example/repo2"})
    
    # 2. Fetch the list
    response = client.get("/api/v1/scans")
    assert response.status_code == 200
    data = response.json()
    
    # 3. Verify structure and content
    assert isinstance(data, list)
    assert len(data) >= 2
    
    # Check fields in the first item
    first_scan = data[0]
    assert "id" in first_scan
    assert "repo_url" in first_scan
    assert "status" in first_scan
    assert "created_at" in first_scan
