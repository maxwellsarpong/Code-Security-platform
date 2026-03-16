import pytest
import io
import zipfile
from pathlib import Path

def test_local_scan_upload_success(auth_client):
    # Create a dummy zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr("test.py", "print('hello world')")
    zip_buffer.seek(0)
    
    # Test upload
    response = auth_client.post(
        "/api/v1/scans/local",
        files={"file": ("workspace.zip", zip_buffer, "application/zip")}
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["is_local"] is True
    assert data["status"] == "queued"
    
    # We no longer verify zip_path existence since zip_data is stored in the DB
    # and processed by the worker from there.

def test_local_scan_invalid_file_type(auth_client):
    response = auth_client.post(
        "/api/v1/scans/local",
        files={"file": ("test.txt", io.BytesIO(b"not a zip"), "text/plain")}
    )
    
    assert response.status_code == 400
    assert "Only .zip files are supported" in response.json()["detail"]
