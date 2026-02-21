import pytest
from uuid import UUID
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.models import Tenant, User


def test_registration_and_login(client: TestClient):
    # 1. Register
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@example.com",
            "password": "password123",
            "tenant_name": "Test Tenant"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "tenant_id" in data

    # 2. Login
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "test@example.com", "password": "password123"}
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # 3. JSON Login
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "password123"}
    )
    assert response.status_code == 200
    token_data_json = response.json()
    assert "access_token" in token_data_json
    assert token_data_json["token_type"] == "bearer"
    assert token_data_json["access_token"]  # Should look like a JWT


@patch("git.Repo.clone_from")
def test_tenant_isolation(mock_clone, client: TestClient):
    mock_clone.return_value = MagicMock()
    # 1. Register Tenant A
    client.post(
        "/api/v1/auth/register",
        json={"email": "a@example.com", "password": "pwd", "tenant_name": "A"}
    )
    token_a = client.post(
        "/api/v1/auth/token",
        data={"username": "a@example.com", "password": "pwd"}
    ).json()["access_token"]

    # 2. Register Tenant B
    client.post(
        "/api/v1/auth/register",
        json={"email": "b@example.com", "password": "pwd", "tenant_name": "B"}
    )
    token_b = client.post(
        "/api/v1/auth/token",
        data={"username": "b@example.com", "password": "pwd"}
    ).json()["access_token"]

    # 3. Tenant A creates a scan
    headers_a = {"Authorization": f"Bearer {token_a}"}
    response = client.post(
        "/api/v1/scans",
        json={"repo_url": "https://github.com/org/repo-a"},
        headers=headers_a
    )
    assert response.status_code == 201
    scan_a_id = response.json()["id"]

    # 4. Tenant B should NOT see Tenant A's scan
    headers_b = {"Authorization": f"Bearer {token_b}"}
    response = client.get("/api/v1/scans", headers=headers_b)
    assert response.status_code == 200
    assert len(response.json()) == 0

    # 5. Tenant B should NOT be able to read Tenant A's scan by ID
    response = client.get(f"/api/v1/scans/{scan_a_id}", headers=headers_b)
    assert response.status_code == 403


@patch("git.Repo.clone_from")
@patch("app.services.resolution.SlackService")
@patch("app.services.resolution.JiraService")
@patch("app.services.resolution.ResolutionService._resolve_multiple_findings")
def test_tenant_settings_usage(mock_resolve, mock_jira, mock_slack, mock_clone, client: TestClient):
    mock_clone.return_value = MagicMock()
    # Verify that resolution service uses tenant settings
    # 1. Register and login
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "t@example.com", 
            "password": "pwd", 
            "tenant_name": "T"
        }
    )
    token = client.post(
        "/api/v1/auth/token",
        data={"username": "t@example.com", "password": "pwd"}
    ).json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Update tenant settings (Manually in DB for test)
    from app.core.db import engine as db_engine
    from sqlmodel import Session, select
    with Session(db_engine) as session:
        tenant = session.exec(select(Tenant).where(Tenant.name == "T")).first()
        tenant.slack_webhook_url = "https://tenant-slack.com"
        tenant.jira_url = "https://tenant-jira.com"
        session.add(tenant)
        session.commit()
        session.refresh(tenant)
        tenant_id = tenant.id
    
    # 3. Create a scan and a finding
    resp = client.post("/api/v1/scans", json={"repo_url": "https://github.com/org/repo"}, headers=headers)
    scan_id = UUID(resp.json()["id"])
    
    with Session(db_engine) as session:
        from app.models import Finding
        finding = Finding(
            scan_id=scan_id, 
            tenant_id=tenant_id, 
            title="Vulnerability", 
            severity="HIGH"
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        finding_id = finding.id

    # 4. Trigger resolution
    # Mock _resolve_multiple_findings to succeed and call PR creation
    mock_resolve.return_value = MagicMock(status="success")
    
    # We need to test the PR creation specifically or just check if services were initialized with tenant
    from app.services.resolution import ResolutionService
    with Session(db_engine) as session:
        res_service = ResolutionService(session)
        # Mocking the actual PR call inside the helper
        with patch("app.services.resolution.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = {"html_url": "https://github.com/PR/1"}
            
            res_service._create_pull_request(
                "https://github.com/org/repo", 
                "branch", 
                finding, 
                "token", 
                tenant=tenant
            )
            
            # Verify SlackService was initialized with tenant
            mock_slack.assert_called_once()
            args, kwargs = mock_slack.call_args
            assert kwargs["tenant"].id == tenant_id
            
            # Verify JiraService was initialized with tenant
            mock_jira.assert_called_once()
            args, kwargs = mock_jira.call_args
            assert kwargs["tenant"].id == tenant_id


def test_scan_id_resolution_routing(client: TestClient):
    # Verify that passing a SCAN ID to the findings endpoint also works
    # 1. Register and login
    client.post(
        "/api/v1/auth/register",
        json={"email": "s@example.com", "password": "pwd", "tenant_name": "S"}
    )
    token = client.post(
        "/api/v1/auth/token",
        data={"username": "s@example.com", "password": "pwd"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create scan with mock clone
    with patch("git.Repo.clone_from") as mock_clone:
        mock_clone.return_value = MagicMock()
        resp = client.post("/api/v1/scans", json={"repo_url": "https://github.com/org/repo-s"}, headers=headers)
        scan_id = resp.json()["id"]

    # 3. Request resolution using SCAN ID on /findings/{id}/resolve
    # It should return 200/Success (even if findings are 0) or 404/Failed if we didn't fix the routing
    # Since there are 0 findings, the service will return "failed" with some message but 
    # the router should first bypass the 404 Finding check
    response = client.post(f"/api/v1/findings/{scan_id}/resolve", headers=headers)
    # The expected status from service for 0 findings is "failed" or "success: no findings"
    # But if the router fix works, it won't be a 404 before reaching the service.
    assert response.status_code != 404
