import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from uuid import uuid4, UUID
from app.models import Scan, Finding, User, APIKey

def test_resolve_finding_endpoint(client, session):
    # Setup: Create a user and API key
    email = f"user_{uuid4()}@example.com"
    response = client.post("/api/v1/auth/register", json={"email": email, "password": "pwd"})
    assert response.status_code == 200
    user_id = UUID(response.json()["user"]["id"])
    
    token_resp = client.post("/api/v1/auth/token", data={"username": email, "password": "pwd"})
    token = token_resp.json()["access_token"]
    response = client.post("/api/v1/user/api-key", headers={"Authorization": f"Bearer {token}"})
    api_key = response.json()["api_key"]
    headers = {"x-api-key": api_key}

    # Setup: Create a scan and a finding
    scan = Scan(user_id=user_id, repo_url="https://github.com/test/repo", status="completed")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        user_id=user_id,
        title="Test Vulnerability",
        severity="HIGH",
        description="Test Description",
        file_path="src/main.py",
        line_number=10
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)

    # Mock the ResolutionService.resolve_finding to test the router
    with patch("app.api.routers.ResolutionService.resolve_finding") as mock_resolve:
        from app.schemas import ResolutionResponse
        mock_resolve.return_value = ResolutionResponse(
            status="success",
            pr_url="https://github.com/test/repo/pull/1",
            finding_id=finding.id,
            message="Pull request created"
        )

        response = client.post(
            f"/api/v1/findings/{finding.id}/resolve",
            json={"github_token": "fake-token"},
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["pr_url"] == "https://github.com/test/repo/pull/1"
        assert data["finding_id"] == str(finding.id)

def test_resolve_finding_not_found(client, session):
    # Setup: Create a user and API key
    email = f"user_{uuid4()}@example.com"
    response = client.post("/api/v1/auth/register", json={"email": email, "password": "pwd"})
    assert response.status_code == 200
    
    token_resp = client.post("/api/v1/auth/token", data={"username": email, "password": "pwd"})
    token = token_resp.json()["access_token"]
    response = client.post("/api/v1/user/api-key", headers={"Authorization": f"Bearer {token}"})
    api_key = response.json()["api_key"]
    headers = {"x-api-key": api_key}

    random_id = uuid4()
    response = client.post(
        f"/api/v1/findings/{random_id}/resolve",
        json={"github_token": "fake-token"},
        headers=headers
    )
    assert response.status_code == 404

def test_resolution_service_logic(session):
    from app.services.resolution import ResolutionService
    
    # Setup
    # Create a dummy user for context
    user = User(email=f"user_{uuid4()}@example.com", hashed_password="pwd")
    session.add(user)
    session.commit()
    session.refresh(user)
    
    scan = Scan(user_id=user.id, repo_url="https://github.com/test/repo", status="completed")
    session.add(scan)
    session.commit()
    
    finding = Finding(
        scan_id=scan.id,
        user_id=user.id,
        title="Test Vulnerability",
        severity="HIGH",
        description="Test Description",
        file_path="src/main.py",
        line_number=10
    )
    session.add(finding)
    session.commit()

    service = ResolutionService(session)
    
    # Mock dependencies
    with patch("app.services.resolution.Repo.clone_from") as mock_clone, \
         patch("app.services.resolution.ResolutionService._generate_fix") as mock_fix, \
         patch("app.services.resolution.ResolutionService._create_pull_request") as mock_pr, \
         patch("app.services.resolution.Path.exists") as mock_exists, \
         patch("app.services.resolution.open", create=True) as mock_open:
        
        mock_repo = MagicMock()
        mock_clone.return_value = mock_repo
        mock_fix.return_value = "fixed content"
        mock_pr.return_value = "https://github.com/test/repo/pull/1"
        mock_exists.return_value = True
        
        response = service.resolve_finding(finding.id, github_token="fake-token")
        
        assert response.status == "success", f"Resolution failed: {response.message}"
        assert response.pr_url == "https://github.com/test/repo/pull/1"
        assert mock_clone.called
        mock_repo.create_head.assert_called_once()
        mock_repo.index.add.assert_called_once()
        mock_repo.index.commit.assert_called_once()
        mock_repo.remote().push.assert_called_once()


def test_resolution_service_gitlab(session):
    from app.services.resolution import ResolutionService
    # Setup
    user = User(email=f"user_{uuid4()}@example.com", hashed_password="pwd", gitlab_token="GL-TOKEN")
    session.add(user)
    session.commit()
    session.refresh(user)
    
    scan = Scan(user_id=user.id, repo_url="https://gitlab.com/test/group/project", status="completed")
    session.add(scan)
    session.commit()
    finding = Finding(scan_id=scan.id, user_id=user.id, title="Test", severity="HIGH", description="Desc", file_path="main.py")
    session.add(finding)
    session.commit()

    with patch("app.services.resolution.Repo.clone_from") as mock_clone, \
         patch("app.services.resolution.ResolutionService._generate_fix") as mock_fix, \
         patch("app.services.resolution.requests.post") as mock_post, \
         patch("app.services.resolution.Path.exists") as mock_exists, \
         patch("app.services.resolution.SlackService") as mock_slack, \
         patch("app.services.resolution.JiraService") as mock_jira, \
         patch("app.services.resolution.open", create=True) as mock_open:
        
        service = ResolutionService(session)
        mock_clone.return_value = MagicMock()
        mock_fix.return_value = "fixed"
        mock_exists.return_value = True
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"web_url": "https://gitlab.com/test/group/project/-/merge_requests/1"}
        mock_post.return_value = mock_response

        response = service.resolve_finding(finding.id, github_token="fake-token")
        assert response.status == "success"
        assert "merge_requests/1" in response.pr_url
        assert mock_post.called
        # Check if URL was correctly encoded (test/group/project -> test%2Fgroup%2Fproject)
        args, kwargs = mock_post.call_args
        assert "test%2Fgroup%2Fproject" in args[0]

def test_resolution_service_bitbucket(session):
    from app.services.resolution import ResolutionService
    # Setup
    user = User(email=f"user_{uuid4()}@example.com", hashed_password="pwd", bitbucket_token="BB-TOKEN")
    session.add(user)
    session.commit()
    session.refresh(user)
    
    scan = Scan(user_id=user.id, repo_url="https://bitbucket.org/workspace/repo", status="completed")
    session.add(scan)
    session.commit()
    finding = Finding(scan_id=scan.id, user_id=user.id, title="Test", severity="HIGH", description="Desc", file_path="main.py")
    session.add(finding)
    session.commit()

    with patch("app.services.resolution.Repo.clone_from") as mock_clone, \
         patch("app.services.resolution.ResolutionService._generate_fix") as mock_fix, \
         patch("app.services.resolution.requests.post") as mock_post, \
         patch("app.services.resolution.Path.exists") as mock_exists, \
         patch("app.services.resolution.SlackService") as mock_slack, \
         patch("app.services.resolution.JiraService") as mock_jira, \
         patch("app.services.resolution.open", create=True) as mock_open:
        
        service = ResolutionService(session)
        mock_clone.return_value = MagicMock()
        mock_fix.return_value = "fixed"
        mock_exists.return_value = True
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"links": {"html": {"href": "https://bitbucket.org/workspace/repo/pull-requests/1"}}}
        mock_post.return_value = mock_response

        response = service.resolve_finding(finding.id, github_token="fake-token")
        assert response.status == "success"
        assert "pull-requests/1" in response.pr_url
        assert mock_post.called
        args, kwargs = mock_post.call_args
        assert "repositories/workspace/repo/pullrequests" in args[0]


def test_fix_dependency_version_increment(session):
    from app.services.resolution import ResolutionService
    service = ResolutionService(session)
    
    finding = Finding(
        title="Vulnerable dependency: requests (2.25.0)",
        description="package requests version 2.25.0 has a vulnerability",
        file_path="requirements.txt"
    )
    content = "requests==2.25.0\n"
    
    fixed = service._fix_dependency(content, finding)
    # 2.25.0 should become 2.25.1
    assert "requests==2.25.1" in fixed

def test_bundled_resolution_scan(session):
    from app.services.resolution import ResolutionService
    service = ResolutionService(session)
    
    # Setup
    user = User(email=f"user_{uuid4()}@example.com", hashed_password="pwd")
    session.add(user)
    session.commit()
    session.refresh(user)
    
    scan = Scan(id=uuid4(), user_id=user.id, repo_url="https://github.com/test/repo", status="completed")
    session.add(scan)
    session.commit()
    
    f1 = Finding(scan_id=scan.id, user_id=user.id, title="Vuln 1", file_path="f1.py", description="D1", severity="HIGH")
    f2 = Finding(scan_id=scan.id, user_id=user.id, title="Vuln 2", file_path="f2.py", description="D2", severity="LOW")
    session.add(f1)
    session.add(f2)
    session.commit()

    with patch("app.services.resolution.Repo.clone_from") as mock_clone, \
         patch("app.services.resolution.ResolutionService._generate_fix") as mock_fix, \
         patch("app.services.resolution.ResolutionService._create_pull_request") as mock_pr, \
         patch("app.services.resolution.Path.exists") as mock_exists, \
         patch("app.services.resolution.open", create=True) as mock_open:
        
        mock_clone.return_value = MagicMock()
        mock_fix.side_effect = ["fixed 1", "fixed 2"]
        mock_pr.return_value = "https://github.com/test/repo/pull/bundled"
        mock_exists.return_value = True
        
        response = service.resolve_finding(scan.id, github_token="fake")
        
        assert response.status == "success"
        assert response.pr_url == "https://github.com/test/repo/pull/bundled"
        assert "Created single PR with 2 fixes" in response.message
        assert mock_pr.call_args[1].get('is_bundled') is True
        assert mock_pr.call_args[1].get('count') == 2
