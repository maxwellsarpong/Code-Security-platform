import pytest
from unittest.mock import patch, MagicMock
from app.services.slack_service import SlackService
from app.services.jira_service import JiraService

@patch("app.services.slack_service.requests.post")
def test_slack_send_notification(mock_post):
    mock_post.return_value.status_code = 200
    service = SlackService(webhook_url="https://mock.slack.com/webhook")
    
    result = service.send_notification("Test Message")
    
    assert result is True
    mock_post.assert_called_once_with(
        "https://mock.slack.com/webhook",
        json={"text": "Test Message"}
    )

@patch("app.services.slack_service.requests.post")
def test_slack_notify_pr_created(mock_post):
    mock_post.return_value.status_code = 200
    service = SlackService(webhook_url="https://mock.slack.com/webhook")
    
    result = service.notify_pr_created("https://github.com/PR/1", "Finding Title", "HIGH")
    
    assert result is True
    assert "Finding Title" in mock_post.call_args[1]["json"]["text"]
    assert "https://github.com/PR/1" in mock_post.call_args[1]["json"]["text"]

@patch("app.services.jira_service.requests.post")
@patch("app.services.jira_service.settings")
def test_jira_create_issue(mock_settings, mock_post):
    mock_settings.jira_url = "https://mock.atlassian.net"
    mock_settings.jira_email = "test@example.com"
    mock_settings.jira_api_token = "token"
    mock_settings.jira_project_key = "PROJ"
    
    mock_post.return_value.status_code = 201
    mock_post.return_value.json.return_value = {"key": "PROJ-123"}
    
    service = JiraService()
    result = service.create_issue("Summary", "Description")
    
    assert result == "PROJ-123"
    assert mock_post.called

@patch("app.services.jira_service.requests.post")
@patch("app.services.jira_service.settings")
def test_jira_create_vulnerability_task(mock_settings, mock_post):
    mock_settings.jira_url = "https://mock.atlassian.net"
    mock_settings.jira_email = "test@example.com"
    mock_settings.jira_api_token = "token"
    mock_settings.jira_project_key = "PROJ"
    
    mock_post.return_value.status_code = 201
    mock_post.return_value.json.return_value = {"key": "PROJ-124"}
    
    service = JiraService()
    result = service.create_vulnerability_task("Vuln Title", "Vuln Desc", "https://github.com/PR/1")
    
    assert result == "PROJ-124"
    payload = mock_post.call_args[1]["json"]
    assert payload["fields"]["summary"] == "Vulnerability Resolution: Vuln Title"
