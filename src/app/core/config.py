from pydantic_settings import BaseSettings
from typing import Optional


import os
class Settings(BaseSettings):
    project_name: str = "security-compliance-platform"
    # Use absolute path to avoid SQLite errors
    database_url: str = f"sqlite:///{os.path.join(os.getcwd(), 'dev.db')}"
    scanner_worker_concurrency: int = 2
    
    # Scanner configuration
    scanner_timeout: int = 300  # 5 minutes
    scanner_temp_dir: str = "/tmp/scans"
    enabled_scanners: str = "bandit,checkov,pip-audit"  # Comma-separated list

    # Resolution configuration
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    bitbucket_token: Optional[str] = None

    # Slack configuration
    slack_webhook_url: Optional[str] = None

    # Jira configuration
    jira_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = None
    jira_project_key: Optional[str] = None
    
    # SMTP configuration
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "noreply@security-platform.com"
    
    # GenAI configuration
    gemini_api_key: Optional[str] = None

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }

# Initialize and debug
settings = Settings()
print(f"!!! CONFIG DEBUG !!! Project: {settings.project_name}")
if settings.github_token or settings.gitlab_token or settings.bitbucket_token:
    print(".....token present.....")
else:
    print(".....token not present.....")