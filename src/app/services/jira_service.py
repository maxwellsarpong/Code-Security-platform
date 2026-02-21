import requests
from requests.auth import HTTPBasicAuth
from typing import Optional
from ..core.config import Settings
from ..models import Tenant

settings = Settings()

class JiraService:
    def __init__(self, tenant: Optional[Tenant] = None, jira_url: Optional[str] = None):
        raw_url = jira_url or (tenant.jira_url if tenant else None) or settings.jira_url
        if raw_url:
            # Normalize URL: remove path components if mistakenly included
            from urllib.parse import urlparse
            parsed = urlparse(raw_url)
            self.jira_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            self.jira_url = None
        
        self.email = (tenant.jira_email if tenant else None) or settings.jira_email
        self.api_token = (tenant.jira_api_token if tenant else None) or settings.jira_api_token
        self.project_key = (tenant.jira_project_key if tenant else None) or settings.jira_project_key

    def create_issue(self, summary: str, description: str, issue_type: str = "Task") -> Optional[str]:
        """
        Creates a new issue in Jira.
        """
        if not all([self.jira_url, self.email, self.api_token, self.project_key]):
            print("WARNING: Jira issue creation skipped. Jira credentials not fully configured.")
            return None

        url = f"{self.jira_url}/rest/api/3/issue"
        auth = HTTPBasicAuth(self.email, self.api_token)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        # Detailed structure for Jira Cloud API v3
        payload = {
            "fields": {
                "project": {
                    "key": self.project_key
                },
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": description
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "name": issue_type
                }
            }
        }

        try:
            print(f"DEBUG: Attempting to create Jira issue at {url}")
            response = requests.post(url, json=payload, headers=headers, auth=auth)
            if response.status_code == 201:
                issue_key = response.json().get("key")
                print(f"Jira issue created successfully: {issue_key}")
                return issue_key
            else:
                print(f"Failed to create Jira issue: Status {response.status_code}")
                print(f"Response: {response.text}")
                return None
        except Exception as e:
            print(f"ERROR: Exception while creating Jira issue: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def create_vulnerability_task(self, finding_title: str, finding_description: str, pr_url: str):
        """
        Creates a Jira task specifically for a vulnerability resolution.
        """
        summary = f"Vulnerability Resolution: {finding_title}"
        description = (
            f"An automated fix has been suggested for the following vulnerability:\n\n"
            f"Description: {finding_description}\n\n"
            f"Pull Request: {pr_url}"
        )
        return self.create_issue(summary, description)
