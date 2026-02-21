import requests
from typing import Optional
from ..core.config import Settings
from ..models import Tenant

settings = Settings()

class SlackService:
    def __init__(self, webhook_url: Optional[str] = None, tenant: Optional[Tenant] = None):
        if webhook_url:
            self.webhook_url = webhook_url
        elif tenant and tenant.slack_webhook_url:
            self.webhook_url = tenant.slack_webhook_url
        else:
            self.webhook_url = settings.slack_webhook_url

    def send_notification(self, message: str) -> bool:
        """
        Sends a notification to Slack via a webhook URL.
        """
        if not self.webhook_url:
            print("WARNING: Slack notification skipped. SLACK_WEBHOOK_URL not configured.")
            return False

        try:
            payload = {"text": message}
            response = requests.post(self.webhook_url, json=payload)
            if response.status_code == 200:
                print("Slack notification sent successfully.")
                return True
            else:
                print(f"Failed to send Slack notification: {response.status_code} {response.text}")
                return False
        except Exception as e:
            print(f"ERROR: Exception while sending Slack notification: {str(e)}")
            return False

    def notify_pr_created(self, pr_url: str, finding_title: str, severity: str):
        """
        Sends a formatted notification about a new Pull Request.
        """
        message = (
            f"🚀 *New Pull Request Created for Security Fix*\n"
            f"*Finding:* {finding_title}\n"
            f"*Severity:* {severity}\n"
            f"*PR URL:* {pr_url}"
        )
        return self.send_notification(message)
