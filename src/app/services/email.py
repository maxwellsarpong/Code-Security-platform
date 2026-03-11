import logging
from typing import Optional
import smtplib
import ssl
from email.message import EmailMessage
from ..core.config import settings


logger = logging.getLogger(__name__)

def send_password_reset_email(email: str, token: str):
    """
    Sends a password reset email using the configured SMTP server.
    """
    reset_link = f"https://code-security-platform-frontend-lan.vercel.app/reset-password?token={token}"
    
    # Log it for development/debugging
    logger.debug(f"PASSWORD RESET REQUESTED - To: {email}, Link: {reset_link}")
    logger.info(f"Password reset link generated for {email}")
    
    if not settings.smtp_server:
        logger.warning("SMTP server not configured. Real email not sent.")
        return

    try:

        sender = settings.smtp_from_email
        password = settings.smtp_password
        receiver = email

        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = receiver
        msg["Subject"] = "Password Reset Request"
        
        body = f"You recently requested a password reset.\n\nClick the link below to reset your password:\n{reset_link}\n\nMake sure you don't share this link with anyone.\nIf you did not request this, please ignore this email."
        msg.set_content(body)
        
        with smtplib.SMTP(settings.smtp_server, settings.smtp_port) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)
        logger.info(f"Password reset email sent successfully to {email}")
        
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {str(e)}")


def send_resolution_email(
    email: str,
    repo_url: str,
    pr_url: str,
    jira_url: Optional[str] = None,
    resolved_count: int = 0,
    severity: str = "",
):
    """
    Sends an email notification to the user after a vulnerability resolution PR has been created.
    Includes the PR URL and optionally a Jira task URL.
    """
    logger.info(f"Sending resolution email to {email} for PR: {pr_url}")

    if not settings.smtp_server:
        logger.warning("SMTP server not configured. Resolution email not sent.")
        return

    try:
        msg = EmailMessage()
        msg["From"] = settings.smtp_from_email
        msg["To"] = email
        msg["Subject"] = f"✅ Vulnerability Fixes Ready for Review — PR Created"

        jira_line = f"\nJira Task:        {jira_url}" if jira_url else ""
        body = f"""\
Hello,

Your vulnerability scan resolution is complete. A Pull Request has been created with the automated fixes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Repository:       {repo_url}
  Fixes Applied:    {resolved_count} vulnerabilities resolved
  Highest Severity: {severity.upper() if severity else "N/A"}
  Pull Request:     {pr_url}{jira_line}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Please review the PR before merging to ensure the fixes are correct.

If you did not initiate this resolution, please contact your administrator.

— Security Compliance Platform
"""
        msg.set_content(body)

        with smtplib.SMTP(settings.smtp_server, settings.smtp_port) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)

        logger.info(f"Resolution email sent successfully to {email}")

    except Exception as e:
        logger.error(f"Failed to send resolution email to {email}: {str(e)}")

