import os
import smtplib
import ssl
from typing import Optional
from email.message import EmailMessage
import logging
from ..core.config import settings

# optional imports for RQ/Redis
try:
    from redis import Redis
    from rq import Queue, Retry
except ImportError:
    Redis = None
    Queue = None
    Retry = None

logger = logging.getLogger(__name__)

def _get_redis_conn():
    """Build a Redis connection that supports both `redis://` and TLS `rediss://`."""
    if Redis is None:
        return None
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    kwargs = {}
    if redis_url.startswith("rediss://"):
        kwargs["ssl_cert_reqs"] = None
    return Redis.from_url(redis_url, **kwargs)

def _send_email_smtp(msg: EmailMessage, email_type: str = "Email"):
    """
    Core SMTP sending logic with timeout and robust connection handling.
    This should ONLY be called from a context with network access (like the worker).
    """
    if not settings.smtp_server:
        logger.warning(f"SMTP server not configured. {email_type} to {msg['To']} not sent.")
        return

    timeout = 30 
    try:
        if settings.smtp_port == 465:
            logger.info(f"Connecting to {settings.smtp_server}:{settings.smtp_port} (SSL/TLS)...")
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(settings.smtp_server, settings.smtp_port, context=context, timeout=timeout)
        else:
            logger.info(f"Connecting to {settings.smtp_server}:{settings.smtp_port} (STARTTLS)...")
            server = smtplib.SMTP(settings.smtp_server, settings.smtp_port, timeout=timeout)
            
        with server:
            logger.debug("Connected to SMTP server. Sending EHLO...")
            server.ehlo()
            
            if settings.smtp_port != 465:
                logger.debug("Starting TLS...")
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                
            if settings.smtp_username and settings.smtp_password:
                logger.debug(f"Attempting login for {settings.smtp_username}...")
                server.login(settings.smtp_username, settings.smtp_password)
                
            logger.debug("Sending message...")
            server.send_message(msg)
        
        logger.info(f"{email_type} sent successfully to {msg['To']}")
    except smtplib.SMTPServerDisconnected:
        logger.error(f"SMTP Disconnected unexpectedly while sending {email_type} to {msg['To']}. Check port {settings.smtp_port} or network.")
        raise
    except Exception as e:
        logger.error(f"SMTP Error sending {email_type} to {msg['To']}: {str(e)}")
        raise


def send_password_reset_email(email: str, token: str):
    """
    Smart email sender: 
    - If in worker: Sends immediately via SMTP.
    - If in API: Enqueues a background task to Redis.
    """
    # 1. Check if we are already in the worker
    if os.getenv("RQ_WORKER_ID"):
        logger.info(f"WORKER: Processing password reset email for {email}")
        reset_link = f"https://code-security-platform-frontend-lan.vercel.app/reset-password?token={token}"
        msg = EmailMessage()
        msg["From"] = settings.smtp_from_email
        msg["To"] = email
        msg["Subject"] = "Password Reset Request"
        body = f"You recently requested a password reset.\n\nClick the link below to reset your password:\n{reset_link}\n\nMake sure you don't share this link with anyone.\nIf you did not request this, please ignore this email."
        msg.set_content(body)
        return _send_email_smtp(msg, "Password reset email")

    # 2. Otherwise, we are in the API — Enqueue to Redis
    logger.info(f"API: Enqueuing password reset email for {email} to background worker.")
    try:
        conn = _get_redis_conn()
        if conn and Queue:
            # Using 'emails' queue to avoid impacting scanners
            q = Queue(name="emails", connection=conn)
            q.enqueue("app.services.email.send_password_reset_email", email, token, job_timeout=60)
            return
    except Exception as e:
        logger.error(f"Failed to enqueue email task: {e}")
    
    # Final fallback if Redis fails: Try sending sync (likely to fail/timeout on Render Web)
    logger.warning("ENQUEUE FAILED: Falling back to synchronous email attempt.")
    reset_link = f"https://code-security-platform-frontend-lan.vercel.app/reset-password?token={token}"
    msg = EmailMessage()
    msg["From"] = settings.smtp_from_email
    msg["To"] = email
    msg["Subject"] = "Password Reset Request"
    msg.set_content(f"Reset link fallback: {reset_link}")
    return _send_email_smtp(msg, "Fallback Password Reset")


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
    Called by the ResolutionService which ALREADY runs in the worker.
    """
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
    _send_email_smtp(msg, "Resolution email")

