import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ..core.config import settings

logger = logging.getLogger(__name__)

def send_password_reset_email(email: str, token: str):
    """
    Sends a password reset email using the configured SMTP server.
    """
    reset_link = f"http://localhost:8000/reset-password?token={token}"
    
    # Log it for development/debugging
    print(f"\n=====================================")
    print(f" PASSWORD RESET REQUESTED")
    print(f" To: {email}")
    print(f" Reset Link: {reset_link}")
    print(f"=====================================\n")
    logger.info(f"Password reset link generated for {email}")
    
    if not settings.smtp_server:
        logger.warning("SMTP server not configured. Real email not sent.")
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = settings.smtp_from_email
        msg["To"] = email
        msg["Subject"] = "Password Reset Request"
        
        body = f"You recently requested a password reset.\n\nClick the link below to reset your password:\n{reset_link}\n\nMakesure you don't share this link with anyone.\nIf you did not request this, please ignore this email."
        msg.attach(MIMEText(body, "plain"))
        
        server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
        server.starttls()
        
        if settings.smtp_username and settings.smtp_password:
            server.login(settings.smtp_username, settings.smtp_password)
            
        server.send_message(msg)
        server.quit()
        logger.info(f"Password reset email sent successfully to {email}")
        
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {str(e)}")
