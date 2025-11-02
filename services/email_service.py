"""Minimal Email Service for OTP delivery.
 
If SMTP environment variables are not configured, falls back to dev mode and
prints OTP to console instead of sending an email.
 
Env vars:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email import encoders
from typing import Optional
 
 
class EmailService:
    def __init__(self):
        self.host = os.getenv("SMTP_HOST")
        self.port = int(os.getenv("SMTP_PORT", "0") or 0)
        self.user = os.getenv("SMTP_USER")
        self.password = os.getenv("SMTP_PASS")
        self.sender = os.getenv("SMTP_FROM", self.user or "noreply@example.com")
 
    @property
    def enabled(self) -> bool:
        return all([self.host, self.port, self.user, self.password, self.sender]) and self.port > 0
 
    def send_otp_email(self, to_email: str, otp: str) -> bool:
        """Synchronous send (used by background task). Returns True if real email sent."""
        if not self.enabled:
            print(f"[EmailService] Dev mode (no SMTP configured). OTP for {to_email}: {otp}")
            return False
        try:
            body = (
                f"Your SecureGuard Pro verification code is: {otp}\n\n"
                "It expires in 5 minutes. If you did not request this, ignore this email."
            )
            msg = MIMEText(body)
            msg["Subject"] = "SecureGuard Pro OTP"
            msg["From"] = self.sender
            msg["To"] = to_email
            with smtplib.SMTP(self.host, self.port, timeout=15) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.send_message(msg)
            print(f"[EmailService] Sent OTP email to {to_email}")
            return True
        except Exception as e:
            print(f"[EmailService] Failed sending email to {to_email}: {e}")
            return False
 
    def send_report_email(self, to_email: str, subject: str, body: str, pdf_path: Optional[str] = None) -> bool:
        """Send a compliance report email with optional PDF attachment. Returns True if SMTP send succeeded.
 
        Falls back to dev mode if SMTP not configured (prints path + body)."""
        if not self.enabled:
            print(f"[EmailService] Dev mode - would send report email to {to_email}. Subject: {subject}\nBody: {body[:200]}...\nPDF: {pdf_path or 'none'}")
            return False
        try:
            if pdf_path and os.path.exists(pdf_path):
                msg = MIMEMultipart()
                msg.attach(MIMEText(body, 'plain'))
                with open(pdf_path, 'rb') as f:
                    part = MIMEApplication(f.read(), Name=os.path.basename(pdf_path))
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(pdf_path)}"'
                msg.attach(part)
            else:
                msg = MIMEText(body, 'plain')
            msg['Subject'] = subject
            msg['From'] = self.sender
            msg['To'] = to_email
            with smtplib.SMTP(self.host, self.port, timeout=20) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.send_message(msg)
            print(f"[EmailService] Sent report email to {to_email} (attachment: {'yes' if pdf_path else 'no'})")
            return True
        except Exception as e:
            print(f"[EmailService] Failed sending report email to {to_email}: {e}")
            return False
 
    def test_connection(self) -> Optional[str]:
        """Attempt a lightweight SMTP connection to verify credentials."""
        if not self.enabled:
            return "SMTP not fully configured"
        try:
            with smtplib.SMTP(self.host, self.port, timeout=10) as server:
                server.starttls()
                server.login(self.user, self.password)
            return "ok"
        except Exception as e:
            return f"failed: {e}"
 