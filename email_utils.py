import os
import smtplib
from email.message import EmailMessage
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def _get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.environ.get(name, default)
    return val


def send_email(to_email: str, subject: str, body: str) -> None:
    smtp_server = _get_env('SMTP_SERVER')
    if not smtp_server:
        raise ValueError('SMTP_SERVER not configured. Please set up environment variables for email sending.')

    smtp_port = int(_get_env('SMTP_PORT', '587'))
    smtp_user = _get_env('SMTP_USER')
    smtp_password = _get_env('SMTP_PASSWORD')
    mail_from = _get_env('MAIL_FROM') or smtp_user or 'no-reply@example.com'
    use_tls = _get_env('MAIL_USE_TLS', 'true').lower() in ('1', 'true', 'yes')

    if not smtp_user or not smtp_password:
        raise ValueError('SMTP_USER and SMTP_PASSWORD must be configured for email sending.')

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = mail_from
    msg['To'] = to_email
    msg.set_content(body)

    if use_tls:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
    else:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)

    if smtp_user and smtp_password:
        server.login(smtp_user, smtp_password)

    server.send_message(msg)
    server.quit()
    print(f"Email successfully sent to {to_email}")
