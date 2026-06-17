"""Send transactional email (e.g. password resets) via stdlib ``smtplib``.

Configured entirely through environment variables so no SaaS client library
is required:

- ``FISHTEST_SMTP_HOST``      SMTP relay host (required to enable sending)
- ``FISHTEST_SMTP_PORT``      SMTP port (default 587; 465 implies implicit TLS)
- ``FISHTEST_SMTP_USERNAME``  SMTP auth username (optional)
- ``FISHTEST_SMTP_PASSWORD``  SMTP auth password (optional)
- ``FISHTEST_SMTP_FROM_EMAIL`` From address (required to enable sending)
- ``FISHTEST_SMTP_FROM_NAME``  From display name (default "Fishtest")
- ``FISHTEST_SMTP_USE_TLS``    "true"/"false" STARTTLS on non-465 ports (default true)
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

_TRUTHY = {"1", "true", "yes", "on"}


class EmailConfigError(RuntimeError):
    """Raised when an email send is attempted without a complete configuration."""


class EmailSender:
    def __init__(
        self,
        *,
        host: str = "",
        port: int = 587,
        username: str = "",
        password: str = "",
        from_email: str = "",
        from_name: str = "Fishtest",
        use_tls: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.from_name = from_name
        self.use_tls = use_tls

    @classmethod
    def from_env(cls) -> EmailSender:
        return cls(
            host=os.environ.get("FISHTEST_SMTP_HOST", "").strip(),
            port=int(os.environ.get("FISHTEST_SMTP_PORT", "587")),
            username=os.environ.get("FISHTEST_SMTP_USERNAME", "").strip(),
            password=os.environ.get("FISHTEST_SMTP_PASSWORD", ""),
            from_email=os.environ.get("FISHTEST_SMTP_FROM_EMAIL", "").strip(),
            from_name=os.environ.get("FISHTEST_SMTP_FROM_NAME", "Fishtest").strip(),
            use_tls=os.environ.get("FISHTEST_SMTP_USE_TLS", "true").lower() in _TRUTHY,
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.from_email)

    def _build_message(self, to_email: str, subject: str, body: str) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = formataddr((self.from_name, self.from_email))
        message["To"] = to_email
        message.set_content(body)
        return message

    def send(self, to_email: str, subject: str, body: str) -> None:
        """Send a plain-text email; raises EmailConfigError if not configured."""
        if not self.is_configured:
            raise EmailConfigError("email sending is not configured")

        message = self._build_message(to_email, subject, body)

        if self.port == 465:  # noqa: PLR2004 - implicit TLS port
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.host, self.port, context=context) as server:
                self._authenticate_and_send(server, message)
        else:
            with smtplib.SMTP(self.host, self.port) as server:
                if self.use_tls:
                    server.starttls(context=ssl.create_default_context())
                self._authenticate_and_send(server, message)

    def _authenticate_and_send(
        self, server: smtplib.SMTP, message: EmailMessage
    ) -> None:
        if self.username:
            server.login(self.username, self.password)
        server.send_message(message)


__all__ = ["EmailConfigError", "EmailSender"]
