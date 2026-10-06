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

import logging
import os
import queue
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formataddr
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}
# Pending background emails; further submissions are dropped while it is full.
BACKGROUND_QUEUE_SIZE = 100
# Emails are sent one at a time, so a stalled SMTP server must not block the
# queue for long.
SMTP_TIMEOUT_SECONDS = 30


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
        self._jobs: queue.Queue[Callable[[], list[tuple[str, str, str]]] | None] = (
            queue.Queue(maxsize=BACKGROUND_QUEUE_SIZE)
        )
        self._thread: threading.Thread | None = None
        self._thread_lock = threading.Lock()

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
            with smtplib.SMTP_SSL(
                self.host, self.port, context=context, timeout=SMTP_TIMEOUT_SECONDS
            ) as server:
                self._authenticate_and_send(server, message)
        else:
            with smtplib.SMTP(
                self.host, self.port, timeout=SMTP_TIMEOUT_SECONDS
            ) as server:
                if self.use_tls:
                    server.starttls(context=ssl.create_default_context())
                self._authenticate_and_send(server, message)

    def _authenticate_and_send(
        self, server: smtplib.SMTP, message: EmailMessage
    ) -> None:
        if self.username:
            server.login(self.username, self.password)
        server.send_message(message)

    def send_in_background(
        self, compose: Callable[[], list[tuple[str, str, str]]]
    ) -> bool:
        """Queue ``compose`` to run on the background email thread.

        ``compose`` returns the ``(to_email, subject, body)`` messages to send,
        possibly none. Running it off the request path keeps the response time
        independent of what it does (database lookups, SMTP). Returns False if
        the queue is full or the sender is closed.
        """
        with self._thread_lock:
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="email-sender", daemon=True
                )
                self._thread.start()
            elif not self._thread.is_alive():
                return False
            try:
                self._jobs.put_nowait(compose)
            except queue.Full:
                logger.error("Background email queue is full; dropping an email")
                return False
        return True

    def _run(self) -> None:
        while True:
            compose = self._jobs.get()
            try:
                if compose is None:
                    return
                for message in compose():
                    try:
                        self.send(*message)
                    except Exception:
                        logger.exception("Background email delivery failed")
            except Exception:
                logger.exception("Background email job failed")
            finally:
                self._jobs.task_done()

    def wait_idle(self, timeout: float | None = None) -> bool:
        """Wait until every queued email job has finished; False on timeout."""
        with self._jobs.all_tasks_done:
            return self._jobs.all_tasks_done.wait_for(
                lambda: self._jobs.unfinished_tasks == 0, timeout
            )

    def close(self, timeout: float | None = None) -> None:
        """Finish queued jobs (up to ``timeout``) and stop the background thread."""
        with self._thread_lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                return
            try:
                self._jobs.put(None, timeout=timeout)
            except queue.Full:
                logger.error("Background email queue did not drain before shutdown")
                return
        thread.join(timeout)


__all__ = ["EmailConfigError", "EmailSender"]
