"""Notification back-ends.

Email (SMTP) is the default so you can "just pass your email". The SMTP host
for the common consumer providers is inferred from the address domain, so a
Gmail/iCloud/Outlook/Yahoo user only needs to supply an app password. A console
notifier is always available for dry runs, and the small :class:`Notifier`
interface makes it easy to add webhooks/ntfy/etc. later.
"""

from __future__ import annotations

import smtplib
import ssl
import sys
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Optional, Protocol

# domain -> (host, port, use_starttls)
_SMTP_PROVIDERS = {
    "gmail.com": ("smtp.gmail.com", 587, True),
    "googlemail.com": ("smtp.gmail.com", 587, True),
    "outlook.com": ("smtp.office365.com", 587, True),
    "hotmail.com": ("smtp.office365.com", 587, True),
    "live.com": ("smtp.office365.com", 587, True),
    "yahoo.com": ("smtp.mail.yahoo.com", 587, True),
    "icloud.com": ("smtp.mail.me.com", 587, True),
    "me.com": ("smtp.mail.me.com", 587, True),
    "mac.com": ("smtp.mail.me.com", 587, True),
}


def infer_smtp(email: str) -> Optional[tuple[str, int, bool]]:
    """Return (host, port, starttls) for a known consumer email domain."""
    domain = email.rsplit("@", 1)[-1].lower()
    return _SMTP_PROVIDERS.get(domain)


class Notifier(Protocol):
    """Anything that can deliver an alarm message."""

    def notify(self, subject: str, body: str) -> None: ...


@dataclass
class ConsoleNotifier:
    """Prints to stderr. Handy for --dry-run and local testing."""

    def notify(self, subject: str, body: str) -> None:
        print(f"\n[ALARM] {subject}\n{body}\n", file=sys.stderr)


@dataclass
class EmailNotifier:
    """Sends alarms as plain-text email over SMTP (STARTTLS or SSL)."""

    host: str
    port: int
    username: str
    password: str
    sender: str
    recipient: str
    use_starttls: bool = True

    @classmethod
    def from_email(
        cls,
        *,
        email: str,
        password: str,
        recipient: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        use_starttls: Optional[bool] = None,
    ) -> "EmailNotifier":
        """Build a notifier, inferring SMTP settings from the address domain.

        ``email`` is the sending account (and the default recipient). If the
        domain isn't one of the known providers, ``host`` must be given.
        """
        inferred = infer_smtp(email)
        if host is None:
            if inferred is None:
                raise ValueError(
                    f"Could not infer an SMTP server for {email!r}. "
                    "Pass an explicit smtp host/port in the config."
                )
            host, port, use_starttls = inferred
        else:
            port = port if port is not None else 587
            use_starttls = True if use_starttls is None else use_starttls
        return cls(
            host=host,
            port=int(port),
            username=email,
            password=password,
            sender=email,
            recipient=recipient or email,
            use_starttls=bool(use_starttls),
        )

    def notify(self, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg["Subject"] = subject
        msg.set_content(body)

        context = ssl.create_default_context()
        if self.use_starttls:
            with smtplib.SMTP(self.host, self.port, timeout=30) as server:
                server.starttls(context=context)
                server.login(self.username, self.password)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(self.host, self.port, context=context, timeout=30) as server:
                server.login(self.username, self.password)
                server.send_message(msg)


@dataclass
class MultiNotifier:
    """Fan an alarm out to several notifiers; one failure doesn't block others."""

    notifiers: list

    def notify(self, subject: str, body: str) -> None:
        for n in self.notifiers:
            try:
                n.notify(subject, body)
            except Exception as exc:  # keep going even if one channel fails
                print(f"[warn] notifier {type(n).__name__} failed: {exc}", file=sys.stderr)
