"""Thin compatibility layer over FindMy.py.

FindMy.py has moved a few symbols between modules across releases. Import
everything through here so the rest of the code doesn't care which layout the
installed version uses. If FindMy.py isn't installed we raise a friendly error
that tells the user how to fix it, instead of a bare ImportError somewhere deep
in the call stack.
"""

from __future__ import annotations

_INSTALL_HINT = (
    "The 'findmy' package is required.\n"
    "Install it with:  pip install -r requirements.txt\n"
    "(or:  pip install 'findmy>=0.7')"
)

try:
    from findmy import FindMyAccessory, KeyPair
except ImportError as exc:  # pragma: no cover - environment dependent
    raise SystemExit(_INSTALL_HINT) from exc

# AppleAccount lives at the top level in recent releases but used to live under
# findmy.reports.account.
try:
    from findmy import AppleAccount
except ImportError:  # pragma: no cover
    from findmy.reports.account import AppleAccount

# LoginState and the anisette providers are exported from findmy.reports.
try:
    from findmy.reports import (
        LocalAnisetteProvider,
        LoginState,
        RemoteAnisetteProvider,
    )
except ImportError:  # pragma: no cover
    from findmy.reports.state import LoginState  # type: ignore
    from findmy.reports.anisette import (  # type: ignore
        LocalAnisetteProvider,
        RemoteAnisetteProvider,
    )


def is_sms_method(method) -> bool:
    """Best-effort detection of an SMS 2FA method across versions.

    We avoid importing the concrete classes (their names/paths drift) and
    instead duck-type: SMS factors expose a phone number, trusted-device
    factors do not.
    """
    return any(
        getattr(method, attr, None)
        for attr in ("phone_number", "phone_numbers", "phone")
    )


def method_label(method) -> str:
    """Human-readable label for a 2FA method choice."""
    phone = (
        getattr(method, "phone_number", None)
        or getattr(method, "phone", None)
        or ""
    )
    if is_sms_method(method):
        return f"SMS to {phone}".strip()
    return "Trusted Device"


__all__ = [
    "AppleAccount",
    "FindMyAccessory",
    "KeyPair",
    "LoginState",
    "LocalAnisetteProvider",
    "RemoteAnisetteProvider",
    "is_sms_method",
    "method_label",
]
