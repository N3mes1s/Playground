"""Configuration model and loading.

Two ways to configure the alarm:

1. A YAML file (``--config config.yaml``) describing your Apple ID and one or
   more objects to watch. Best for watching several tags with different anchors.
2. Quick CLI flags for the single-object case -- "just pass my email":
       watch --email you@gmail.com --plist airtag.plist --radius 150

Secrets are never taken from the command line. The Apple ID password and the
SMTP password come from environment variables (or the config file / an
interactive prompt), so they don't end up in your shell history.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# Environment variables used for secrets.
ENV_APPLE_PASSWORD = "FINDMY_APPLE_PASSWORD"
ENV_SMTP_PASSWORD = "FINDMY_SMTP_PASSWORD"


@dataclass
class ObjectConfig:
    """One Find My object to watch."""

    name: str
    plist: Optional[str] = None       # path to accessory .plist (AirTag etc.)
    key_b64: Optional[str] = None     # OR a base64 private key
    radius_m: float = 100.0
    anchor: Optional[dict] = None     # {"lat":..,"lon":..} or None -> auto-capture

    def validate(self) -> None:
        if not self.plist and not self.key_b64:
            raise ValueError(
                f"object {self.name!r} needs either 'plist' or 'key_b64'"
            )
        if self.plist and self.key_b64:
            raise ValueError(
                f"object {self.name!r} has both 'plist' and 'key_b64'; pick one"
            )


@dataclass
class NotifyConfig:
    """Email delivery settings. Only ``to`` differs from the Apple ID by default."""

    to: Optional[str] = None          # defaults to the Apple ID email
    smtp_host: Optional[str] = None   # inferred from the email domain if omitted
    smtp_port: Optional[int] = None
    smtp_starttls: Optional[bool] = None
    smtp_user: Optional[str] = None   # defaults to the Apple ID email
    smtp_password: Optional[str] = None  # else from env FINDMY_SMTP_PASSWORD

    def resolved_password(self) -> Optional[str]:
        return self.smtp_password or os.environ.get(ENV_SMTP_PASSWORD)


@dataclass
class Config:
    """Top-level configuration."""

    apple_id: str
    objects: list[ObjectConfig] = field(default_factory=list)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    anisette_server: Optional[str] = None
    poll_interval_s: float = 300.0
    renotify_after_s: float = 0.0     # 0 = alarm only on departure edge
    store_path: str = "account.json"  # cached Apple session
    state_path: str = "alarm_state.json"
    apple_password: Optional[str] = None  # prefer env FINDMY_APPLE_PASSWORD

    def validate(self) -> None:
        if not self.apple_id:
            raise ValueError("apple_id (your Apple ID email) is required")
        if not self.objects:
            raise ValueError("at least one object to watch is required")
        for obj in self.objects:
            obj.validate()

    def resolved_apple_password(self) -> Optional[str]:
        return self.apple_password or os.environ.get(ENV_APPLE_PASSWORD)

    def notify_recipient(self) -> str:
        return self.notify.to or self.apple_id


def load_yaml(path: str) -> Config:
    """Load configuration from a YAML file."""
    if yaml is None:
        raise SystemExit("PyYAML is required for --config. pip install pyyaml")
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    notify_raw = raw.get("notify", {}) or {}
    notify = NotifyConfig(
        to=notify_raw.get("to"),
        smtp_host=notify_raw.get("smtp_host"),
        smtp_port=notify_raw.get("smtp_port"),
        smtp_starttls=notify_raw.get("smtp_starttls"),
        smtp_user=notify_raw.get("smtp_user"),
        smtp_password=notify_raw.get("smtp_password"),
    )

    objects = []
    for obj in raw.get("objects", []) or []:
        objects.append(
            ObjectConfig(
                name=obj["name"],
                plist=obj.get("plist"),
                key_b64=obj.get("key_b64"),
                radius_m=float(obj.get("radius_m", 100.0)),
                anchor=obj.get("anchor"),
            )
        )

    cfg = Config(
        apple_id=raw["apple_id"],
        objects=objects,
        notify=notify,
        anisette_server=raw.get("anisette_server"),
        poll_interval_s=float(raw.get("poll_interval_s", 300.0)),
        renotify_after_s=float(raw.get("renotify_after_s", 0.0)),
        store_path=raw.get("store_path", "account.json"),
        state_path=raw.get("state_path", "alarm_state.json"),
        apple_password=raw.get("apple_password"),
    )
    return cfg


def from_cli_quickargs(args) -> Config:
    """Build a single-object config from the quick CLI flags."""
    anchor = None
    if args.anchor:
        lat_s, lon_s = args.anchor.split(",", 1)
        anchor = {"lat": float(lat_s), "lon": float(lon_s)}

    obj = ObjectConfig(
        name=args.name or "find-my-object",
        plist=args.plist,
        key_b64=args.key_b64,
        radius_m=float(args.radius),
        anchor=anchor,
    )
    notify = NotifyConfig(
        to=args.notify_to,
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
    )
    return Config(
        apple_id=args.email,
        objects=[obj],
        notify=notify,
        anisette_server=args.anisette_server,
        poll_interval_s=float(args.interval),
        renotify_after_s=float(args.renotify),
        store_path=args.store_path,
        state_path=args.state_path,
    )
