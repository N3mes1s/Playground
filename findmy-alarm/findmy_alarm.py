#!/usr/bin/env python3
"""findmy-alarm -- a geofence departure alarm for Apple Find My objects on Linux.

Point it at an AirTag / Find My accessory, give it your email, and it emails you
the moment the object moves away from where it started -- like arming a real
alarm. Built on FindMy.py (https://github.com/malmeloo/FindMy.py), which does
the GrandSlam login, key derivation, and report decryption described in
https://zerotistic.blog/posts/find-my-people-linux/.

Commands:
    login    Authenticate to Apple once (handles 2FA) and cache the session.
    status   Fetch each object's current location once and print it.
    watch    Poll on an interval and alarm on departure. This is the daemon.

Quick start (single object, "just pass your email"):
    export FINDMY_APPLE_PASSWORD=...        # your Apple ID / app-specific password
    export FINDMY_SMTP_PASSWORD=...         # email app password for sending
    python findmy_alarm.py login  --email you@gmail.com
    python findmy_alarm.py watch  --email you@gmail.com --plist airtag.plist --radius 150

Multiple objects: use a YAML config (see config.example.yaml):
    python findmy_alarm.py watch --config config.yaml
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import config as config_mod
import findmy_compat as fm
from geofence import GeofenceState, evaluate
from notifier import ConsoleNotifier, EmailNotifier, MultiNotifier


# --------------------------------------------------------------------------- #
# Apple account handling
# --------------------------------------------------------------------------- #

def _anisette(cfg: config_mod.Config):
    if cfg.anisette_server:
        return fm.RemoteAnisetteProvider(cfg.anisette_server)
    return fm.LocalAnisetteProvider()


def load_account(cfg: config_mod.Config):
    """Restore a cached Apple session. Raises if not logged in yet."""
    if not os.path.exists(cfg.store_path):
        raise SystemExit(
            f"No cached session at {cfg.store_path!r}.\n"
            "Run the 'login' command first."
        )
    return fm.AppleAccount.from_json(cfg.store_path)


def do_login(cfg: config_mod.Config) -> int:
    """Interactive Apple login with 2FA, cached to cfg.store_path."""
    if os.path.exists(cfg.store_path):
        print(f"A session already exists at {cfg.store_path!r}.")
        if input("Overwrite and log in again? [y/N] ").strip().lower() != "y":
            return 0

    account = fm.AppleAccount(_anisette(cfg))
    password = cfg.resolved_apple_password()
    if not password:
        password = getpass.getpass(f"Apple ID password for {cfg.apple_id}: ")

    state = account.login(cfg.apple_id, password)

    if state == fm.LoginState.REQUIRE_2FA:
        methods = account.get_2fa_methods()
        print("Two-factor authentication required. Choose a method:")
        for i, method in enumerate(methods):
            print(f"  [{i}] {fm.method_label(method)}")
        idx = int(input("Method number: ").strip())
        method = methods[idx]
        method.request()
        code = input("Enter the 2FA code you received: ").strip()
        method.submit(code)

    save_account(account, cfg.store_path)
    print(f"Logged in. Session cached to {cfg.store_path!r}.")
    return 0


# --------------------------------------------------------------------------- #
# Object sources (accessory .plist or raw key)
# --------------------------------------------------------------------------- #

def build_source(obj: config_mod.ObjectConfig):
    """Turn an ObjectConfig into something fetch_location() understands."""
    if obj.plist:
        if not os.path.exists(obj.plist):
            raise SystemExit(f"plist not found for {obj.name!r}: {obj.plist!r}")
        with open(obj.plist, "rb") as fh:
            return fm.FindMyAccessory.from_plist(fh)
    return fm.KeyPair.from_b64(obj.key_b64)


# --------------------------------------------------------------------------- #
# Secret-file handling
# --------------------------------------------------------------------------- #

def secure_file(path: str) -> None:
    """Restrict a file to owner read/write (0600).

    account.json holds Apple session tokens and alarm_state.json holds your
    home coordinates -- neither should be group/world readable.
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best-effort (e.g. exotic filesystems)


def save_account(account, path: str) -> None:
    """Persist the Apple session and lock the file down."""
    account.to_json(path)
    secure_file(path)


# --------------------------------------------------------------------------- #
# State persistence
# --------------------------------------------------------------------------- #

def load_states(path: str) -> dict[str, GeofenceState]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {name: GeofenceState.from_dict(d) for name, d in raw.items()}


def save_states(path: str, states: dict[str, GeofenceState]) -> None:
    tmp = f"{path}.tmp"
    # Create the temp file with 0600 from the start so coordinates are never
    # briefly world-readable between write and chmod.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({name: s.to_dict() for name, s in states.items()}, fh, indent=2)
    os.replace(tmp, path)
    secure_file(path)


def seed_anchor(obj: config_mod.ObjectConfig, state: GeofenceState) -> None:
    """Apply a configured anchor to fresh state (auto-capture if none given)."""
    if state.anchor is None and obj.anchor:
        from geofence import Anchor

        state.anchor = Anchor.from_dict(obj.anchor)
        state.inside = True


# --------------------------------------------------------------------------- #
# Notifier construction
# --------------------------------------------------------------------------- #

def build_notifier(cfg: config_mod.Config, dry_run: bool):
    channels = []
    if dry_run:
        channels.append(ConsoleNotifier())
        return MultiNotifier(channels)

    smtp_password = cfg.notify.resolved_password()
    if not smtp_password:
        smtp_password = getpass.getpass(
            f"SMTP password for {cfg.notify.smtp_user or cfg.apple_id} "
            "(leave blank for console-only): "
        )
    if not smtp_password:
        print("[warn] no SMTP password -> falling back to console notifications.")
        channels.append(ConsoleNotifier())
        return MultiNotifier(channels)

    email = cfg.notify.smtp_user or cfg.apple_id
    notifier = EmailNotifier.from_email(
        email=email,
        password=smtp_password,
        recipient=cfg.notify_recipient(),
        host=cfg.notify.smtp_host,
        port=cfg.notify.smtp_port,
        use_starttls=cfg.notify.smtp_starttls,
    )
    channels.append(notifier)
    return MultiNotifier(channels)


# --------------------------------------------------------------------------- #
# Fetch + evaluate one object
# --------------------------------------------------------------------------- #

def _maps_link(lat: float, lon: float) -> str:
    return f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"


def fetch_one(account, source):
    """Return the latest LocationReport for a source, or None."""
    return account.fetch_location(source)


def check_object(
    account,
    cfg: config_mod.Config,
    obj: config_mod.ObjectConfig,
    state: GeofenceState,
    notifier,
    source_factory=build_source,
) -> Optional[str]:
    """Fetch one object, update state, alarm if needed. Returns a status line.

    ``source_factory`` is injected so --simulate can swap the Apple-backed
    source for a scripted one while running this exact code path.
    """
    source = source_factory(obj)
    report = fetch_one(account, source)
    if report is None:
        return f"{obj.name}: no location report available yet"

    lat, lon = report.latitude, report.longitude
    ts = report.timestamp
    if isinstance(ts, datetime):
        ts_str = ts.astimezone(timezone.utc).isoformat()
        now = ts.timestamp()
    else:
        ts_str = str(ts)
        now = time.time()

    ev = evaluate(
        state,
        lat,
        lon,
        obj.radius_m,
        now=now,
        renotify_after_s=cfg.renotify_after_s,
    )

    if ev.anchor_captured:
        return (
            f"{obj.name}: anchor captured at {lat:.6f},{lon:.6f} "
            f"(radius {obj.radius_m:.0f} m) -- armed"
        )

    line = (
        f"{obj.name}: {lat:.6f},{lon:.6f} "
        f"({ev.distance_m:.0f} m from anchor, "
        f"{'OUTSIDE' if ev.outside else 'inside'}) @ {ts_str}"
    )

    if ev.should_alarm:
        anchor = state.anchor
        subject = (
            f"[Find My Alarm] {obj.name} is moving "
            f"({ev.distance_m:.0f} m away)"
        )
        body = (
            f"Object '{obj.name}' left its geofence.\n\n"
            f"Distance from anchor: {ev.distance_m:.0f} m "
            f"(radius {obj.radius_m:.0f} m)\n"
            f"Current position:     {lat:.6f}, {lon:.6f}\n"
            f"Anchor position:      {anchor.lat:.6f}, {anchor.lon:.6f}\n"
            f"Accuracy:             ~{report.horizontal_accuracy} m\n"
            f"Report time:          {ts_str}\n"
            f"Map:                  {_maps_link(lat, lon)}\n"
        )
        notifier.notify(subject, body)
        line += "  -> ALARM SENT"

    return line


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def _account_and_source(cfg: config_mod.Config, simulate: bool):
    """Return (account, source_factory) for either real or simulated mode."""
    if simulate:
        from simulate import build_simulated_account, simulated_source

        anchor = cfg.objects[0].anchor if cfg.objects else None
        print("[simulate] no Apple login used; replaying a scripted track.")
        return build_simulated_account(anchor), simulated_source
    return load_account(cfg), build_source


def do_status(cfg: config_mod.Config, dry_run: bool, simulate: bool = False) -> int:
    account, source_factory = _account_and_source(cfg, simulate)
    states = load_states(cfg.state_path)
    notifier = build_notifier(cfg, dry_run=True)  # status never really alarms
    for obj in cfg.objects:
        state = states.setdefault(obj.name, GeofenceState())
        seed_anchor(obj, state)
        try:
            print(check_object(account, cfg, obj, state, notifier, source_factory))
        except Exception as exc:
            print(f"{obj.name}: error: {exc}", file=sys.stderr)
    save_states(cfg.state_path, states)
    if not simulate:
        save_account(account, cfg.store_path)
    return 0


def do_watch(cfg: config_mod.Config, dry_run: bool, simulate: bool = False) -> int:
    account, source_factory = _account_and_source(cfg, simulate)
    notifier = build_notifier(cfg, dry_run=dry_run)
    states = load_states(cfg.state_path)

    print(
        f"Watching {len(cfg.objects)} object(s) every "
        f"{cfg.poll_interval_s:.0f}s. Ctrl-C to stop."
    )
    try:
        while True:
            for obj in cfg.objects:
                state = states.setdefault(obj.name, GeofenceState())
                seed_anchor(obj, state)
                try:
                    line = check_object(
                        account, cfg, obj, state, notifier, source_factory
                    )
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] {line}")
                except Exception as exc:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"{obj.name}: error: {exc}", file=sys.stderr)
            save_states(cfg.state_path, states)
            if not simulate:
                save_account(account, cfg.store_path)
            time.sleep(cfg.poll_interval_s)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        save_states(cfg.state_path, states)
    return 0


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def _add_quick_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--email", help="Your Apple ID email (also default notify address)")
    p.add_argument("--plist", help="Path to accessory .plist (AirTag/Find My object)")
    p.add_argument("--key-b64", dest="key_b64", help="Base64 private key (instead of --plist)")
    p.add_argument("--name", help="Object name (default: find-my-object)")
    p.add_argument("--radius", type=float, default=100.0, help="Geofence radius in meters (default 100)")
    p.add_argument("--anchor", help='Anchor "lat,lon" (default: auto-capture first fix)')
    p.add_argument("--interval", type=float, default=300.0, help="Poll interval seconds (default 300)")
    p.add_argument("--renotify", type=float, default=0.0, help="Re-alert every N seconds while away (0=off)")
    p.add_argument("--notify-to", dest="notify_to", help="Email to alert (default: --email)")
    p.add_argument("--smtp-host", dest="smtp_host", help="SMTP host (default: inferred from email)")
    p.add_argument("--smtp-port", dest="smtp_port", type=int, help="SMTP port (default 587)")
    p.add_argument("--anisette-server", dest="anisette_server", help="Remote anisette server URL")
    p.add_argument("--simulate", action="store_true",
                   help="Replay a scripted track instead of contacting Apple (no login/keys needed)")
    # Also accepted after the subcommand, which is where people naturally type it.
    p.add_argument("--dry-run", dest="dry_run_sub", action="store_true",
                   help="Print alarms to the console instead of emailing")
    p.add_argument("--store-path", dest="store_path", default="account.json", help="Cached session path")
    p.add_argument("--state-path", dest="state_path", default="alarm_state.json", help="Alarm state path")


def build_config(args, require_objects: bool = True) -> config_mod.Config:
    simulate = getattr(args, "simulate", False)
    if getattr(args, "config", None):
        cfg = config_mod.load_yaml(args.config)
    else:
        if not args.email:
            raise SystemExit("Provide --config, or --email plus --plist/--key-b64.")
        # In simulate mode there is no real tag, so invent a key-less object.
        if simulate and not args.plist and not args.key_b64:
            args.key_b64 = None
            cfg = config_mod.from_cli_quickargs(args)
            cfg.objects[0].key_b64 = "SIMULATED"
        else:
            cfg = config_mod.from_cli_quickargs(args)
    if require_objects and not simulate:
        cfg.validate()
    elif require_objects:
        if not cfg.apple_id:
            raise SystemExit("apple_id (your Apple ID email) is required")
    elif not cfg.apple_id:
        raise SystemExit("apple_id (your Apple ID email) is required")
    return cfg


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="findmy_alarm",
        description="Geofence departure alarm for Apple Find My objects.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print alarms to console instead of emailing")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("login", "status", "watch"):
        sp = sub.add_parser(name, help=f"{name} command")
        sp.add_argument("--config", help="Path to YAML config (multi-object)")
        _add_quick_flags(sp)

    args = parser.parse_args(argv)
    # --dry-run is accepted either before or after the subcommand.
    args.dry_run = args.dry_run or getattr(args, "dry_run_sub", False)
    cfg = build_config(args, require_objects=(args.command != "login"))

    if args.command == "login":
        return do_login(cfg)
    if args.command == "status":
        return do_status(cfg, dry_run=args.dry_run, simulate=args.simulate)
    if args.command == "watch":
        return do_watch(cfg, dry_run=args.dry_run, simulate=args.simulate)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
