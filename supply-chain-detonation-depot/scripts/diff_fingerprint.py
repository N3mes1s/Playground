#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Diff a per-package detonation fingerprint against a committed
# baseline. Used by the verify-package.yml workflow to gate a PR.
#
# Usage: diff_fingerprint.py <fingerprint.json> <baseline.json>
#
# Exit codes:
#   0  PASS — every observed execve target / connect peer matches
#             an entry in the baseline allowlists
#   1  DIFF — at least one observation isn't covered by the baseline.
#             Report goes to stdout as JSON; CI fails the job.
#   2  argv / parse error
#
# Baseline format (see baselines/lodash@4.17.21.json for a real one):
#   {
#     "package": "lodash@4.17.21",
#     "verdict_required": "OK",
#     "execve_targets_allowlist": ["/usr/bin/npm", "/usr/bin/node", ...],
#     "connect_peers_allowlist": [
#       {"kind": "loopback", "label": "npm IPC"},
#       {"kind": "cidr", "range": "104.16.0.0/13", "port": 443,
#        "label": "Cloudflare (registry.npmjs.org)"}
#     ],
#     "openat_writes_allowlist": [
#       {"kind": "exact",  "path": "/dev/null"},
#       {"kind": "prefix", "path": "/tmp/v8-compile-cache-"}
#     ]
#   }
#
# Connect-peer allowlist entry kinds:
#   - loopback: matches 127.0.0.0/8 + ::1, any port
#   - cidr:     matches `range` (v4 or v6), optionally restricted to `port`
#   - exact:    matches a specific `ip` + optional `port`
#
# Openat-writes allowlist entry kinds:
#   - exact:  full path equality
#   - prefix: path startswith `path`
#
# If a fingerprint emits `openat_writes` and the baseline has no
# `openat_writes_allowlist` (or an empty one), every captured write
# is unknown — that's the right default ("no writes outside the
# install root are expected unless you've explicitly approved them").

import ipaddress
import json
import sys


def parse_peer(s):
    """
    Parse our loader's "<ip>:<port>" format. IPv6 is emitted in expanded
    form without brackets (e.g. "0:0:0:0:0:0:0:1:65535"), so the LAST
    colon is the port separator — use rpartition.
    """
    if not s or ":" not in s:
        return None, None
    ip_s, _, port_s = s.rpartition(":")
    try:
        ip = ipaddress.ip_address(ip_s)
        port = int(port_s)
    except (ValueError, TypeError):
        return None, None
    return ip, port


def match_peer(ip, port, allowlist):
    """Return label of the first matching allowlist entry, or None."""
    for entry in allowlist:
        kind = entry.get("kind")
        if kind == "loopback":
            if ip.is_loopback:
                return entry.get("label", "loopback")
        elif kind == "cidr":
            try:
                net = ipaddress.ip_network(entry["range"], strict=False)
            except (ValueError, KeyError):
                continue
            if ip.version != net.version:
                continue
            if ip in net:
                ep = entry.get("port")
                if ep is None or ep == port:
                    return entry.get("label", str(net))
        elif kind == "exact":
            if str(ip) == entry.get("ip"):
                ep = entry.get("port")
                if ep is None or ep == port:
                    return entry.get("label", f"{ip}:{port}")
    return None


def match_openat(path, allowlist):
    """Return label of the first matching allowlist entry, or None."""
    for entry in allowlist:
        kind = entry.get("kind")
        if kind == "exact":
            if path == entry.get("path"):
                return entry.get("label", path)
        elif kind == "prefix":
            p = entry.get("path", "")
            if p and path.startswith(p):
                return entry.get("label", p)
    return None


def main():
    if len(sys.argv) != 3:
        print("usage: diff_fingerprint.py <fingerprint.json> <baseline.json>",
              file=sys.stderr)
        sys.exit(2)

    try:
        fp = json.load(open(sys.argv[1]))
    except Exception as e:
        print(f"fingerprint parse failed: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        bl = json.load(open(sys.argv[2]))
    except Exception as e:
        print(f"baseline parse failed: {e}", file=sys.stderr)
        sys.exit(2)

    violations = []
    unknown_execve = []
    unknown_connect = []
    matched_connect = []  # (peer_string, label)
    unknown_openat = []
    matched_openat = []   # (path, label)

    # Verdict check
    required = bl.get("verdict_required")
    actual = fp.get("verdict")
    if required and actual != required:
        violations.append(
            f"verdict={actual!r} but baseline requires {required!r}"
        )

    # execve targets
    allow_execve = set(bl.get("execve_targets_allowlist", []))
    for t in fp.get("execve_targets", []):
        if t not in allow_execve:
            unknown_execve.append(t)

    # connect peers
    allow_connect = bl.get("connect_peers_allowlist", [])
    for p in fp.get("connect_peers", []):
        ip, port = parse_peer(p)
        if ip is None:
            unknown_connect.append(f"{p} (unparseable)")
            continue
        label = match_peer(ip, port, allow_connect)
        if label is None:
            unknown_connect.append(p)
        else:
            matched_connect.append({"peer": p, "matched_label": label})

    # openat writes outside the install root
    allow_openat = bl.get("openat_writes_allowlist", [])
    for path in fp.get("openat_writes", []):
        label = match_openat(path, allow_openat)
        if label is None:
            unknown_openat.append(path)
        else:
            matched_openat.append({"path": path, "matched_label": label})

    verdict = "PASS"
    if violations or unknown_execve or unknown_connect or unknown_openat:
        verdict = "DIFF"

    report = {
        "package": fp.get("package"),
        "verdict": verdict,
        "fingerprint_verdict": actual,
        "violations": violations,
        "unknown_execve_targets": unknown_execve,
        "unknown_connect_peers": unknown_connect,
        "matched_connect_peers": matched_connect,
        "unknown_openat_writes": unknown_openat,
        "matched_openat_writes": matched_openat,
        "events_total": fp.get("events_total"),
        "ringbuf_drops": fp.get("ringbuf_drops"),
    }
    print(json.dumps(report, indent=2))
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
