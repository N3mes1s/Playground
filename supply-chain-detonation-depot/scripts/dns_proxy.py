#!/usr/bin/env python3
# Minimal UDP forwarding DNS proxy. Each guest's UDP/53 traffic is
# REDIRECTed by iptables to this process; we forward to a real
# upstream, parse the A / AAAA records out of the response, and
# log every (ip, hostname) tuple to a file. Userspace post-processes
# the log into an IP-to-hostnames map for hostname-based baseline
# matching in diff_fingerprint.py.
#
# Usage: dns_proxy.py <listen_port> <log_path> [upstream_ip:port]
#
# Append-only log format: "<ip>\t<hostname>\n", one line per
# answered RR. Same IP can appear multiple times across queries
# (e.g. registry.npmjs.org resolves to multiple Cloudflare IPs
# over time); dns_log_to_json.py dedups.

import socket
import struct
import sys

LISTEN_PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
upstream_arg = sys.argv[3] if len(sys.argv) > 3 else "1.1.1.1:53"
uh, _, up = upstream_arg.partition(":")
UPSTREAM = (uh, int(up or "53"))


def parse_qname(data, offset):
    """Decode a DNS name starting at `offset`. Returns (name, next_offset)."""
    parts = []
    jumped = False
    next_offset = offset
    safety = 0
    while True:
        safety += 1
        if safety > 64:
            return "", next_offset
        b = data[offset]
        if b == 0:
            offset += 1
            break
        if b & 0xC0 == 0xC0:  # pointer
            ptr = ((b & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = ptr
            continue
        parts.append(data[offset + 1 : offset + 1 + b].decode("utf-8", "ignore"))
        offset += 1 + b
    return ".".join(parts), (next_offset if jumped else offset)


def parse_response(data, logf):
    if len(data) < 12:
        return
    flags = struct.unpack(">H", data[2:4])[0]
    if (flags & 0x8000) == 0:  # not a response
        return
    qd_count, an_count = struct.unpack(">HH", data[4:8])
    if qd_count == 0 or an_count == 0:
        return
    offset = 12
    qname, offset = parse_qname(data, offset)
    offset += 4  # qtype + qclass
    for _ in range(an_count):
        _, offset = parse_qname(data, offset)
        if offset + 10 > len(data):
            return
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):  # A
            ip = ".".join(str(b) for b in data[offset : offset + 4])
            logf.write(f"{ip}\t{qname}\n")
            logf.flush()
        elif rtype == 28 and rdlen == 16 and offset + 16 <= len(data):  # AAAA
            parts = struct.unpack(">HHHHHHHH", data[offset : offset + 16])
            ip = ":".join(f"{p:x}" for p in parts)
            logf.write(f"{ip}\t{qname}\n")
            logf.flush()
        offset += rdlen


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    logf = open(LOG_PATH, "a", buffering=1)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            continue
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(2.0)
            up.sendto(data, UPSTREAM)
            resp, _ = up.recvfrom(4096)
            up.close()
            try:
                parse_response(resp, logf)
            except Exception:
                pass
            sock.sendto(resp, addr)
        except Exception:
            continue


if __name__ == "__main__":
    main()
