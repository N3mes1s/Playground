#!/usr/bin/env python3
# Turn dns_proxy.py's append-only log into an IP-to-hostnames map.
# Output: JSON object {"<ip>": ["<hostname>", ...]}, hostnames sorted
# and deduplicated. Stdout is meant to be embedded between
# DNS_MAP_BEGIN / DNS_MAP_END markers by run_detonation.sh.

import json
import sys

if len(sys.argv) != 2:
    print("usage: dns_log_to_json.py <log_path>", file=sys.stderr)
    sys.exit(2)

ip_to_names = {}
try:
    with open(sys.argv[1]) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 2:
                continue
            ip, qname = parts
            if not ip or not qname:
                continue
            ip_to_names.setdefault(ip, set()).add(qname)
except FileNotFoundError:
    pass

print(json.dumps({k: sorted(v) for k, v in ip_to_names.items()}, indent=2))
