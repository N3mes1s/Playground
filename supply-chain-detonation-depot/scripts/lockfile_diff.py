#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Extract added or version-bumped packages between two
# `package-lock.json` files (npm lockfile v3).
#
# Usage: lockfile_diff.py [--direct] <base.json> <head.json>
#
# Modes:
#   default     emit every node_modules/<...> entry that differs
#               (direct + transitive — broad coverage, expensive matrix).
#   --direct    emit only the top-level direct dependencies from
#               packages[""].{dependencies,devDependencies,...}.
#               This is what you want for a per-PR gate: detonating
#               `npm install axios` exercises axios + all its
#               transitives in one guest run, so the fingerprint
#               implicitly covers the whole tree without needing a
#               detonation per transitive.
#
# Output: one "<name>@<version>" per line, sorted.

import json
import sys


def packages_from_lockfile_all(path):
    """All node_modules/<...> entries, keyed by their bare package name."""
    data = json.load(open(path))
    out = {}
    for key, val in (data.get("packages") or {}).items():
        if not key.startswith("node_modules/"):
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        version = val.get("version")
        if version:
            out[name] = version
    return out


def packages_from_lockfile_direct(path):
    """
    Direct deps only — the ones the project explicitly added to
    package.json. Read from packages[""].dependencies +
    devDependencies + peerDependencies + optionalDependencies. The
    version comes from the resolved node_modules/<name> entry so we
    pin to the actual locked version, not the version-range spec.
    """
    data = json.load(open(path))
    root = (data.get("packages") or {}).get("", {}) or {}
    direct_names = set()
    for field in ("dependencies", "devDependencies",
                  "peerDependencies", "optionalDependencies"):
        for name in (root.get(field) or {}).keys():
            direct_names.add(name)

    all_pkgs = packages_from_lockfile_all(path)
    return {name: ver for name, ver in all_pkgs.items()
            if name in direct_names}


def main():
    args = sys.argv[1:]
    direct = False
    if args and args[0] == "--direct":
        direct = True
        args = args[1:]
    if len(args) != 2:
        print("usage: lockfile_diff.py [--direct] <base.json> <head.json>",
              file=sys.stderr)
        sys.exit(2)

    fn = packages_from_lockfile_direct if direct else packages_from_lockfile_all
    base = fn(args[0])
    head = fn(args[1])

    added = []
    for name, version in head.items():
        if name not in base or base[name] != version:
            added.append(f"{name}@{version}")

    for a in sorted(added):
        print(a)


if __name__ == "__main__":
    main()

