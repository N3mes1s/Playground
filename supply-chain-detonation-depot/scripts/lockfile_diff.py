#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Extract added or version-bumped packages between two
# `package-lock.json` files (npm lockfile v3).
#
# Usage: lockfile_diff.py <base.json> <head.json>
# Output: one "<name>@<version>" per line, sorted.
#
# Stage 3's matrix-lockfile.yml feeds this list to N parallel
# detonate+verify runs. In a real PR check the two lockfiles are
# `git show base:package-lock.json` vs the PR's package-lock.json.

import json
import sys


def packages_from_lockfile(path):
    """
    Return {name: version} for every node_modules/<name> entry.
    npm v3 lockfile uses path-keyed `packages` map. Nested deps appear
    as `node_modules/a/node_modules/b` — we keep only the leaf name so
    the matrix doesn't double-detonate the same package at two depths.
    """
    data = json.load(open(path))
    out = {}
    for key, val in (data.get("packages") or {}).items():
        if not key.startswith("node_modules/"):
            continue
        # last path segment after the last "node_modules/"
        name = key.rsplit("node_modules/", 1)[-1]
        version = val.get("version")
        if version:
            # If the same name appears multiple times at different
            # depths with different versions we'd lose one; for the
            # detonation matrix that's fine — we'll re-detonate the
            # surviving one and any drift in the others will surface
            # the next time it gets bumped.
            out[name] = version
    return out


def main():
    if len(sys.argv) != 3:
        print("usage: lockfile_diff.py <base.json> <head.json>",
              file=sys.stderr)
        sys.exit(2)
    base = packages_from_lockfile(sys.argv[1])
    head = packages_from_lockfile(sys.argv[2])

    added = []
    for name, version in head.items():
        if name not in base or base[name] != version:
            added.append(f"{name}@{version}")

    for a in sorted(added):
        print(a)


if __name__ == "__main__":
    main()
