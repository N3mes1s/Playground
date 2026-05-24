# supply-chain-detonation-depot

Detonate an `npm install <pkg>` inside a Firecracker microVM on a
[Depot](https://depot.dev) nested-virt CI runner, with a CO-RE eBPF
probe attached to capture the syscall fingerprint. The first step
toward a per-PR gate that fails on install-time supply-chain
attacks (xz-utils-style, eslint-scope-style) by diffing the
fingerprint of every added/bumped dependency against a committed
baseline.

| Stage | What | Status |
|---|---|---|
| 1 | One package, one kernel, fingerprint to JSON, real `npm install` over the network | **green — 867 ms install, ~15 s CI wall** |
| 2 | Baseline + fingerprint diff with CIDR-based connect-peer matching | **green — gate PASSes when baseline allowlists hold, blocks PR on mutation** |
| 3 | Multi-package matrix from a lockfile diff, per-package PASS/DIFF/NEW/FAIL table | **green — 2/2 PASS, ~30 s wall for two packages** |
| 3 — real world | Same matrix against an actual `npm install axios` lockfile diff (axios + 26 transitive deps, ~1.6 s install) | **green — first-pass NEW blocks PR; after baseline review committed, re-run PASSes** |

Built on top of the FC plumbing patterns from the sibling
[`unikraft-firecracker-depot`](../unikraft-firecracker-depot) (PR #18)
and the CO-RE eBPF stack from
[`ebpf-core-firecracker-depot`](../ebpf-core-firecracker-depot)
(PR #19). The probe shape, static-musl loader pattern, and
multi-stage Dockerfile come directly from PR #19; the new pieces
here are a real `npm install` workload, an Alpine-based cpio
initrd large enough to host node + npm, host-side TAP + iptables
NAT so the guest can reach the npm registry, and a multi-tracepoint
probe (execve + connect, with openat-writes + suspicious-syscalls
planned for Stage 2).

## Quickstart

```bash
curl -L https://depot.dev/install-cli.sh | sh
export PATH=$HOME/.depot/bin:$PATH
export DEPOT_TOKEN='depot_org_...'

cd supply-chain-detonation-depot

# Same Depot project as the sibling experiments (lmpn2xx8kz).
# AEGIS_DEPOT_TOKEN secret already provisioned on the org.

./experiment.sh build      # ~90 s first time, ~30 s cached
./experiment.sh detonate   # ~15 s — Stage 1: npm install + fingerprint JSON
./experiment.sh verify     # ~15 s — Stage 2: detonate + diff against baseline
./experiment.sh matrix     # ~30 s — Stage 3: detonate+verify every package
                           #         added/bumped between two lockfiles
./experiment.sh matrix-rw  # ~15 s — Stage 3 against a REAL `npm install axios`
                           #         (27 packages installed; 1 direct dep
                           #          detonated, transitives implicitly
                           #          covered by the install scripts).
```

`./experiment.sh --help` for the full command list.

## Stage 1 result snapshot

```json
{
  "package": "lodash@4.17.21",
  "exit_status": 0,
  "duration_ms": 867,
  "boot_to_install_ms": 21,
  "events_total": 11,
  "ringbuf_drops": 0,
  "execve_targets": [
    "/usr/local/sbin/npm","/usr/local/bin/npm","/usr/sbin/npm","/usr/bin/npm",
    "/usr/local/sbin/node","/usr/local/bin/node","/usr/sbin/node","/usr/bin/node"
  ],
  "connect_peers": [
    "127.0.0.1:65535",
    "0:0:0:0:0:0:0:1:65535",
    "104.16.3.34:443"
  ]
}
```

Translation:

- `exit_status: 0` — `npm install lodash@4.17.21` actually completed
  inside the FC microVM. Captured guest console also shows
  `added 1 package in 640ms`.
- `execve_targets` — every PATH entry execlp tried while resolving
  `npm` and `node` (busybox-style search). The probe fires at syscall
  entry, so we see all attempts even though only one per binary
  actually exists.
- `connect_peers` — three peers contacted during the install:
  - `127.0.0.1:65535` and `::1:65535`: npm's internal IPC.
  - `104.16.3.34:443`: Cloudflare-fronted `registry.npmjs.org` over
    TLS. This is the real install-time network egress.
- `duration_ms: 867` — wall time from `npm install` fork to exit.

## Stage 2 result snapshot (verify run `0qsgw8l5nq`)

```json
{
  "package": "lodash@4.17.21",
  "verdict": "PASS",
  "fingerprint_verdict": "OK",
  "violations": [],
  "unknown_execve_targets": [],
  "unknown_connect_peers": [],
  "matched_connect_peers": [
    {"peer": "127.0.0.1:65535", "matched_label": "npm internal IPC (v4+v6 localhost)"},
    {"peer": "0:0:0:0:0:0:0:1:65535", "matched_label": "npm internal IPC (v4+v6 localhost)"},
    {"peer": "104.16.6.34:443", "matched_label": "Cloudflare (registry.npmjs.org) — primary v4 range"}
  ]
}
```

Notable: the registry IP this run was `104.16.6.34`; the baseline
was captured with `104.16.3.34`. A naive byte-equality baseline
would have failed here, but our CIDR-based allowlist
(`104.16.0.0/13`, port 443) recognises both as legitimate
Cloudflare-fronted registry endpoints. **That's the whole reason
the baseline format is semantic — Cloudflare rotates IPs inside
its ASN range across requests.**

## Stage 3 result snapshot (matrix run `pjnz4rvgg2`)

```
== Per-package matrix
  PACKAGE                          STATUS WALL_MS    NOTE
  -------                          ------ -------    ----
  lodash@4.17.21                   PASS   10000ms
  ms@2.1.3                         PASS   9000ms
OVERALL: all packages PASS
```

Two paths exercised across two runs:

- **`sp81gmmcnh`** — only `lodash` had a baseline; `ms` got status
  `NEW` and the job exited 1, blocking the PR pending review.
- **`pjnz4rvgg2`** — after committing `baselines/ms@2.1.3.json`,
  re-run goes 2/2 PASS, exit 0.

Both packages produce the same fingerprint shape (pure-JS, only
contacts the npm registry over TLS) because they have no
postinstall scripts. The matrix wall time scales linearly with the
number of added packages (~10 s each); Stage 3 runs sequentially in
a single job but is straightforward to fan out as a true parallel
matrix once that pays off.

## Stage 3 — real-world `npm install axios`

The previous matrix used hand-rolled fixtures. To demonstrate the
gate against a genuinely realistic scenario, the fixtures in
`lockfile-fixtures/realworld-axios/` were generated by literally
running:

```bash
mkdir realproj && cd realproj
npm init -y                              # captured as base.json
npm install --package-lock-only axios    # captured as head.json
```

against the live npm registry on 2026-05-24. The diff brings in
**27 packages** — `axios` plus 26 transitive deps (`form-data`,
`mime-types`, `follow-redirects`, the `es-*`/`has-*` chain).

`lockfile_diff.py --direct` emits only the top-level direct dep
(`axios@1.16.1`). The matrix detonates that one package; the
`npm install axios` running inside the FC guest fork-execs the
install scripts of all 27 packages in a single boot, so the
fingerprint covers the whole transitive tree implicitly. **One
detonation, full coverage — instead of 27 separate detonations.**

### First run — gate blocks (run `c2bp1vhg4k`)

```
== Per-direct-dep matrix (real-world axios install)
  PACKAGE                          STATUS WALL_MS    NOTE
  -------                          ------ -------    ----
  axios@1.16.1                     NEW    10000ms    no baseline — commit one after review
OVERALL: at least one direct dep did not PASS (would block PR)
```

`exit 1`. PR is blocked. The captured fingerprint:

```json
{
  "package": "axios@1.16.1",
  "exit_status": 0,
  "duration_ms": 1634,
  "boot_to_install_ms": 21,
  "events_total": 25,
  "ringbuf_drops": 0,
  "execve_targets": [/* npm + node + PATH-search ENOENTs */],
  "connect_peers": [
    "127.0.0.1:65535",
    "0:0:0:0:0:0:0:1:65535",
    "104.16.8.34:443"
  ]
}
```

25 events vs lodash's 11 — the bigger transitive tree means more
PATH searches and IPC, but the network egress is still just
`registry.npmjs.org` (Cloudflare-fronted). No suspicious execve,
no out-of-tree connect, npm exited cleanly.

### After baseline review — gate passes (run `mbmfdxjn1c`)

A maintainer reads the captured fingerprint, decides it's clean,
commits `baselines/axios@1.16.1.json` (same shape as the
lodash/ms baselines, generalised to Cloudflare CIDR ranges so it
survives IP rotation). Re-run:

```
== Per-direct-dep matrix (real-world axios install)
  PACKAGE                          STATUS WALL_MS    NOTE
  -------                          ------ -------    ----
  axios@1.16.1                     PASS   10000ms
OVERALL: all direct deps PASS
```

`exit 0`. PR can merge.

That's the complete supply-chain-gate workflow end-to-end against a
real-world npm package — block on first encounter, review,
baseline, then green.

## How it works

1. `experiment.sh build` saves
   `registry.depot.dev/lmpn2xx8kz:detonation-runner-latest` containing
   firecracker, a Linux 6.8 vmlinux (Ubuntu `linux-image-virtual`
   extracted to ELF), and a ~73 MB cpio initrd assembled from an
   Alpine root via `apk add --root /rootfs nodejs npm iproute2`. Our
   static-musl loader is dropped on top as `/init`, the BPF object
   as `/probe.bpf.o`. `/etc/resolv.conf` is pre-seeded with public
   DNS.
2. `experiment.sh detonate` pulls that image into a Depot CI job.
3. Inside the container, `run_detonation.sh` brings up a tap device
   with a per-instance IP/MAC, enables IPv4 forwarding, adds an
   iptables MASQUERADE on the container's egress interface, and
   `PUT /network-interfaces/eth0` to Firecracker pointing at the tap.
4. FC boots vmlinux + initrd with `boot_args="… acpi=off -- pkg=… guest_ip=… gw=…"`.
   `acpi=off` is critical: Ubuntu kernels otherwise reserve PCI
   host-bridge windows from ACPI tables, overlapping FC's
   virtio-mmio region at 0xc0001000 and breaking the virtio_net
   probe with EBUSY.
5. Loader (PID 1) mounts /proc /sys /sys/fs/bpf tracefs + tmpfs at
   /install, reads `pkg=` / `guest_ip=` / `gw=` from `/proc/cmdline`,
   configures eth0 via fork+exec of `/sbin/ip`, loads + attaches
   the BPF probe, fork+execs `npm install --prefix=/install <pkg>`,
   polls the ringbuf until the child exits.
6. Loader aggregates dedup'd execve targets + connect peers, prints
   JSON between `DETONATION_BEGIN`/`DETONATION_END` markers,
   `reboot(LINUX_REBOOT_CMD_RESTART)`.
7. Host script awk-extracts the JSON, prints it pretty, exits 0.

## Layout

```
supply-chain-detonation-depot/
├── .depot/workflows/
│   ├── build-runner-image.yml      # build + cache detonation-runner image
│   ├── detonate-one.yml            # Stage 1: boot guest, npm install, fingerprint
│   ├── verify-package.yml          # Stage 2: detonate + diff vs baseline
│   └── matrix-lockfile.yml         # Stage 3: matrix per lockfile-diff package
├── src/
│   ├── probe.bpf.c                 # multi-tracepoint CO-RE BPF probe
│   ├── loader.c                    # static-musl PID 1 / aggregator
│   └── Makefile                    # clang -target bpf + gcc -static
├── infra/docker/
│   └── detonation-runner.Dockerfile  # 5-stage: kernel, BTF, probe+loader,
│                                    # Alpine+node+npm initrd, runtime
├── scripts/
│   ├── run_detonation.sh           # tap+NAT setup, FC REST, JSON parse
│   ├── diff_fingerprint.py         # Stage 2 diff tool, CIDR + loopback matching
│   └── lockfile_diff.py            # Stage 3 helper: extract added/bumped pkgs
├── baselines/                      # per-package expected-fingerprint allowlists
│   ├── lodash@4.17.21.json
│   └── ms@2.1.3.json
├── lockfile-fixtures/              # demo input for Stage 3
│   ├── base.json                   # empty deps
│   └── head.json                   # adds lodash + ms (the matrix target)
├── experiment.sh                   # ./experiment.sh build|detonate|verify|matrix
├── depot.json                      # { "id": "lmpn2xx8kz" }
├── SPEC.md                         # original spec for this experiment
├── .dockerignore
└── README.md
```

## Setup (one-time per Depot org)

```bash
export DEPOT_TOKEN='depot_org_...'

# Reuses the sibling experiments' project (lmpn2xx8kz). Tags are
# scoped per-tag, no clash with helloworld-runner-latest /
# native-runner-latest / ebpf-runner-latest / ebpf-lvh-runner-latest.

depot ci secrets list   # confirm AEGIS_DEPOT_TOKEN is set
```

## What's NOT new about this experiment

- **Runtime tracing of package installs** has been done before:
  Aegis-style sandboxes, Socket Security, Snyk's runtime scanners.
- **Static syscall-fingerprint diffing as an IDS pattern** has
  existed for decades (Forrest et al., 1996).
- **eBPF observers for install/build pipelines** is what Cilium's
  Tetragon does in production at scale.

What is incrementally new is **applying the pattern as a per-PR CI
gate** on a managed CI service: nested-virt makes the per-package
sandbox cheap enough (~15 s wall per package, parallelizable across
packages, cacheable when a package hasn't changed since the last
green baseline) to actually deploy as a blocking check rather than
a separate offline scanner.

## Known gotchas (verified the hard way during this experiment)

1. **`pci=off` is added by FC itself.** If you also pass `pci=nocrs`
   in `boot_args`, FC's later-appended `pci=off` overrides and the
   ACPI-reserved PCI host-bridge windows still overlap the
   virtio-mmio region. Use `acpi=off` instead — it short-circuits
   the resource reservation upstream of PCI parsing.
2. **LVH `complexity-test` and `kernel-images` are different repos.**
   PR #19 documented this; we hit a third twist here: LVH's
   `kernel-images:6.6-main` doesn't ship the `virtio_net` driver,
   so even with a working network the guest never enumerates eth0.
   Switched to Ubuntu's `linux-image-virtual` which is explicitly
   built for VM guests and has the full virtio stack.
3. **Don't set both `npm_config_userconfig` and `npm_config_globalconfig`**
   to the same path. npm bails with `double-loading config "..."
   as "global", previously loaded as "user"` and exits before doing
   any install work. Pick one.
4. **The Linux kernel's `ip=` autoconf boot arg needs `CONFIG_IP_PNP=y`**
   in the kernel. Don't assume it's enabled — Ubuntu's
   `linux-image-virtual` *does* have it but we configure eth0
   manually from the loader anyway since it's only three calls into
   busybox `/sbin/ip` and works against any kernel config.
5. **`apk add --root /rootfs --initdb`** needs the host's apk
   keys (`cp /etc/apk/keys`) plus the host's repositories
   (`cp /etc/apk/repositories`) inside the chroot or it can't
   verify signatures of the packages it's about to install.
6. **The kernel runs `/init` with an empty environment.** Set PATH
   in the loader BEFORE the first `execvp` or every fork+exec fails
   with errno=2 (ENOENT) because the binary lookup has no search
   directories.
7. **The probe needs `BPF_PROBE_READ_USER` for sockaddr** — it's a
   userspace pointer, not kernelspace. Pulling it with
   `bpf_probe_read` (no `_user` suffix) returns garbage.
8. Same FC-on-CI quirks as PR #18 (PTY for guest serial via
   `script -qfec`, x-token Depot Registry auth, container needs
   KVM passthrough + SYS_ADMIN + seccomp/apparmor unconfined +
   NET_ADMIN + NET_RAW + /dev/net/tun for the tap interface).

## Reference

- libbpf-bootstrap: <https://github.com/libbpf/libbpf-bootstrap>
- Firecracker boot-source API:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/actions.md>
- Firecracker networking docs:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/network-setup.md>
- The xz-utils backdoor postmortem (good context for why install-time
  tracing matters):
  <https://research.swtch.com/xz-script>
- Cilium Tetragon (production-grade eBPF observation):
  <https://github.com/cilium/tetragon>
- Sibling PR #18 (FC plumbing patterns reused here):
  <https://github.com/N3mes1s/Playground/pull/18>
- Sibling PR #19 (CO-RE eBPF + LVH integration):
  <https://github.com/N3mes1s/Playground/pull/19>
