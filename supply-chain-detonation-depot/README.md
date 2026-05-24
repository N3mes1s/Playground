# supply-chain-detonation-depot

Detonate an `npm install <pkg>` inside a Firecracker microVM on a
[Depot](https://depot.dev) nested-virt CI runner, with a CO-RE eBPF
probe attached to capture the syscall fingerprint. The first step
toward a per-PR gate that fails on install-time supply-chain
attacks (xz-utils-style, eslint-scope-style) by diffing the
fingerprint of every added/bumped dependency against a committed
baseline.

| What | Status |
|---|---|
| Stage 1 — one package, one kernel, fingerprint to JSON, real `npm install` over the network | **green — 867 ms install, ~15 s CI wall (cached)** |
| Stage 2 — baseline + fingerprint diff in CI | not started |
| Stage 3 — multi-package matrix from a lockfile diff | not started |

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
./experiment.sh detonate   # ~15 s — boots Linux guest, runs npm install
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
│   └── detonate-one.yml            # boot guest, npm install, fingerprint
├── src/
│   ├── probe.bpf.c                 # multi-tracepoint CO-RE BPF probe
│   ├── loader.c                    # static-musl PID 1 / aggregator
│   └── Makefile                    # clang -target bpf + gcc -static
├── infra/docker/
│   └── detonation-runner.Dockerfile  # 5-stage: kernel, BTF, probe+loader,
│                                    # Alpine+node+npm initrd, runtime
├── scripts/
│   └── run_detonation.sh           # tap+NAT setup, FC REST, JSON parse
├── baselines/                      # (Stage 2: per-package expected fingerprints)
├── experiment.sh                   # ./experiment.sh detonate
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
