# Experiment — per-PR supply-chain detonation gate using FC + CO-RE eBPF on Depot CI

## Context

Modern npm / PyPI / Cargo supply-chain attacks act at **install
time**, not run time:

- xz-utils 5.6.0 (CVE-2024-3094) — backdoor activated by the build
  script
- eslint-scope (2018), event-stream (2018), ua-parser-js (2021), the
  ongoing wave of typosquat malware on PyPI / npm — all run their
  payload during `pip install` / `npm install`, before anything is
  even imported by the dependent project.

Static scanners (Socket, Snyk, Phylum) match patterns; package
signing catches "different author signed it"; SBOM catches "this
package is vulnerable to known CVE." None of them observe **what an
install actually does** in isolation, on every PR.

The two sibling experiments in this repo make that gate cheap
enough to actually deploy:

- **PR #18** (`unikraft-firecracker-depot/`) proves we can boot a
  microVM under Firecracker on a Depot CI runner via the FC REST
  API, capture serial via a PTY workaround, ship a cached runner
  image to the Depot Registry.
- **PR #19** (`ebpf-core-firecracker-depot/`) proves we can build a
  CO-RE eBPF probe, load it inside a guest Linux kernel under FC,
  read `task_struct` fields via `BPF_CORE_READ`, capture events on
  a ringbuf, emit a JSON verdict over ttyS0. It also integrates
  LVH (`lvh kernels pull`) so kernel-fetch is one line of
  Dockerfile.

This experiment plugs those two pieces together: the FC plumbing,
the kernel ABI portability, and the BPF tracing — but with a real
workload (`npm install <pkg>`) inside the guest instead of a
fork+execve toy. The output is a per-package syscall fingerprint
that a host-side diff can gate on.

Branches to read first (use `mcp__github__get_file_contents` against
`n3mes1s/playground`):

- `claude/unikraft-firecracker-depot-Lfwst` (PR #18) — read
  `unikraft-firecracker-depot/scripts/run_unikernel.sh` and
  `unikraft-firecracker-depot/experiment.sh` for the wrapper shape.
- `claude/ebpf-core-firecracker-depot-prep` (PR #19) — read
  `ebpf-core-firecracker-depot/src/probe.bpf.c`,
  `ebpf-core-firecracker-depot/src/loader.c`,
  `ebpf-core-firecracker-depot/infra/docker/ebpf-runner-lvh.Dockerfile`,
  `ebpf-core-firecracker-depot/scripts/run_linux_guest.sh`. **This
  is the closest sibling — your starting point.**

## Goal

A CI gate that, given a `package-lock.json` (or pip / cargo lockfile)
diff in a PR:

1. Enumerates added or bumped packages from the diff.
2. For each one, spawns a fresh FC microVM with a known Linux
   kernel + a rootfs containing `npm` (or `pip` / `cargo`) + a
   CO-RE eBPF tracer.
3. Runs `npm install <pkg>@<exact-version>` inside the guest.
4. Captures a syscall fingerprint:
   - set of `connect()` peers (network egress)
   - set of `openat()` writes outside the install root
   - set of `execve()` targets observed during install
   - count of suspicious syscalls (`ptrace`, `chmod` on system
     paths, `unlink` outside install root, etc.)
5. Emits the fingerprint as JSON over the guest's serial console.
6. On the host: diff each package's fingerprint against a baseline
   (committed to the repo as `baselines/<package>@<version>.json`).
7. Fail the PR if any package's fingerprint mutates without an
   explanation in the baseline; pass if every package matches its
   baseline OR if the baseline is missing AND the fingerprint
   looks unsuspicious (no execve of `/bin/sh`, no network outside
   the package registry, no write to home directory, etc.).

## Scope — three stages

Don't move on until each stage is green.

### Stage 1 — one package, one kernel, fingerprint to JSON

- Boot one Linux guest (kernel from `lvh kernels pull 6.6-main` —
  PR #19's working setup).
- Inside the guest, `npm install lodash@4.17.21` to a tmpfs.
- BPF probe collects the syscall fingerprint described above.
- Loader emits the fingerprint JSON between
  `DETONATION_BEGIN`/`DETONATION_END` markers, halts.
- Host-side: print the JSON, exit 0.

### Stage 2 — baseline + diff

- Commit `baselines/lodash@4.17.21.json` with the fingerprint
  observed in Stage 1.
- Run Stage 1 again, diff fingerprint against the committed
  baseline. Exit 0 if identical, non-zero if not.
- Bonus: implement a "fuzzy" diff — set membership, not byte equality
  (sorted-set comparison of `connect()` peers, etc.). Real installs
  have non-deterministic syscall counts.

### Stage 3 — multi-package matrix from a lockfile diff

- Helper that reads two lockfiles (HEAD vs base of the PR), produces
  the set of added/bumped packages.
- Loop over each package, run Stage 2 per package.
- Aggregate: per-package PASS / NEW / DIFF / FAIL, plus an "OVERALL"
  exit code.
- Optional: parallelise — Depot CI can spawn N jobs concurrently.

## Pattern to mirror (verbatim where it makes sense)

Most of the structure is already in PR #19. Reuse:

1. **Workflow shape**: `<experiment>/.depot/workflows/<verb>-<noun>.yml`
   with `defaults: { run: { shell: bash } }`, the same `container:`
   block (image: `registry.depot.dev/lmpn2xx8kz:<tag>`, KVM
   passthrough, x-token auth).
2. **Multi-stage Dockerfile**: stage A `lvh kernels pull <ver>`;
   stage B build the probe + loader (`clang -target bpf`,
   `gcc -static`); stage C build the initrd; stage D final runtime
   image with FC + util-linux + the kernel ELF + initrd + boot
   script.
3. **`scripts/run_linux_guest.sh`**: copy from PR #19 verbatim and
   adjust the marker grep (`DETONATION_END` instead of
   `BPF_RESULT_END`).
4. **`experiment.sh`**: wrapper around `depot ci run`, mirroring
   PR #19's structure: subcommands `build`, `detonate <pkg>`,
   `matrix <lockfile-diff>`, `--help`.

## What's different from PR #19

- **The loader does more.** PR #19's loader fires one `execve` and
  collects one event. Here it spawns `npm install <pkg>` and runs
  the BPF probe across the entire install lifecycle. Mount tmpfs
  at the install root so the FS state is observable and clean
  between runs.
- **The initrd needs npm.** PR #19's initrd has only the static-musl
  loader + `probe.bpf.o`. Here you need `node` + `npm` available.
  Two options:
  - **Static-musl Node** (preferred) — there are static Node builds
    from `nodejs/node-builder` or unofficial `node-ci-amd64-static`.
    Or build one once with `--fully-static`. Embed in the initrd.
  - **Real Linux rootfs (ext4)** — switch from cpio initrd to an
    ext4 disk image with full Debian/Alpine. FC supports both. The
    LVH `kernel-images` repo also ships base rootfs images you can
    reuse.
- **The probe captures more syscalls.** Beyond `sys_enter_execve`,
  attach to:
  - `tp/syscalls/sys_enter_connect` for network egress
  - `tp/syscalls/sys_enter_openat` filtered for `O_WRONLY`/
    `O_CREAT` paths outside the install root
  - `tp/syscalls/sys_enter_execve` for child processes
  - `tp/syscalls/sys_enter_ptrace`, `_chmod`, `_unlink`,
    `_unlinkat` for anything suspicious
- **The fingerprint format is structured, not a single event.**
  Aggregate in the loader's userspace before emitting; emit a JSON
  object with sorted sets of observations.
- **Baseline diff is host-side.** Loader emits raw data; host's
  `experiment.sh` does the comparison against
  `baselines/<pkg>@<ver>.json`.

## Required setup

Same as PR #19. Reuse:

- Depot project `lmpn2xx8kz` (`depot.json`).
- `AEGIS_DEPOT_TOKEN` already provisioned on the org.
- `x-token` username for Depot Registry pulls.

```bash
export DEPOT_TOKEN='depot_org_...'
```

## Concrete layout

```
supply-chain-detonation-depot/
├── .depot/workflows/
│   ├── build-runner-image.yml        # bake kernel + node + tracer + initrd
│   ├── detonate-one.yml              # stage 1+2: one pkg, fingerprint, diff
│   └── matrix-lockfile-diff.yml      # stage 3: N packages from lockfile diff
├── src/
│   ├── probe.bpf.c                   # multi-tracepoint BPF probe
│   ├── loader.c                      # spawn npm install, aggregate, emit JSON
│   └── Makefile                      # same shape as PR #19
├── infra/docker/
│   └── detonation-runner.Dockerfile  # FC + kernel + node + tracer + initrd
├── scripts/
│   ├── run_detonation.sh             # adapted from run_linux_guest.sh
│   ├── diff_fingerprint.sh           # host-side diff vs baselines/
│   └── lockfile_diff.sh              # extract added/bumped pkgs from git diff
├── baselines/
│   └── lodash@4.17.21.json           # committed expected fingerprint
├── experiment.sh                     # ./experiment.sh detonate lodash@...
├── depot.json
├── SPEC.md
└── README.md
```

## Probe — multi-tracepoint outline

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Event types emitted on a single ringbuf so userspace can aggregate.
enum event_type {
    EV_EXECVE = 1,
    EV_CONNECT = 2,
    EV_OPENAT_WRITE = 3,
    EV_SUSPICIOUS = 4,   // ptrace, chmod /usr/, unlink outside install root
};

struct event {
    __u32 type;
    __u32 pid;
    char  comm[16];
    union {
        struct { char path[256]; } execve;
        struct { __u32 family; __u32 port; __u8 addr[16]; } connect;
        struct { char path[256]; __u32 flags; } openat;
        struct { __u32 syscall_nr; char detail[128]; } suspicious;
    };
};

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<20); } events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")  int on_execve (void *ctx) { /* emit EV_EXECVE  */ return 0; }
SEC("tp/syscalls/sys_enter_connect") int on_connect(void *ctx) { /* emit EV_CONNECT */ return 0; }
SEC("tp/syscalls/sys_enter_openat")  int on_openat (void *ctx) { /* emit EV_OPENAT_WRITE if O_WRONLY|O_CREAT and path outside /install */ return 0; }
SEC("tp/syscalls/sys_enter_ptrace")  int on_ptrace (void *ctx) { /* emit EV_SUSPICIOUS */ return 0; }
// ... etc for chmod, unlink, unlinkat
```

Read the tracepoint args with `BPF_CORE_READ` so the probe stays
CO-RE-portable (same compiled `.bpf.o` works across kernel versions).

## Loader outline

Spawn `npm install <pkg>` from PID 1, attach probes BEFORE the
fork, ringbuf-poll until the npm process exits, then aggregate
the events into a fingerprint:

```c
// pseudocode
attach_probes(obj);

pid_t npm_pid = fork();
if (npm_pid == 0) {
    setenv("HOME", "/install", 1);
    chdir("/install");
    execvp("/usr/bin/npm", (char *[]){"npm", "install", "--prefix=/install", argv[1], NULL});
    _exit(127);
}

// In parent: ringbuf__poll until child exits
while (waitpid(npm_pid, &status, WNOHANG) == 0) {
    ring_buffer__poll(rb, 50);
}
ring_buffer__poll(rb, 200);  // drain

emit_fingerprint_json();
sync(); sleep(1);
reboot(LINUX_REBOOT_CMD_RESTART);
```

Aggregation: maintain a few in-memory sets/maps (e.g. `khash`
single-file header, or plain sorted arrays for small N) for
unique `connect()` peers, unique `execve()` paths, etc. Emit:

```json
{
  "package": "lodash@4.17.21",
  "exit_status": 0,
  "duration_ms": 1840,
  "events_total": 12453,
  "connect_peers": ["registry.npmjs.org:443"],
  "execve_targets": ["/usr/bin/npm", "/usr/bin/node", "/usr/bin/tar"],
  "openat_writes_outside_install": [],
  "suspicious": []
}
```

## Stage 1 acceptance

- CI wall **< 60 s** (image cached, one package).
- Loader emits `DETONATION_BEGIN`/`DETONATION_END` with a JSON
  fingerprint of a real lodash install.
- `connect_peers` contains exactly `registry.npmjs.org:443`.
- `suspicious` is empty.
- FC `exit_code=0`.

## Stage 2 acceptance

- `baselines/lodash@4.17.21.json` committed.
- Re-running on identical input exits 0 with no diff reported.
- Synthetic test: append a `connect_peers` entry to the baseline,
  re-run, expect non-zero exit with a diff explaining the missing
  peer.

## Stage 3 acceptance

- A test PR adds `lodash@4.17.21` and `safe-stable-stringify@2.5.0`
  to a sample lockfile. Workflow detects both, detonates each, and
  reports a 2-row table. Both PASS.
- A synthetic malicious package (write your own fake one with a
  `postinstall` that does `curl evil.example.com`) fails the gate
  with `connect_peers` containing the bad host. The error message
  on the PR cites the bad observation.

## Gotchas to expect (in addition to PRs #18 and #19)

1. **`npm install` writes EVERYWHERE.** Default `~/.npm` cache, lock
   files, package.json. You'll see many `openat(O_WRONLY)` events
   outside the install dir unless you set `npm_config_cache=/install/.npm-cache`
   and `npm_config_prefix=/install` carefully.
2. **DNS lookups happen.** `connect()` to port 53. Either don't
   resolve (use IPs) or whitelist port 53 in the fingerprint format.
3. **Static Node is annoying to acquire.** `node` is dynamically
   linked to glibc by default. Static builds exist but are
   second-class. Easier path: ship a full rootfs (alpine or
   debian-slim ext4 image) and ditch the cpio initrd — FC supports
   both as long as the disk has an `init`.
4. **BPF ringbuf can overflow** during a busy `npm install`. Size
   the ringbuf to ≥ 1 MiB and check `bpf_ringbuf_reserve` return
   value; if NULL, emit a single "ringbuf overflow" suspicious
   event so the verdict isn't silently wrong.
5. **Baselines need a story for non-determinism.** Timestamps,
   PIDs, and event ordering vary between runs. The fingerprint
   format must intentionally hash *kinds* of observations
   (sorted set membership), not raw event streams.
6. **`tp/syscalls/sys_enter_openat` fires constantly.** Filter
   inside the BPF program (drop paths starting with the install
   root, drop reads, drop `/proc/*`, drop `/sys/*`) or the
   ringbuf will overflow within milliseconds.
7. **Network "where does the install reach out to"** must be
   captured at `connect()` entry — by `accept()` time the kernel
   has already done DNS + might have skipped CONNECT for some
   protocols. `inet_sock_set_state` or `sock_*` kprobes are an
   alternative if `connect` doesn't catch everything.

## What is NOT new about this (read PR #19's "What is NOT new" first)

- Runtime tracing of package installs has been done before:
  Aegis (the spec the parent experiments inherit from), Snyk's
  CI checks, Socket Security's behaviour scanner, Phylum's
  install analysis. The framing as a **per-PR gate built on cheap
  managed-CI nested-virt** is what's incrementally new.
- Static-syscall-fingerprint diffing is a well-known IDS pattern;
  what's specific here is applying it to lockfile changes as a CI
  gate.

## Resources

- libbpf-bootstrap (more tracepoint examples):
  <https://github.com/libbpf/libbpf-bootstrap>
- Cilium's tetragon — a production policy-enforcing eBPF observer
  with a richer event model than the toy probe in PR #19:
  <https://github.com/cilium/tetragon>
- The xz-utils backdoor postmortem (good reading for what install-
  time attacks actually look like):
  <https://research.swtch.com/xz-script>
- PR #18 (FC plumbing): <https://github.com/N3mes1s/Playground/pull/18>
- PR #19 (CO-RE eBPF + LVH): <https://github.com/N3mes1s/Playground/pull/19>
- PR #18 branch (for direct file access):
  <https://github.com/N3mes1s/Playground/tree/claude/unikraft-firecracker-depot-Lfwst>
- PR #19 branch (closest sibling — start here):
  <https://github.com/N3mes1s/Playground/tree/claude/ebpf-core-firecracker-depot-prep>
