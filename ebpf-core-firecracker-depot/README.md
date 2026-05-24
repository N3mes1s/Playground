# ebpf-core-firecracker-depot

Load a CO-RE (Compile Once, Run Everywhere) eBPF probe inside a real
Linux microVM under Firecracker on a [Depot](https://depot.dev)
nested-virt CI runner. The point: validate that the probe's
`BPF_CORE_READ` relocations resolve against the guest kernel's BTF —
the kind of test that used to require bare-metal CI.

| What | Status |
|---|---|
| Stage 1 — single kernel, single probe, end-to-end CO-RE load + event capture | **green — 14 ms to libbpf-load, sub-ms to first event, ~15 s CI wall (cached)** |
| Stage 2 — kernel matrix (5.15 / 6.1 / 6.8), hand-rolled kernel-fetch | **green — 3/3 OK, ~45 s CI wall** |
| Stage 2 (alt) — kernel matrix via Cilium's `lvh kernels pull` (5.15 / 6.1 / 6.6 / 6.12) | **green — 4/4 OK, ~45 s CI wall** |

Built on top of the FC plumbing patterns from the sibling
[`unikraft-firecracker-depot`](../unikraft-firecracker-depot) experiment
(PR #18) — the PTY-for-FC-stdout trick, the `x-token` Depot Registry
auth, the multi-stage Dockerfile-then-runner-image pattern, all of it.

## Quickstart

```bash
curl -L https://depot.dev/install-cli.sh | sh
export PATH=$HOME/.depot/bin:$PATH
export DEPOT_TOKEN='depot_org_...'

cd ebpf-core-firecracker-depot

# One-time per Depot org. depot.json already points at project
# lmpn2xx8kz (shared with the sibling experiment). AEGIS_DEPOT_TOKEN
# is already provisioned on the org.

./experiment.sh build       # ~90 s first time, ~30 s cached
./experiment.sh boot        # ~15 s — boots Linux 6.8 guest, loads probe, prints JSON
./experiment.sh matrix      # ~45 s — boots 5.15 + 6.1 + 6.8 (hand-rolled kernels)

# Same probe, but the kernel ELFs come from lvh kernels pull instead
# of our Ubuntu-apt-and-extract-vmlinux dance:
./experiment.sh build-lvh   # ~90 s first time, ~30 s cached
./experiment.sh matrix-lvh  # ~45 s — 5.15 + 6.1 + 6.6 + 6.12 via lvh
```

`./experiment.sh --help` for the full command list.

## Stage 1 result snapshot

```
--- guest serial ---
[    0.000000] Command line: console=ttyS0 reboot=k panic=1 root=/dev/ram0 rw pci=off
[    0.023686] Kernel command line: console=ttyS0 reboot=k panic=1 ...
[    0.609691] Loaded X.509 cert 'Canonical Ltd. Kernel Module Signing 2025 Kmod ...'
BPF_RESULT_BEGIN
{"verdict":"OK","events":1,"pid":75,"ppid":1,"comm":"init",
 "core_relocs":"resolved","boot_to_load_ms":14,"load_to_event_ms":0}
BPF_RESULT_END
Firecracker exiting successfully. exit_code=0
```

Translation:

- `core_relocs:"resolved"` — libbpf successfully resolved every
  `BPF_CORE_READ` in `probe.bpf.c` against the kernel's BTF at load
  time. CO-RE guarantee made empirical.
- `events:1` — the probe fired on the loader's own `execve` (we
  intentionally exec a path that doesn't exist; the tracepoint is
  at syscall entry, before the lookup fails).
- `pid:75, ppid:1, comm:"init"` — fields read from
  `task_struct.{pid, real_parent.pid, comm}` via CO-RE. PID 1 is
  the loader; PID 75 is the forked child whose `execve()` triggered
  the probe.
- `boot_to_load_ms:14` — wall time from PID 1 starting to
  `bpf_object__load()` returning success. Essentially the
  KVM-accelerated kernel boot plus libbpf's relocation pass.

## Stage 2 result snapshot — hand-rolled kernel fetch

```
== Matrix summary
  KERNEL     STATUS       BOOT_TO_LOAD    EVENTS   NOTE
  ------     ------       ------------    ------   ----
  5.15       OK           43ms            1
  6.1        OK           12ms            1
  6.8        OK           13ms            1
OVERALL: all kernels accepted the probe
```

Same `probe.bpf.o` (compiled against 6.8's BTF), same initrd, same
loader — booted against three different kernel ABIs. libbpf
relocated each `BPF_CORE_READ` field access against the running
kernel's BTF.

A kernel that *fails* CO-RE here would show up with
`STATUS=FAIL note=(stage=load)` and the workflow exits non-zero —
which is the useful CI signal for "this probe needs updating to
match a struct layout change upstream."

## Stage 2 result snapshot — LVH-backed kernel fetch

```
== LVH matrix summary
  KERNEL     STATUS       BOOT_TO_LOAD    EVENTS   NOTE
  ------     ------       ------------    ------   ----
  5.15       OK           41ms            1
  6.1        OK           13ms            1
  6.6        OK           19ms            1
  6.12       OK           16ms            1
OVERALL: all LVH kernels accepted the probe
```

Same probe, same loader, same initrd, but the four kernel ELFs were
pulled by `lvh kernels pull <ver>-main` from
`quay.io/lvh-images/kernel-images`. The Dockerfile delta is small —
~10 lines of `lvh kernels pull` instead of ~50 lines of apt + curl +
extract-vmlinux — and we gain newer kernels (6.6, 6.12) that aren't
in Noble's apt archive.

### Hand-rolled vs LVH-backed: when to use which

| | Hand-rolled (`build` + `matrix`) | LVH-backed (`build-lvh` + `matrix-lvh`) |
|---|---|---|
| Kernel source | Ubuntu apt + `kernel.ubuntu.com/mainline` debs | `lvh kernels pull` from `quay.io/lvh-images/kernel-images` |
| Kernel versions available here | 5.15, 6.1, 6.8 | 5.15, 6.1, 6.6, 6.12 (and many more — `lvh kernels catalog`) |
| Lines of Dockerfile for kernel fetch | ~50 | ~10 |
| Trust surface | Canonical / kernel.ubuntu.com | quay.io/lvh-images (Cilium maintains) |
| Why it's here | Learning value: shows what `extract-vmlinux` does, what BTF generation looks like | Production-shaped: this is how Cilium does kernel-matrix BPF CI |

Both produce identical JSON verdicts on the same compiled
`probe.bpf.o`. Pick LVH for real CO-RE matrix work; the hand-rolled
variant is in this repo to make the underlying mechanics visible.

## Layout

```
ebpf-core-firecracker-depot/
├── .depot/workflows/
│   ├── build-runner-image.yml       # build + cache hand-rolled runner image
│   ├── boot-single-kernel.yml       # boot Linux 6.8 guest + load probe
│   ├── matrix-kernels.yml           # 5.15 + 6.1 + 6.8 (hand-rolled)
│   ├── build-runner-lvh-image.yml   # build + cache LVH-backed runner image
│   └── matrix-kernels-lvh.yml       # 5.15 + 6.1 + 6.6 + 6.12 (lvh kernels pull)
├── src/
│   ├── probe.bpf.c                  # CO-RE eBPF probe
│   ├── loader.c                     # static-musl PID 1 / libbpf loader
│   └── Makefile                     # clang -target bpf, gcc -static
├── infra/docker/
│   ├── ebpf-runner.Dockerfile       # 5-stage hand-rolled: fetch kernels via
│   │                                # apt + dpkg-deb + extract-vmlinux
│   └── ebpf-runner-lvh.Dockerfile   # same shape, but kernels come from
│                                    # `lvh kernels pull`
├── scripts/
│   └── run_linux_guest.sh           # FC REST + PTY for serial, JSON marker parse
├── experiment.sh                    # ./experiment.sh boot | matrix
├── .dockerignore
├── depot.json                       # { "id": "lmpn2xx8kz" }
├── SPEC.md                          # the original spec for this experiment
└── README.md
```

## Setup (one-time, per Depot org)

```bash
export DEPOT_TOKEN='depot_org_...'

# Reuses the sibling experiment's project (lmpn2xx8kz). Tags are
# scoped per-tag, not per-project, so there's no clash with
# helloworld-runner-latest / native-runner-latest.

depot ci secrets list   # confirm AEGIS_DEPOT_TOKEN is set
```

## What this proves about Depot's nested-virt runners

- The guest kernel is a real, full-fat Ubuntu 6.8 — not the runner's
  kernel — booted under KVM acceleration. We control the version,
  the config, the BTF.
- libbpf's CO-RE relocator ran against the guest BTF at load time
  and resolved every field access in the probe. If you swap in a
  different kernel version (Stage 2), failures here would mean
  "your probe's field accesses don't translate" — the same signal
  you'd get from running on the real production kernel of a
  different host.
- Total wall time per kernel boot+probe-load+halt: ~1 second
  in-guest, ~15 seconds CI overhead. Cheap enough to matrix-test
  across many kernel versions in a single CI workflow.

## Known gotchas (carried over from PR #18 + discovered here)

1. **Depot Registry username is `x-token`**, not `depot`.
2. **Static linking libbpf on Alpine** needs the dev packages PLUS
   `zlib-static zstd-static xz-static bzip2-static`. The `libbpf-dev`
   and `elfutils-dev` packages bundle the `.a` archives themselves;
   there are no separate `-static` packages for those two. libelf
   transitively calls into all four compression libraries for
   compressed-ELF-section support.
3. **`apt-get` doesn't know the latest kernel deb filename in advance** —
   don't hardcode a launchpad URL. Use `apt-get install linux-image-virtual`
   and read whatever `/boot/vmlinuz-*-generic` ended up there.
4. Same FC-on-CI quirks as the sibling experiment: PTY for guest serial
   (firecracker-microvm/firecracker#2729), Depot CI secrets can't start
   with `DEPOT_`, container needs KVM passthrough + SYS_ADMIN +
   seccomp/apparmor unconfined.

## Reference

- libbpf-bootstrap (canonical CO-RE skeleton):
  <https://github.com/libbpf/libbpf-bootstrap>
- libbpf:
  <https://github.com/libbpf/libbpf>
- **Cilium's little-vm-helper (LVH)** — the production tool for
  matrix-BPF-testing across kernels. The `lvh-backed` variant here
  uses it directly:
  <https://github.com/cilium/little-vm-helper>
- Firecracker boot-source API:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/actions.md>
- CO-RE explainer (Andrii Nakryiko):
  <https://nakryiko.com/posts/bpf-portability-and-co-re/>
- Sibling experiment PR #18 (FC plumbing patterns reused here):
  <https://github.com/N3mes1s/Playground/pull/18>
