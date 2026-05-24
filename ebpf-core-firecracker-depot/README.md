# ebpf-core-firecracker-depot

Load a CO-RE (Compile Once, Run Everywhere) eBPF probe inside real
Linux microVMs under Firecracker on a [Depot](https://depot.dev)
nested-virt CI runner, then matrix-test the same compiled `.bpf.o`
against several guest kernel ABIs.

The technical pattern (FC microVMs + matrix BPF testing) **is not
new** — Cilium's [little-vm-helper](https://github.com/cilium/little-vm-helper)
(LVH) does exactly this and is what real projects reach for. What's
incrementally new is doing it inside a *managed* CI service without
self-hosting bare metal or `*.metal`-class instances. This experiment
ships both:

- a **hand-rolled** FC + initrd + apt-fetch-kernel pipeline
  (educational; shows the mechanics LVH hides), and
- the same pipeline with **`lvh kernels pull`** swapped in for the
  kernel-fetch step (recommended for real work; ~10 lines of
  Dockerfile instead of ~50).

| Stage | Path | Result |
|---|---|---|
| 1 — single kernel, single probe, end-to-end CO-RE load + event capture | hand-rolled, kernel 6.8 | **green** — 14 ms to libbpf-load, sub-ms to first event, ~15 s CI wall (cached) |
| 2 — kernel matrix 5.15 / 6.1 / 6.8 | hand-rolled | **green** — 3/3 OK, ~45 s CI wall |
| 2 — kernel matrix 5.15 / 6.1 / 6.6 / 6.12 | LVH | **green** — 4/4 OK, ~45 s CI wall |

FC plumbing patterns (PTY-for-stdout, `x-token` Depot Registry auth,
multi-stage Dockerfile → cached runner image) are inherited from the
sibling [`unikraft-firecracker-depot`](../unikraft-firecracker-depot)
experiment (PR #18) — see its README for the firsthand-discovered
quirks.

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

## What's actually demonstrated here

- **Same `probe.bpf.o` runs on four different guest kernel ABIs**
  spanning ~3 years of Linux evolution (5.15 → 6.12). Each guest's
  libbpf resolved every `BPF_CORE_READ` field access against its
  own kernel's BTF at load time. That's CO-RE working empirically,
  not in theory.
- **LVH integration in a managed CI runner.** `lvh kernels pull`
  in a build stage, kernel ELFs baked into the runner image, FC +
  initrd + boot script the same as PR #18. No bare metal involved.
- **The hand-rolled mechanics are visible** so you can see what
  LVH hides: Ubuntu kernel deb extraction, `extract-vmlinux` on
  the vmlinuz, `bpftool btf dump file` for vmlinux.h, cpio newc
  for the initrd, FC REST + PTY for serial capture.
- **Per-kernel wall time: ~1 s in-guest, ~12 s CI overhead.** Most
  of the wall is container pull + KVM init, not the boot itself.
  Cheap enough that a per-PR multi-kernel CO-RE check is realistic.

### What is NOT new here

- **Matrix BPF testing under microVMs** — Cilium has been doing
  this in production with LVH for years.
- **Loading eBPF in CI** — privileged Linux runners with BTF have
  been able to do that on the host kernel for years (GitHub
  Actions, GitLab, etc.).
- **The CO-RE relocation pattern itself** — libbpf shipped this
  with v1.0 in 2022.

What is new: doing it on a **shared/managed CI service** without
owning bare-metal infrastructure. That's a CI delivery-model
change, not a kernel/BPF capability one.

## Known gotchas (verified in this experiment)

1. **LVH ships two OCI image families with confusingly similar names.**
   - `quay.io/lvh-images/complexity-test:<ver>-<timestamp>` is a
     whole-VM **qcow2 disk image** for use with `lvh run`. The
     filesystem of the OCI image contains
     `/data/images/complexity-test_<ver>.qcow2.zst` — no
     `/boot/vmlinux` directly accessible.
   - `quay.io/lvh-images/kernel-images:<ver>-main` is what
     `lvh kernels pull` defaults to. The OCI image extracts as
     `./<tag>/boot/vmlinux-X.Y.Z` (raw ELF, ready for FC).
   - Reach for `kernel-images` if you want kernels; reach for
     `complexity-test` only if you want LVH to run the whole VM.
2. **`lvh` requires Go ≥ 1.25.7** to `go install`. Use
   `golang:1.25-alpine` or later as the build stage base.
3. **Depot Registry username is `x-token`**, not `depot`.
4. **Static linking libbpf on Alpine** needs the dev packages PLUS
   `zlib-static zstd-static xz-static bzip2-static`. `libbpf-dev`
   and `elfutils-dev` bundle their `.a` archives themselves (no
   separate `-static` apk). libelf transitively calls into all four
   compression libraries for compressed-ELF-section support.
5. **Don't hardcode launchpad URLs for kernel debs** — they 404 as
   versions roll over. `apt-get install linux-image-virtual` and
   read whatever `/boot/vmlinuz-*-generic` lands.
6. Same FC-on-CI quirks as the sibling experiment: PTY for guest
   serial (firecracker-microvm/firecracker#2729), Depot CI secrets
   can't start with `DEPOT_`, container needs KVM passthrough +
   SYS_ADMIN + seccomp/apparmor unconfined.

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
