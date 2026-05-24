# Experiment — load + CO-RE-validate an eBPF probe inside Firecracker microVMs on Depot CI

## Context

Depot's nested-virtualization CI runners (`runs-on: depot-ubuntu-24.04`) expose `/dev/kvm` to a job container. That lets you spawn a real Linux microVM under Firecracker from a CI job and **control the guest kernel version** — exactly what you need to validate that a CO-RE (Compile Once, Run Everywhere) eBPF probe relocates correctly across kernel ABIs. Before this offering, that workflow needed bare-metal CI (self-hosted or Equinix-style metal); shared CI providers couldn't do it.

We just shipped a sibling experiment in this same repo that nails the FC plumbing for Unikraft guests:

Branch: `claude/unikraft-firecracker-depot-Lfwst` (open as PR #18)

Specific files to read (use `mcp__github__get_file_contents` against `n3mes1s/playground` on that branch):

- `unikraft-firecracker-depot/README.md` — Quickstart, layout, three FC gotchas
- `unikraft-firecracker-depot/scripts/run_unikernel.sh` — the FC REST + PTY pattern
- `unikraft-firecracker-depot/.depot/workflows/build-helloworld-image.yml` + `boot-helloworld-cached.yml` — the build-cache + boot pattern
- `unikraft-firecracker-depot/infra/docker/helloworld-runner.Dockerfile` — multi-stage Dockerfile saved to Depot Registry
- `unikraft-firecracker-depot/experiment.sh` — wrapper around `depot ci run`

That experiment boots a Unikraft unikernel. **This one boots a real Linux kernel guest** (vmlinux + initrd) so eBPF actually has a Linux kernel to load against. Reuse the wrapper, the workflow shape, the Dockerfile pattern, and the serial-PTY trick.

## Goal

Demonstrate the full CI loop for CO-RE eBPF:

1. Cross-compile a small CO-RE probe with libbpf + clang.
2. Embed the `.bpf.o` and a static userspace loader into an initrd cpio.
3. Boot **multiple Linux kernel versions** (e.g. 5.15, 6.1, 6.8 — pick 3) under Firecracker on a single Depot runner.
4. For each kernel: load the probe via libbpf, attach to a tracepoint, generate ≥1 event, dump JSON to ttyS0.
5. Host-side: parse the per-kernel JSON, succeed only if every kernel resolved CO-RE relocations and emitted ≥1 event.

The end goal is a 3–5 minute CI workflow that proves a probe works against N kernel ABIs without anyone owning bare metal. The matrix-across-kernels capability is the genuinely new thing nested-virt unlocks; everything else has been possible on privileged CI containers for years.

## Scope — two stages

Don't start stage 2 until stage 1 is green.

### Stage 1 — one kernel, one probe

- Cross-compile a "BPF_OK" probe attached to `sys_enter_execve` (or any always-firing tracepoint).
- Boot **one** Linux kernel under FC, load the probe inside the guest via a static-musl loader binary in the initrd, write `BPF_RESULT_BEGIN…END` JSON to ttyS0, reboot to halt cleanly.
- Host-side assertion: the JSON marker, `verdict: OK`, `events ≥ 1`.

### Stage 2 — kernel matrix

- Loop the same `.bpf.o` and loader across 3+ kernel versions.
- Surface a per-kernel pass/fail table like the sibling repo's `smoke-catalog-images.yml`.
- A kernel that fails CO-RE relocation is the interesting failure mode — keep that case loud, don't silently skip.

## Pattern to mirror (verbatim where it makes sense)

1. **Workflows** at `ebpf-core-firecracker-depot/.depot/workflows/*.yml`. Add `defaults: { run: { shell: bash } }`. Use the same `container:` block with `--device=/dev/kvm --cap-add=SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined`.
2. **Runner image** built via `depot/build-push-action@v1` with `save: true, save-tag: <name>-latest`. Multi-stage Dockerfile: stage A cross-compiles BPF + builds initrd + fetches/unpacks vmlinux(es); stage B is the runtime image with firecracker + util-linux + the baked-in artifacts.
3. **Depot Registry pull** in the consumer workflow: `container.image: registry.depot.dev/<project_id>:<tag>` with `credentials: { username: x-token, password: ${{ secrets.AEGIS_DEPOT_TOKEN }} }`.
4. **FC REST + PTY**: take `scripts/run_unikernel.sh` and adapt as `scripts/run_linux_guest.sh`:
   - Replace boot_args with Linux-style `"console=ttyS0 reboot=k panic=1"`. (The Unikraft `"<app> -- <args>"` convention does NOT apply here.)
   - Pass `initrd_path` in the `/boot-source` body.
   - Pattern to match becomes your `BPF_RESULT_END` marker.
   - Bump `mem_size_mib` to 256–512.

## Required setup

### Depot CI secret

`AEGIS_DEPOT_TOKEN` is already provisioned on org `1crx4tb65r` (PR #18 uses it). Reuse it. Don't add a new secret unless you have a reason. The token rule from PR #18 still applies: CI secret names cannot start with `DEPOT_`.

### Depot project

PR #18 uses project `lmpn2xx8kz` (`unikraft-playground`). Two options:

- **Reuse it**: registry tags are scoped by tag string, not project, so as long as you use distinct tags (`ebpf-runner-latest`, etc.) there's no clash. Easiest.
- **New project**: `depot projects create ebpf-playground`. The token can create but cannot list/delete — see PR #18 gotcha #2.

### Local

```bash
curl -L https://depot.dev/install-cli.sh | sh
export PATH=$HOME/.depot/bin:$PATH
export DEPOT_TOKEN='depot_org_...'   # from the human
```

## Concrete layout

```
ebpf-core-firecracker-depot/
├── .depot/workflows/
│   ├── build-runner-image.yml        # bake kernels + probe + loader + FC
│   ├── boot-single-kernel.yml        # stage 1
│   └── matrix-kernels.yml            # stage 2
├── src/
│   ├── probe.bpf.c                   # CO-RE probe
│   ├── loader.c                      # libbpf userspace loader
│   └── Makefile                      # cross-compile both, vendor libbpf
├── kernels/
│   └── manifest.yaml                 # (name, source-url, sha256) per kernel
├── infra/docker/
│   └── ebpf-runner.Dockerfile        # multi-stage build
├── scripts/
│   ├── run_linux_guest.sh            # adapted from sibling's run_unikernel.sh
│   └── build_initrd.sh               # cpio newc with /init + /probe.bpf.o
├── experiment.sh                     # wrapper, mirror sibling's structure
├── depot.json
└── README.md
```

## Probe — `src/probe.bpf.c`

Make it exercise at least one CO-RE relocation so success is meaningful — not a hello-world that would pass on any kernel:

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event { __u32 pid; char comm[16]; };

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    struct task_struct *t = (void *)bpf_get_current_task();
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = BPF_CORE_READ(t, pid);
    BPF_CORE_READ_STR_INTO(&e->comm, t, comm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

`vmlinux.h` generation strategy: either pre-bake one (CO-RE handles the rest) OR generate per-kernel at runtime from `/sys/kernel/btf/vmlinux` inside the guest via `bpftool btf dump file ... format c`. Pre-baking is simpler.

## Loader — `src/loader.c`

Outline:

- `bpf_object__open_file("/probe.bpf.o")`
- `bpf_object__load(obj)` — this is where CO-RE relocations resolve. Capture errno + libbpf error string on failure.
- Attach the program (`bpf_program__attach`).
- Open the ringbuf, poll up to 5 s for ≥1 event. Run `execve("/bin/true", …)` from inside the loader so you generate your own event deterministically.
- Print:

  ```
  BPF_RESULT_BEGIN
  {"kernel":"6.1.0","verdict":"OK","events":3,"core_relocs":"resolved","boot_ms":712}
  BPF_RESULT_END
  ```

  …or on failure:

  ```
  {"kernel":"5.4.0","verdict":"FAIL","stage":"load","libbpf_err":"…","core_relocs":"unresolved:struct task_struct field 'pid'"}
  ```

- `reboot(LINUX_REBOOT_CMD_RESTART)` so FC catches the halt and `exit_code=0`.

Build with `musl-gcc -static`, link libbpf statically (vendor a known-good version, e.g. v1.4.x). Zero shared-lib deps in the initrd.

## Kernel images

Each guest needs:

- `vmlinux` (ELF, with `CONFIG_DEBUG_INFO_BTF=y` so `/sys/kernel/btf/vmlinux` is exposed and CO-RE can resolve)
- Minimal initrd cpio containing `/init` (the loader, exec'd as PID 1), `/probe.bpf.o`, and whatever the loader needs (probably nothing).

Sources to try, easiest first:

- **Firecracker test kernels**: <https://github.com/firecracker-microvm/firecracker/tree/main/tests/host_tools> — small, BTF on, designed for FC.
- **Ubuntu LTS kernel debs**: unpack `linux-image-*-generic`, zstd-decompress the vmlinuz to extract vmlinux. The sibling aegis pipeline does this for Noble's 6.8 — install `zstd`, `lz4`, `lzop` in the Dockerfile (already noted in PR #18's earlier gotcha list).
- **AmazonLinux Bottlerocket** kernels: tiny, BTF on, well-maintained.

Pick 3 versions that span ≥ one major struct-layout change in `task_struct` so the CO-RE work is non-trivial — e.g. 5.10, 5.15, 6.1, 6.8 are all interesting choices.

## Stage 1 acceptance

- CI wall **< 90 s** (image cached, boot is fast).
- Loader emits `BPF_RESULT_BEGIN/END` with `verdict:"OK"` and `events ≥ 1`.
- FC `exit_code=0`.
- `scripts/run_linux_guest.sh` exits 0.

## Stage 2 acceptance

- All N kernels report `verdict:"OK"`.
- Per-kernel summary on stdout, e.g.:

  ```
  KERNEL          STATUS    BOOT_MS   EVENTS    CORE_RELOCS
  linux-5.15.x    PASS      812       3         resolved
  linux-6.1.x     PASS      745       3         resolved
  linux-6.8.x     PASS      691       3         resolved
  OVERALL: 3/3 kernels accepted the probe
  ```

- Job exits non-zero if any kernel fails — failure is itself a useful CI signal for "your CO-RE probe needs updating".

## Gotchas (carried over from PR #18, verified)

1. **Depot Registry username is `x-token`**, password is any depot token.
2. **`depot projects list/delete` are scope-locked**; `create` works. Test projects are UI-only to clean up.
3. **Guest serial is dropped** in non-interactive containers unless FC stdout is a PTY. Use `script -qfec "firecracker ..." serial.log` and route FC's own slog to `--log-path`. (firecracker-microvm/firecracker#2729)
4. **`archive.ubuntu.com`** may be Cloudflare-blocked from Depot egress; the sibling defensively rewrites apt sources to `mirror.facebook.net`. We never confirmed the block ourselves but the swap is free.
5. **CI secret names cannot start with `DEPOT_`** — `AEGIS_DEPOT_TOKEN` is what's already set up.
6. **Workflows in the experiment subdir aren't auto-discovered**. Trigger via `experiment.sh` or `depot ci run --workflow ebpf-core-firecracker-depot/.depot/workflows/...`.

## Things that differ from PR #18

- **Boot args are Linux-style** (`console=ttyS0 reboot=k panic=1`). The Unikraft `<app> -- <args>` convention does not apply.
- **initrd is required.** FC `/boot-source` needs `initrd_path` set.
- **Kernel image is decompressed vmlinux ELF**, not Unikraft's stripped 32-bit multiboot ELF. Different artefact.
- **Memory** ≥ 256 MiB. eBPF maps + libbpf load can use a few MiB.
- **The PTY trick still applies** — copy it verbatim from `scripts/run_unikernel.sh`.

## Deliverables

One PR per stage:

- workflow file(s)
- src/ (probe + loader + Makefile)
- Dockerfile + initrd builder
- `experiment.sh` extended with `boot-single-kernel`, `matrix-kernels`, `build-runner-image`
- README with per-stage result snapshot (matrix table for stage 2)
- Reference to PR #18 for the FC plumbing patterns reused

If you hit a blocker for > 30 min, write a PR comment with the repro + what you've ruled out. CO-RE relocation failures are themselves an interesting finding worth documenting in the README.

## Resources

- libbpf-bootstrap (canonical skeleton):
  <https://github.com/libbpf/libbpf-bootstrap>
- libbpf:
  <https://github.com/libbpf/libbpf>
- Firecracker boot-source API:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/actions.md>
- CO-RE explainer (Andrii Nakryiko):
  <https://nakryiko.com/posts/bpf-portability-and-co-re/>
- Sibling PR #18 (FC plumbing we already shipped):
  <https://github.com/N3mes1s/Playground/pull/18>
- Sibling branch (for direct file access):
  <https://github.com/N3mes1s/Playground/tree/claude/unikraft-firecracker-depot-Lfwst>
