# unikraft-firecracker-depot

Run [Unikraft](https://unikraft.org) unikernels under
[Firecracker](https://github.com/firecracker-microvm/firecracker)
on a [Depot](https://depot.dev) nested-virt CI runner. Three things
work end-to-end:

| What | Where | CI wall | Boot time | ELF size |
|---|---|---|---|---|
| Boot the prebuilt `helloworld` unikernel via Firecracker REST API | `boot-helloworld-cached.yml` | **11 s** | 209 ms | 258 KB |
| Smoke-boot 4 official catalog images (`helloworld`, `python:3.12`, `nginx:1.25`, `redis:7.2`) via `kraft run` | `smoke-catalog-images.yml` | ~3 min | — | — |
| **Build a from-source native unikernel** (C + `kraft build`) and boot it | `boot-native-cached.yml` | **10 s** | **209 ms** | **249 KB** |

## Quickstart

```bash
# 0. Prereqs: depot CLI + a depot org token
#    https://depot.dev/docs/cli/installation
curl -L https://depot.dev/install-cli.sh | sh
export PATH=$HOME/.depot/bin:$PATH
export DEPOT_TOKEN='depot_org_...'

cd unikraft-firecracker-depot

# 1. One-time (if depot.json isn't already populated):
#    depot projects create unikraft-playground   # paste returned id into depot.json
#    depot ci secrets add AEGIS_DEPOT_TOKEN      # paste DEPOT_TOKEN at prompt

# 2. Build the cached runner images (only needed once, or after Dockerfile/script edits)
./experiment.sh build-helloworld-image      # ~45 s
./experiment.sh build-native-image          # ~5 min first ever, ~30 s after

# 3. Boot things
./experiment.sh boot-helloworld             # ~11 s — direct-FC prebuilt unikernel
./experiment.sh boot-native                 # ~10 s — from-source native unikernel
./experiment.sh smoke                       # ~3 min — 4 official catalog images
```

Each `boot-*` command returns the boot's serial output, the boot
elapsed_ms, and exits 0/1 on banner match.

For an inline-install fallback that doesn't need a Depot project at
all (~61 s wall), use `./experiment.sh boot-helloworld-inline`.

Run `./experiment.sh --help` for the full command list.

## Result snapshots

### `boot-helloworld-cached` — prebuilt unikernel, direct Firecracker REST API

```
Powered by
o.   .o       _ _               __ _
Oo   Oo  ___ (_) | __ __  __ _ ' _) :_
oO   oO ' _ `| | |/ /  _)' _` | |_|  _)
oOo oOO| | | | |   (| | | (_) |  _) :_
 OoOoO ._, ._:_:_,\_._,  .__,_:_, \___)
                  Ijiraq 0.21.0~87240a2

Hello from Unikraft!
elapsed_ms=209
Firecracker exiting successfully. exit_code=0
```

### `boot-native-cached` — `kraft build`-from-source unikernel

```
Powered by
=== aegis-probe (native Unikraft unikernel) ===
DETONATE_JSON_BEGIN
{"verdict":"OK","app":"aegis-probe","runtime":"native","argc":2,"argv0":"kernel","linkage":"compiled-into-unikernel"}
DETONATE_JSON_END
elapsed_ms=209
Firecracker exiting successfully. exit_code=0
```

`main.c` is linked into the unikernel ELF at build time — no rootfs,
no Linux binary, no syscall translation. The C code IS the kernel.
To change what it does, see [`apps/aegis-probe/README.md`](apps/aegis-probe/README.md).

### `smoke-catalog-images` — official catalog images via kraft run

```
  IMAGE                            STATUS       PULL     RUN
  unikraft.org/helloworld:latest   PASS         22s      1s
  unikraft.org/python:3.12         PASS         24s      20s
  unikraft.org/nginx:1.25          PASS         22s      20s
  unikraft.org/redis:7.2           PASS         22s      20s
  OVERALL: all images booted to the Unikraft banner
```

Notes:
- helloworld self-halts; server/runtime images (nginx, redis,
  python) don't, so we cap each run at 20 s and pass on the
  `"Powered by Unikraft"` splash.
- `unikraft.org/node:21` is intentionally not in the list — its
  package ships only the unikernel and expects `/usr/bin/node`
  from a user-supplied rootfs cpio. See "What's not in scope".
- Want to probe a different image? Edit the `IMAGES` array in
  [`smoke-catalog-images.yml`](.depot/workflows/smoke-catalog-images.yml).

## Layout

```
unikraft-firecracker-depot/
├── .depot/workflows/
│   ├── boot-helloworld-inline.yml      # no-cache helloworld boot (apt+kraft inline)
│   ├── build-helloworld-image.yml      # build & save the helloworld runner image
│   ├── boot-helloworld-cached.yml      # boot helloworld from the cached image (~11 s)
│   ├── smoke-catalog-images.yml        # smoke-boot 4 catalog images via kraft run
│   ├── build-native-image.yml          # kraft build aegis-probe + save runner image
│   └── boot-native-cached.yml          # boot the native unikernel (~10 s)
├── apps/aegis-probe/
│   ├── main.c                          # the C code that becomes the unikernel
│   ├── Kraftfile                       # spec v0.6, target fc/x86_64
│   ├── Makefile.uk                     # registers main.c into the unikraft build
│   ├── Makefile                        # wrapper around the unikraft build system
│   └── README.md                       # how to edit & rebuild
├── infra/docker/
│   ├── helloworld-runner.Dockerfile    # pulls prebuilt helloworld unikernel + bakes FC
│   └── native-runner.Dockerfile        # `kraft build`s apps/aegis-probe -> ELF + bakes FC
├── scripts/
│   └── run_unikernel.sh                # boots FC via REST API, asserts a serial pattern
├── experiment.sh                       # wrapper: ./experiment.sh boot-native
├── .dockerignore
├── depot.json                          # { "id": "lmpn2xx8kz" }
└── README.md
```

> Workflows live under the experiment subdir, so Depot CI's auto-
> discovery (which scans `.depot/workflows/` at the *repo root*)
> doesn't pick them up. Trigger explicitly via `experiment.sh` (which
> calls `depot ci run --workflow …`).

## Setup (one-time, per Depot org)

```bash
export DEPOT_TOKEN='depot_org_...'   # org token

# Create the Depot project; paste the returned id into depot.json
depot projects create unikraft-playground

# Add the org token as a CI secret (must NOT start with DEPOT_)
depot ci secrets add AEGIS_DEPOT_TOKEN
#   then paste depot_org_... at the prompt
```

Depot Registry uses `x-token` as the username and any depot token
(org, project, or short-lived pull) as the password. No separate
pull token is needed for this repo.

## Three things that were non-obvious about driving FC directly

(beyond what `kraft run` does for you):

1. Load `/unikraft/bin/kernel` (the ~258 KB stripped ELF32 with the
   multiboot entry stub) — **not** `/unikraft/bin/kernel.dbg`. The
   `.dbg` artifact is for symbol lookup; loading it silently jumps
   to the wrong entry and hangs.
2. Boot args follow Unikraft's `"<app_name> -- <app_args>"` format
   (e.g. `"kernel -- "` for helloworld,
   `"kernel -- /usr/bin/redis-server /etc/redis/redis.conf"` for
   redis — confirmed from kraft's API calls). Linux-style args like
   `"console=ttyS0 reboot=k panic=1"` silently break early Unikraft
   boot.
3. Allocate a PTY for `firecracker`'s stdout via
   `script -qfec "firecracker --api-sock ..." serial.log` and route
   FC's own structured logs to `--log-path` separately. Without a
   PTY, guest serial output is dropped in non-interactive containers
   ([firecracker-microvm/firecracker#2729](https://github.com/firecracker-microvm/firecracker/issues/2729)).

## What's not in scope (deliberately)

The Unikraft catalog images `node:21`, `python:3.12`, etc. are the
**binary-compatibility** flavor of Unikraft — they boot a Linux ELF
(`/usr/bin/node`, `/usr/bin/python3`, …) inside a Unikraft libOS via
syscall translation. The Linux binary has to come from a
user-supplied rootfs cpio; the package only ships the kernel.

Booting these images to the "Powered by Unikraft" banner with no
user rootfs is sufficient to prove **the unikernel boots on FC under
Depot CI**, which is one of the deliverables. Running an actual
Node program (e.g. `require("lodash")`) inside one would mean
staging a 100 MB rootfs with the Linux node binary + musl +
libstdc++, booting it in a 1 GB FC microVM — which defeats the
unikernel value prop entirely.

The native `aegis-probe` deliverable shows what that value prop
actually looks like: a 249 KB self-contained unikernel ELF that
boots in 209 ms with our C code linked in. Extending it to host a
JS or Wasm interpreter linked into the unikernel (so it's a
*unikernel that runs JS*, not a *microVM running Linux + node*) is
the natural next step but out of scope here.

## Known gotchas (verified)

1. **Depot Registry username is `x-token`** (not `depot`, not the
   project ID). Password is any depot token. The obvious
   `username: depot` returns HTTP 401 with no useful hint.
2. **`depot projects list` / `delete` need elevated scope** the org
   token lacks, but `depot projects create` works. Test projects
   created during iteration can only be cleaned up via the Depot UI.
3. **Unikraft on FC has three non-obvious wiring requirements** —
   see the three bullets above.
4. **`unikraft.org` catalog refs are `unikraft.org/<name>:<version>`**
   — no `library/`, `runtime/`, or `native/` prefix. (The aegis
   spec mentioned those prefixes; the actual registry uses none.)
   And Node only goes up to `:21`, not `:22`.

## Reference

- Unikraft: <https://unikraft.org>
- KraftKit: <https://github.com/unikraft/kraftkit>
- Unikraft application catalog: <https://github.com/unikraft/catalog>
- Firecracker API spec:
  <https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml>
- Firecracker bug — serial drop in non-TTY contexts:
  <https://github.com/firecracker-microvm/firecracker/issues/2729>
- Depot Registry quickstart: <https://depot.dev/docs/registry/quickstart>
- Depot CI docs: <https://depot.dev/docs/ci>
