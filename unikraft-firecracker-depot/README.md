# unikraft-firecracker-depot

Run [Unikraft](https://unikraft.org) unikernels under
[Firecracker](https://github.com/firecracker-microvm/firecracker)
on a [Depot](https://depot.dev) nested-virt CI runner.

| Goal | Status |
|---|---|
| Boot the Unikraft `helloworld` unikernel under Firecracker on `depot-ubuntu-24.04`, capture the serial banner via the FC REST API directly | **green — 11 s wall (cached), 209 ms boot** |
| Run the official Unikraft catalog images in Depot CI, confirm each boots to the Unikraft banner | **green — 4/4 boot** (helloworld, python:3.12, nginx:1.25, redis:7.2). `node:21` excluded — see below. |

## Result snapshots

### Direct-FC boot of helloworld (cached runner image)

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

### Multi-image smoke (via `kraft run --plat fc --arch x86_64`)

```
  IMAGE                            STATUS       PULL     RUN
  unikraft.org/helloworld:latest   PASS         22s      1s
  unikraft.org/python:3.12         PASS         24s      20s
  unikraft.org/nginx:1.25          PASS         22s      20s
  unikraft.org/redis:7.2           PASS         22s      20s
  OVERALL: all images booted to the Unikraft banner
```

Notes:
- helloworld self-halts after printing. The server / runtime
  images (nginx, redis, python) don't self-halt, so we cap the
  run at 20 s and pass when "Powered by Unikraft" lands on serial.
- `unikraft.org/node:21` is intentionally NOT in the smoke list.
  That package ships only the unikernel; `/usr/bin/node` is meant
  to come from a user-supplied rootfs cpio. Without one the
  unikernel aborts in libukcpio at 0.1 s, before the splash.
  Staging the 100 MB node-rootfs to get past that point defeats
  the unikernel value prop, so it's out of scope here (see "What's
  not in scope" below).

## What's not in scope (deliberately)

The Unikraft catalog images `node:21`, `python:3.12`, etc. are the
**binary-compatibility** flavor of Unikraft — they boot a Linux ELF
(`/usr/bin/node`, `/usr/bin/python3`, …) inside a Unikraft libOS via
syscall translation. The Linux binary has to come from a
user-supplied rootfs cpio; the package only ships the kernel.

Booting these images to the "Powered by Unikraft" banner with no
user rootfs is sufficient to prove **the unikernel boots on FC under
Depot CI**, which is the deliverable here. Running an actual Node
program (e.g. `require("lodash")`) inside one would mean staging a
100 MB rootfs with the Linux node binary + musl + libstdc++ — which
defeats the unikernel value prop (5–30 MB image, sub-second boot, no
userland). A real demonstration of that value prop would mean
`kraft build`ing a custom unikernel with a tiny JS engine
(QuickJS, ~1 MB) and the application baked in. Not scoped here.

## Three things that were surprising about driving FC directly

(beyond what `kraft run` does for you):

1. Load `/unikraft/bin/kernel` (the ~258 KB stripped ELF32 with the
   multiboot entry stub) — **not** `/unikraft/bin/kernel.dbg`. The
   `.dbg` artifact is for symbol lookup; loading it silently jumps
   to the wrong entry and hangs.
2. Boot args follow Unikraft's `"<app_name> -- <app_args>"` format
   (e.g. `"kernel -- "` for helloworld,
   `"kernel -- /usr/bin/redis-server /etc/redis/redis.conf"` for
   redis). Linux-style args like
   `"console=ttyS0 reboot=k panic=1"` silently break early Unikraft
   boot.
3. Allocate a PTY for `firecracker`'s stdout via
   `script -qfec "firecracker --api-sock ..." serial.log` and route
   FC's own structured logs to `--log-path` separately. Without a
   PTY, guest serial output is dropped in non-interactive containers
   (firecracker-microvm/firecracker#2729).

## Layout

```
unikraft-firecracker-depot/
├── .depot/workflows/
│   ├── stage1-bootstrap.yml        # no-cache helloworld boot (apt+kraft inline)
│   ├── build-runner-image.yml      # build & save the helloworld cached runner
│   ├── run-stage1-cached.yml       # pull cached image, boot helloworld in <12 s
│   └── multi-image-smoke.yml       # boot all 5 catalog images via kraft run
├── infra/docker/
│   └── helloworld-runner.Dockerfile  # multi-stage: kraft-pulls helloworld kernel + bakes FC
├── scripts/
│   └── run_unikernel.sh            # boots FC via REST API, asserts banner
├── .dockerignore
├── depot.json                      # { "id": "lmpn2xx8kz" }
└── README.md
```

> Workflows live under the experiment subdir, so Depot CI auto-discovery
> (which scans `.depot/workflows/` at the repo root) doesn't pick them up.
> Trigger each explicitly with `depot ci run --workflow ...`.

## Setup (one-time)

```bash
export DEPOT_TOKEN='depot_org_...'   # org token

# 1. Create the Depot project; paste the returned id into depot.json
depot projects create unikraft-playground

# 2. Add the org token as a CI secret (must NOT start with DEPOT_)
depot ci secrets add AEGIS_DEPOT_TOKEN
#    paste depot_org_... at the prompt
```

Depot Registry uses `x-token` as the username and any depot token
(org, project, or short-lived pull) as the password. No separate
pull token needed.

## How to run

```bash
# (one-time, or after Dockerfile/script changes)
depot ci run --repo N3mes1s/Playground \
  --workflow unikraft-firecracker-depot/.depot/workflows/build-runner-image.yml

# Direct-FC helloworld via cached runner image (~11 s wall)
depot ci run --repo N3mes1s/Playground \
  --workflow unikraft-firecracker-depot/.depot/workflows/run-stage1-cached.yml

# Direct-FC helloworld via inline install (~61 s wall, no project needed)
depot ci run --repo N3mes1s/Playground \
  --workflow unikraft-firecracker-depot/.depot/workflows/stage1-bootstrap.yml

# Boot all 5 catalog images via kraft run (~3 min wall)
depot ci run --repo N3mes1s/Playground \
  --workflow unikraft-firecracker-depot/.depot/workflows/multi-image-smoke.yml
```

## Known gotchas (verified)

1. **Depot Registry username is `x-token`** (not `depot`, not the
   project ID). Password is any depot token. The obvious
   `username: depot` returns HTTP 401 with no useful hint.
2. **`depot projects list` / `delete` need elevated scope** the org
   token lacks, but `depot projects create` works. Test projects
   created during iteration can only be cleaned up via the Depot UI.
3. **Unikraft on FC has three non-obvious wiring requirements** —
   see the three bullets above (kernel file selection, boot_args
   format, PTY for guest serial).
4. **`unikraft.org` catalog refs are `unikraft.org/<name>:<version>`**
   — no `library/`, `runtime/`, or `native/` prefix. (The aegis spec
   mentioned those prefixes; the actual registry uses none.) And
   Node only goes up to `:21`, not `:22`.

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
