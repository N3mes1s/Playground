# unikraft-firecracker-depot

Boot a [Unikraft](https://unikraft.org) unikernel inside
[Firecracker](https://github.com/firecracker-microvm/firecracker)
on a [Depot](https://depot.dev) nested-virt CI runner.

| Stage | Goal | Status |
|-------|------|--------|
| 1 | Boot the Unikraft `helloworld` unikernel under Firecracker on `depot-ubuntu-24.04`, capture the serial banner | **green — 11 s wall, 209 ms boot** (cached runner image) |
| 2 | Boot a Node.js unikernel and run `require("lodash")`, surface a JSON verdict off ttyS0 | not started |

## Stage 1 result

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

| Path | CI wall | Notes |
|------|---------|-------|
| `stage1-bootstrap.yml` | 61 s | Apt + curl-installs firecracker, kraft; pulls unikernel at run time. No registry needed. |
| `build-runner-image.yml` + `run-stage1-cached.yml` | 11 s per run (+ one-time ~45 s build) | Everything baked into `registry.depot.dev/lmpn2xx8kz:helloworld-runner-latest`. |

Three non-obvious things were needed to drive Firecracker directly
(beyond what `kraft run` does for you):

1. Load `/unikraft/bin/kernel` (the 258 KB stripped ELF32 with
   multiboot entry stub) — **not** `/unikraft/bin/kernel.dbg`. The
   `.dbg` artifact is for symbol lookup, not booting; loading it
   silently jumps to the wrong entry and hangs.
2. Boot args follow Unikraft's `"<app_name> -- <app_args>"` format
   (e.g. `"kernel -- "`). Linux-style args like
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
│   ├── stage1-bootstrap.yml        # no-cache path (apt + kraft install + pull at run time)
│   ├── build-runner-image.yml      # build & save runner image to Depot Registry
│   └── run-stage1-cached.yml       # pull cached image, boot in <12 s
├── infra/docker/
│   └── helloworld-runner.Dockerfile  # multi-stage: kraft-pulls kernel + bakes FC
├── scripts/
│   └── run_unikernel.sh            # boots FC via REST API, asserts banner
├── .dockerignore                   # restricts build context to infra/ + scripts/
├── depot.json                      # { "id": "lmpn2xx8kz" }
└── README.md
```

> **Note on `.depot/workflows/` location.** Depot CI's auto-discovery
> scans `.depot/workflows/` at the repo root. Because this experiment
> lives in a subdirectory of Playground, workflows here are not
> push-triggered — invoke them with `depot ci run --workflow ...`.

## Setup (one-time)

```bash
export DEPOT_TOKEN='depot_org_...'

# 1. Create the Depot project (returns id, paste into depot.json)
depot projects create unikraft-playground

# 2. Add the org token as a CI secret (must NOT start with DEPOT_)
depot ci secrets add AEGIS_DEPOT_TOKEN
#    paste depot_org_... at the prompt
```

That's it — no separate pull token needed. The Depot Registry uses
`x-token` as the username and any depot token (org, project, or
short-lived pull) as the password.

## Build and run

### Cached path (recommended)

```bash
# Build the runner image once (or after Dockerfile/script changes).
# Saves to registry.depot.dev/lmpn2xx8kz:helloworld-runner-latest.
depot ci run --repo N3mes1s/Playground \
  --workflow unikraft-firecracker-depot/.depot/workflows/build-runner-image.yml

# Boot — pulls cached image, runs the boot script. ~11 s wall.
depot ci run --repo N3mes1s/Playground \
  --workflow unikraft-firecracker-depot/.depot/workflows/run-stage1-cached.yml
```

### Bootstrap path (no project ID required)

```bash
# Installs firecracker + kraft inline on every run. ~61 s wall.
depot ci run --repo N3mes1s/Playground \
  --workflow unikraft-firecracker-depot/.depot/workflows/stage1-bootstrap.yml
```

## Stage 1 acceptance

- workflow run completes in **< 30 s total** → cached: **11 s** ✓
- firecracker stdout contains "Hello from Unikraft!" → ✓
- microVM exits cleanly → `exit_code=0` ✓
- script-reported boot+exec time is **< 1 s** → **209 ms** ✓

## Known gotchas (carried over from aegis + discovered here)

1. **archive.ubuntu.com is Cloudflare-blocked** from Depot egress
   (HTTP 1010). Dockerfile rewrites apt sources to
   `mirror.facebook.net` before any `apt-get`.
2. **Secret names can't start with `DEPOT_`.** We use
   `AEGIS_DEPOT_TOKEN`; inject as `DEPOT_TOKEN` env var inside steps
   where the depot CLI needs it.
3. **Depot Registry username is `x-token`** (not `depot`, not the
   project ID). Password is any depot token.
4. **`depot projects list`/`delete` need elevated scope** the org
   token lacks, but `depot projects create` works. Test projects
   that get created can only be cleaned up via the Depot UI.
5. **Unikraft on FC quirks** — see the three bullets above.

## Reference

- Unikraft: <https://unikraft.org>
- KraftKit: <https://github.com/unikraft/kraftkit>
- Firecracker API spec:
  <https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml>
- Firecracker bug — serial drop in non-TTY contexts:
  <https://github.com/firecracker-microvm/firecracker/issues/2729>
- Depot Registry quickstart: <https://depot.dev/docs/registry/quickstart>
- Depot CI docs: <https://depot.dev/docs/ci>
