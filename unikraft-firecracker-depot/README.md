# unikraft-firecracker-depot

Boot a [Unikraft](https://unikraft.org) unikernel inside
[Firecracker](https://github.com/firecracker-microvm/firecracker)
on a [Depot](https://depot.dev) nested-virt CI runner. Two
stages:

| Stage | Goal | Status |
|-------|------|--------|
| 1 | Boot the Unikraft `helloworld` unikernel under Firecracker on `depot-ubuntu-24.04`, capture the serial banner | **green** — 210 ms boot, 61 s CI wall (no cache yet) |
| 2 | Boot a Node.js unikernel and run `require("lodash")`, surface a JSON verdict off ttyS0 | not started |

### Stage 1 result (run `ghjzjb731b`)

```
Powered by
o.   .o       _ _               __ _
Oo   Oo  ___ (_) | __ __  __ _ ' _) :_
oO   oO ' _ `| | |/ /  _)' _` | |_|  _)
oOo oOO| | | | |   (| | | (_) |  _) :_
 OoOoO ._, ._:_:_,\_._,  .__,_:_, \___)
                  Ijiraq 0.21.0~87240a2

Hello from Unikraft!
elapsed_ms=210
Firecracker exiting successfully. exit_code=0
```

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

Why: Unikraft images are 5–30 MB and boot in milliseconds.
If the plumbing works, this is a much faster sandbox for
tier-0 "what does this package do at import time" checks
than the Ubuntu microVM pipeline used in
[aegis](https://github.com/N3mes1s/aegis/tree/claude/firecracker-aegis-ci-job-40KrY/.depot/workflows).

## Layout

```
unikraft-firecracker-depot/
├── .depot/workflows/
│   ├── ci-base-image.yml         # build + cache the runner image
│   ├── unikraft-image.yml        # pull helloworld unikernel, package as OCI
│   └── unikraft-helloworld.yml   # boot the unikernel under Firecracker
├── infra/docker/
│   ├── ci-base.Dockerfile        # firecracker + kraft + docker + depot CLI
│   ├── helloworld-uk.Dockerfile  # FROM scratch, COPY kernel /kernel
│   └── .dockerignore
├── scripts/
│   └── run_unikernel.sh          # talks to firecracker over its API socket
├── depot.json                    # { "id": "<DEPOT_PROJECT_ID>" }
└── README.md
```

> **Note on `.depot/workflows/` location.** Depot CI's
> auto-discovery scans `.depot/workflows/` at the *repo
> root*. Because this experiment lives in a subdirectory
> of Playground, the workflows here are not auto-picked-up.
> Trigger them explicitly:
>
> ```bash
> depot ci run \
>   --workflow unikraft-firecracker-depot/.depot/workflows/unikraft-helloworld.yml
> ```
>
> If we ever want push-driven triggers, symlink or move
> `.depot/workflows/` and `depot.json` to the repo root.

## One-time setup (repo owner)

```bash
# 1. Create the Depot project, paste the returned id into depot.json
depot projects create unikraft-playground

# 2. Add the token as a CI secret (must NOT start with DEPOT_)
depot ci secrets add AEGIS_DEPOT_TOKEN
#    then paste depot_org_... at the prompt
```

After that, edit `depot.json` and every `<DEPOT_PROJECT_ID>`
placeholder in `.depot/workflows/*.yml` to the real project ID.

## Local sanity check (for the agent)

```bash
curl -L https://depot.dev/install-cli.sh | sh
export PATH=$HOME/.depot/bin:$PATH
export DEPOT_TOKEN='depot_org_...'   # from owner
depot whoami
```

## Build order

1. **`ci-base-image.yml`** — builds the runner image with
   firecracker, kraft, docker, depot. Cached as
   `registry.depot.dev/<DEPOT_PROJECT_ID>:base-latest`.
2. **`unikraft-image.yml`** — pulls
   `unikraft.org/helloworld:latest` via kraft, packages the
   `*_fc-x86_64` ELF as `FROM scratch + COPY kernel /kernel`.
   Cached as `helloworld-uk-latest`.
3. **`unikraft-helloworld.yml`** — pulls the cached
   unikernel, boots it under Firecracker, asserts the banner.

## Stage 1 acceptance

- workflow run completes in **< 30 s total**
- firecracker stdout contains the helloworld banner
  ("Hello, World" or similar)
- microVM exits cleanly or is killed once the banner lands
- script-reported boot+exec time is **< 1 s**

## Known gotchas (carried over from aegis)

1. `archive.ubuntu.com` returns Cloudflare HTTP 1010 from
   Depot egress. The base Dockerfile rewrites `apt`
   sources to `mirror.facebook.net` first.
2. Depot CI secret names cannot start with `DEPOT_` — use
   `AEGIS_DEPOT_TOKEN`, inject as `DEPOT_TOKEN` env var
   where the CLI needs it.
3. `docker create` on a `FROM scratch` image errors with
   "no command specified". Pass a dummy arg:
   `docker create unikernel:local /kernel`.
4. The runner image is pulled from the Depot Registry,
   which is private. The `container:` block needs
   `credentials:` (username `depot`, password
   `${{ secrets.AEGIS_DEPOT_TOKEN }}`).
5. Linux 6.8 vmlinux is zstd-compressed — `zstd`, `lz4`,
   `lzop` are pre-installed so `extract-vmlinux` works if
   we later swap in a Linux guest. Not needed for stage 1
   (Unikraft kernels are uncompressed ELF).
6. `dnsmasq-base` ships the binary at `/usr/sbin/dnsmasq`
   on Ubuntu. Matters when stage 2 adds a tap network.

## Reference

- Unikraft: <https://unikraft.org>
- KraftKit: <https://github.com/unikraft/kraftkit>
- Firecracker API spec:
  <https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml>
- Depot CI: <https://depot.dev/docs/ci>
- aegis reference pipeline:
  <https://github.com/N3mes1s/aegis/tree/claude/firecracker-aegis-ci-job-40KrY/.depot/workflows>
