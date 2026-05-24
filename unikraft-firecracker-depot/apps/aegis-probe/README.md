# aegis-probe — a minimal native Unikraft unikernel

A C program built into a self-contained Unikraft unikernel ELF by
`kraft build`. Boots under Firecracker in ~210 ms, ~249 KB stripped.
No rootfs, no Linux ELF loader, no syscall translation.

## Files

- **`main.c`** — the application. Prints a banner + JSON status line
  + returns. On `return`, Unikraft's libukboot halts the unikernel
  cleanly (Firecracker `exit_code=0`).
- **`Makefile.uk`** — Unikraft "app library" registration. Tells the
  build system which source files belong to this app.
- **`Makefile`** — wrapper that delegates to the Unikraft build
  system in `.unikraft/unikraft/`. Standard upstream pattern.
- **`Kraftfile`** — spec v0.6 config: pins unikraft@stable, target
  `fc/x86_64`.

## How to change what the unikernel does

1. Edit `main.c`. (For more source files, append to `Makefile.uk`
   as `APPAEGISPROBE_SRCS-y += $(APPAEGISPROBE_BASE)/<file>.c`.)
2. From the experiment root, rebuild the runner image:
   ```bash
   ./experiment.sh build-native-image
   ```
   This kraft-builds the unikernel on Depot's BuildKit, bakes the
   resulting ELF + firecracker into a new runner image, and saves
   it to the Depot Registry. ~30 s cached, ~5 min on first build
   ever for this project.
3. Boot it:
   ```bash
   ./experiment.sh boot-native
   ```
   ~10 s wall.

## Notes

- The unikernel binary lands at
  `.unikraft/build/aegis-probe_fc-x86_64` in the build context
  (with a `.dbg` debug-info variant alongside). The build Dockerfile
  copies just the stripped one into the runner image.
- Boot args follow Unikraft's `<app_name> -- <app_args>` convention.
  The default in `scripts/run_unikernel.sh` is `kernel -- ` (empty
  args). Override via the `BOOT_ARGS` env var if you want to pass
  argv to `main`.
- The unikernel runs as a single address-space binary — there's no
  shell, no init, no userland. Anything you'd normally fork/exec
  has to be linked in at build time.
