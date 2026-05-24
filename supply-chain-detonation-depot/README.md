# supply-chain-detonation-depot — placeholder

> **This directory is a scaffold for a future experiment that hasn't
> been built yet.** The full spec lives in [`SPEC.md`](SPEC.md). Read
> that first; it links back to two sibling experiments in this same
> repo (`unikraft-firecracker-depot/` PR #18 and
> `ebpf-core-firecracker-depot/` PR #19) which already shipped the
> Firecracker plumbing and the CO-RE eBPF tracer patterns you'll
> reuse here.

## What this is

A planned experiment to turn the FC + CO-RE eBPF stack from PR #19
into a **per-PR supply-chain detonation gate**:

- On any PR that bumps `package-lock.json` / `requirements.txt` /
  similar, spawn a fresh Firecracker microVM per added or bumped
  dependency.
- Inside the guest: run the package's actual `npm install` (or
  `pip install`, etc.) with a CO-RE eBPF probe attached, capturing
  syscalls, network connect targets, file writes outside the
  install root, and `execve` targets.
- Emit a per-package fingerprint as JSON over ttyS0.
- Host-side: diff the fingerprint against a baseline. Fail the PR
  if a package's install-time behaviour mutates without
  explanation (new outbound host, writes to `~/.ssh/`, shell
  invocation during install, etc.).

The point: catch install-time supply-chain attacks (xz-utils-style,
eslint-scope-style, malicious typosquats) BEFORE they land in main.
Static scanners miss runtime behaviour; this gates on actual
observed syscalls.

## How to start

Open a new coding session pointed at this directory, feed it
[`SPEC.md`](SPEC.md). The spec references PRs #18 and #19 for any
plumbing pattern that's already proven and tells the next agent
exactly which files to read for inspiration.

Sibling experiments:

- FC plumbing (PTY for serial, multi-stage Dockerfile, Depot
  Registry x-token auth, `experiment.sh` wrapper):
  <https://github.com/N3mes1s/Playground/pull/18>
- CO-RE eBPF probe, static-musl loader, initrd-as-PID-1, LVH
  kernel-image integration:
  <https://github.com/N3mes1s/Playground/pull/19>
