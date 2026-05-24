# ebpf-core-firecracker-depot — placeholder

> **This directory is a scaffold for a future experiment that hasn't
> been built yet.** The full spec lives in [`SPEC.md`](SPEC.md). Read
> that first; it links back to a sibling experiment in this same
> repo (`unikraft-firecracker-depot/`, PR #18) which already shipped
> the Firecracker plumbing patterns you'll reuse here.

## What this is

A planned experiment to demonstrate CO-RE (Compile Once, Run Everywhere)
eBPF probe loading **across multiple Linux kernel versions** inside
Firecracker microVMs on Depot CI's nested-virt runners. The "kernel
matrix in regular CI" capability is the genuinely new thing the
nested-virt runners unlock; everything else has been possible on
privileged CI containers for years.

## How to start

Open a new coding session in this repo, point it at this directory,
and feed it `SPEC.md`. The spec is self-contained and references the
sibling PR for any plumbing pattern that's already proven.

Sibling experiment (FC plumbing already shipped, read this for patterns):
<https://github.com/N3mes1s/Playground/pull/18>
