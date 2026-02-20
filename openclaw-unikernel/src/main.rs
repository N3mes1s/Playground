//! # OpenClaw Unikernel
//!
//! A bare-metal Rust unikernel implementing the full OpenClaw AI agent platform.
//! This is a single-address-space operating system image that boots directly into
//! the AI agent runtime — no userspace/kernel boundary, no syscall overhead.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                   OpenClaw Agent Loop                    │
//! │  ┌──────────┐ ┌──────────┐ ┌───────┐ ┌──────────────┐  │
//! │  │ Providers │ │ Channels │ │ Tools │ │    Skills     │  │
//! │  └────┬─────┘ └────┬─────┘ └───┬───┘ └──────┬───────┘  │
//! │       │             │           │             │          │
//! │  ┌────▼─────────────▼───────────▼─────────────▼───────┐ │
//! │  │              Memory System (FTS + Vector)           │ │
//! │  └────────────────────┬────────────────────────────────┘ │
//! │                       │                                  │
//! │  ┌────────────────────▼────────────────────────────────┐ │
//! │  │           Security Policy Engine                     │ │
//! │  │  (ChaCha20 · Pairing · Allowlists · Rate Limits)    │ │
//! │  └────────────────────┬────────────────────────────────┘ │
//! ├───────────────────────┼──────────────────────────────────┤
//! │                  Kernel Layer                            │
//! │  ┌─────────┐ ┌───────▼───────┐ ┌────────┐ ┌──────────┐ │
//! │  │  Boot   │ │  Net Stack    │ │ Sched  │ │  Memory  │ │
//! │  │ (x86_64)│ │ (TCP/TLS/HTTP)│ │(Cooperative)│ │(Alloc) │ │
//! │  └─────────┘ └───────────────┘ └────────┘ └──────────┘ │
//! │                    Hardware (QEMU/KVM/Bare Metal)        │
//! └─────────────────────────────────────────────────────────┘
//! ```

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
// Unikernel: single-core cooperative scheduling makes static mut safe.
// Many modules define infrastructure that isn't all called yet (stubs for
// future channels, security primitives, etc.) — suppress dead_code globally.
#![allow(static_mut_refs)]
#![allow(dead_code)]

extern crate alloc;

// ── Kernel subsystems ──────────────────────────────────────────────────────
mod kernel;

// ── Network stack ──────────────────────────────────────────────────────────
mod net;

// ── Agent platform ─────────────────────────────────────────────────────────
mod providers;
mod channels;
mod memory;
mod tools;
mod security;
mod agent;
mod config;
mod cron;
mod heartbeat;
mod gateway;
mod daemon;
mod skills;
mod observability;
mod onboard;
mod integrations;
mod util;
mod tunnel;
mod migration;
mod doctor;
mod identity;

use core::panic::PanicInfo;
use kernel::console;

/// Kernel entry point — called from the boot assembly stub after basic
/// hardware initialization (GDT, page tables, stack).
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // Phase 1: Hardware initialization
    console::init();
    console::puts("[openclaw] booting unikernel v0.1.0\n");

    kernel::mm::init_heap();
    console::puts("[openclaw] heap initialized (512 MiB)\n");

    kernel::sched::init();
    console::puts("[openclaw] cooperative scheduler ready\n");

    // Phase 2: Network stack
    net::init();
    console::puts("[openclaw] network stack initialized (TCP/IP + TLS 1.3)\n");

    // Phase 3: Security subsystem
    security::init();
    console::puts("[openclaw] security policy engine loaded\n");

    // Phase 4: Memory / brain
    memory::init();
    console::puts("[openclaw] memory system ready (FTS + vector search)\n");

    // Phase 5: Load configuration
    config::init();
    console::puts("[openclaw] configuration loaded\n");

    // Phase 6: Start the agent
    console::puts("[openclaw] starting agent loop...\n");
    console::puts("============================================\n");
    console::puts("  OpenClaw Unikernel Agent v0.1.0\n");
    console::puts("  Zero overhead. Zero compromise.\n");
    console::puts("  Bare-metal AI agent runtime.\n");
    console::puts("============================================\n\n");

    // Enter the main agent daemon loop — this never returns
    daemon::run();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    console::puts("\n!!! KERNEL PANIC !!!\n");
    if let Some(location) = info.location() {
        console::puts("  at ");
        console::puts(location.file());
        console::puts("\n");
    }
    if let Some(msg) = info.message().as_str() {
        console::puts("  ");
        console::puts(msg);
        console::puts("\n");
    }
    loop {
        kernel::halt();
    }
}

#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    console::puts("!!! OUT OF MEMORY !!!\n");
    loop {
        kernel::halt();
    }
}
