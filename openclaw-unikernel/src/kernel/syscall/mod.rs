//! # Syscall Shim Layer
//!
//! In a unikernel there is no userspace/kernel boundary, so traditional
//! syscalls don't exist. This module provides a compatibility layer that
//! maps POSIX-like operations to direct kernel function calls.
//!
//! This enables code written against standard abstractions to work
//! without modification.

use alloc::string::String;
use alloc::vec::Vec;

/// File descriptor table — maps fd numbers to kernel resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    /// Standard input (serial/console)
    Stdin,
    /// Standard output (serial/console)
    Stdout,
    /// Standard error (serial/console)
    Stderr,
    /// Network socket
    Socket(usize),
    /// In-memory file (ramfs)
    File(usize),
}

/// Global file descriptor table.
static mut FD_TABLE: Option<Vec<Option<FdKind>>> = None;

/// Initialize the fd table with stdin/stdout/stderr.
pub fn init() {
    unsafe {
        let mut table = Vec::with_capacity(256);
        table.push(Some(FdKind::Stdin));   // fd 0
        table.push(Some(FdKind::Stdout));  // fd 1
        table.push(Some(FdKind::Stderr));  // fd 2
        FD_TABLE = Some(table);
    }
}

/// Allocate a new file descriptor.
pub fn alloc_fd(kind: FdKind) -> i32 {
    unsafe {
        if let Some(ref mut table) = FD_TABLE {
            // Find first free slot
            for (i, slot) in table.iter_mut().enumerate() {
                if slot.is_none() {
                    *slot = Some(kind);
                    return i as i32;
                }
            }
            // No free slot — extend
            let fd = table.len() as i32;
            table.push(Some(kind));
            fd
        } else {
            -1
        }
    }
}

/// Close a file descriptor.
pub fn close_fd(fd: i32) -> i32 {
    unsafe {
        if let Some(ref mut table) = FD_TABLE {
            let idx = fd as usize;
            if idx < table.len() && table[idx].is_some() {
                table[idx] = None;
                return 0;
            }
        }
        -1
    }
}

/// Look up what a file descriptor refers to.
pub fn lookup_fd(fd: i32) -> Option<FdKind> {
    unsafe {
        if let Some(ref table) = FD_TABLE {
            let idx = fd as usize;
            if idx < table.len() {
                return table[idx];
            }
        }
        None
    }
}

/// Write to a file descriptor.
pub fn sys_write(fd: i32, buf: &[u8]) -> isize {
    match lookup_fd(fd) {
        Some(FdKind::Stdout) | Some(FdKind::Stderr) => {
            for &b in buf {
                crate::kernel::console::puts(
                    core::str::from_utf8(&[b]).unwrap_or("?")
                );
            }
            buf.len() as isize
        }
        Some(FdKind::Socket(sock_id)) => {
            // Delegate to network stack
            crate::net::tcp::send(sock_id, buf)
        }
        _ => -1,
    }
}

/// Read from a file descriptor.
pub fn sys_read(fd: i32, buf: &mut [u8]) -> isize {
    match lookup_fd(fd) {
        Some(FdKind::Stdin) => {
            // Read from serial port
            if buf.is_empty() {
                return 0;
            }
            let byte = unsafe { crate::kernel::inb(0x3F8) };
            buf[0] = byte;
            1
        }
        Some(FdKind::Socket(sock_id)) => {
            crate::net::tcp::recv(sock_id, buf)
        }
        _ => -1,
    }
}

/// Get the current "time" as a monotonic counter (TSC-based).
pub fn sys_clock_gettime() -> u64 {
    crate::kernel::rdtsc()
}

/// Sleep for approximately `ms` milliseconds.
/// In a unikernel, this busy-waits while yielding to the scheduler.
pub fn sys_sleep_ms(ms: u64) {
    let start = crate::kernel::rdtsc();
    // Approximate: assume ~2 GHz TSC (this should be calibrated at boot)
    let ticks = ms * 2_000_000;
    while crate::kernel::rdtsc() - start < ticks {
        crate::kernel::sched::yield_now();
    }
}

/// Get environment variable (from in-memory config).
pub fn sys_getenv(_name: &str) -> Option<String> {
    // In the unikernel, environment variables come from the config system
    crate::config::get_env(_name)
}
