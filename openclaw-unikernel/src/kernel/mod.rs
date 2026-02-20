//! # Kernel Layer
//!
//! The lowest layer of the OpenClaw unikernel. Provides:
//! - Boot sequence (GDT, page tables, multiboot)
//! - Memory management (physical frame allocator, heap allocator)
//! - Cooperative scheduler (async task executor)
//! - Synchronization primitives (spinlock, mutex, semaphore)
//! - Console I/O (VGA text mode + serial port)
//! - Port I/O and hardware abstraction

pub mod boot;
pub mod mm;
pub mod sched;
pub mod sync;
pub mod syscall;
pub mod console;

use core::arch::asm;

/// Halt the CPU until the next interrupt.
#[inline(always)]
pub fn halt() {
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }
}

/// Disable interrupts.
#[inline(always)]
pub fn cli() {
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

/// Enable interrupts.
#[inline(always)]
pub fn sti() {
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Read a byte from an I/O port.
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Write a byte to an I/O port.
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Read the CPU timestamp counter.
#[inline(always)]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}
