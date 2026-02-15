//! # Boot Sequence
//!
//! Handles the x86_64 boot process:
//! 1. Multiboot1/2 headers for GRUB and QEMU compatibility
//! 2. 32-bit trampoline: page tables + long mode transition
//! 3. 64-bit entry: reload segments, set stack, call kernel_main

pub mod entry;
pub mod gdt;
pub mod paging;
