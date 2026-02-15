//! # Boot Sequence
//!
//! Handles the x86_64 boot process:
//! 1. Multiboot2 header for GRUB/QEMU compatibility
//! 2. Initial 32-bit entry point
//! 3. GDT setup and long mode transition
//! 4. Page table setup (identity + higher-half mapping)
//! 5. Jump to 64-bit `kernel_main`

pub mod entry;
pub mod gdt;
pub mod paging;

pub use entry::_start;
