//! # Kernel Entry Point
//!
//! The very first code that executes. Sets up the stack and calls `kernel_main`.
//! This uses a naked function to avoid any Rust prologue — we control the ABI entirely.

use core::arch::asm;

/// Multiboot2 header — placed in `.multiboot_header` section by the linker script.
/// GRUB and QEMU's `-kernel` flag recognize this.
#[used]
#[link_section = ".multiboot_header"]
static MULTIBOOT_HEADER: [u32; 6] = {
    let magic: u32 = 0xE85250D6; // Multiboot2 magic
    let arch: u32 = 0; // i386 protected mode
    let length: u32 = 24; // Header length
    let checksum: u32 = 0u32.wrapping_sub(magic.wrapping_add(arch).wrapping_add(length));
    // End tag
    [magic, arch, length, checksum, 0, 8]
};

extern "C" {
    static __stack_top: u8;
}

/// Assembly entry point. Sets up the stack pointer and jumps to `kernel_main`.
#[naked]
#[no_mangle]
#[link_section = ".text"]
pub unsafe extern "C" fn _start() -> ! {
    unsafe {
        asm!(
            // Set up the stack
            "lea rsp, [rip + {stack_top}]",
            // Clear the frame pointer for clean backtraces
            "xor rbp, rbp",
            // Call into Rust
            "call kernel_main",
            // If kernel_main returns (it shouldn't), halt
            "2:",
            "hlt",
            "jmp 2b",
            stack_top = sym __stack_top,
            options(noreturn)
        );
    }
}
