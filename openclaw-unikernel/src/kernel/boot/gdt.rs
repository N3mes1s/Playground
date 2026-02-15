//! # Global Descriptor Table (GDT)
//!
//! Minimal 64-bit GDT for the unikernel. Since we run everything in ring 0
//! (single address space, no userspace), we only need:
//! - Null descriptor
//! - Kernel code segment (64-bit)
//! - Kernel data segment

use core::arch::asm;

/// GDT entry — 8 bytes each.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

impl GdtEntry {
    const fn null() -> Self {
        GdtEntry {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    const fn kernel_code() -> Self {
        GdtEntry {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x9A,       // Present, Ring 0, Code, Execute/Read
            granularity: 0xAF,  // 64-bit, 4K granularity
            base_high: 0,
        }
    }

    const fn kernel_data() -> Self {
        GdtEntry {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x92,       // Present, Ring 0, Data, Read/Write
            granularity: 0xCF,  // 32-bit (data), 4K granularity
            base_high: 0,
        }
    }
}

/// The GDT pointer structure for LGDT.
#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u64,
}

static GDT: [GdtEntry; 3] = [
    GdtEntry::null(),
    GdtEntry::kernel_code(),
    GdtEntry::kernel_data(),
];

/// Load the GDT and reload segment registers.
pub fn init() {
    let gdt_ptr = GdtPointer {
        limit: (core::mem::size_of_val(&GDT) - 1) as u16,
        base: &GDT as *const _ as u64,
    };

    unsafe {
        asm!(
            "lgdt [{}]",
            in(reg) &gdt_ptr,
            options(nostack)
        );

        // Reload code segment via far return
        asm!(
            "push 0x08",        // Kernel code segment selector
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            // Reload data segments
            "mov ax, 0x10",     // Kernel data segment selector
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            out("rax") _,
            options(nostack)
        );
    }
}
