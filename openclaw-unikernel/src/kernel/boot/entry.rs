//! # Kernel Entry Point
//!
//! Boots from Multiboot (via GRUB or QEMU) in 32-bit protected mode,
//! sets up identity-mapped paging, transitions to 64-bit long mode,
//! and calls `kernel_main`.

use core::arch::global_asm;

global_asm!(
    // ═══════════════════════════════════════════════════════════════
    // Multiboot2 header (for GRUB2)
    // ═══════════════════════════════════════════════════════════════
    ".section .multiboot_header, \"a\"",
    ".align 8",
    "mb2_start:",
    ".long 0xE85250D6",         // magic
    ".long 0",                   // architecture: i386
    ".long 24",                  // header length
    ".long 0x17ADAF12",         // checksum = -(magic + arch + length)
    ".short 0",                  // end tag type
    ".short 0",                  // end tag flags
    ".long 8",                   // end tag size

    // ═══════════════════════════════════════════════════════════════
    // Multiboot1 header (for QEMU -kernel)
    // ═══════════════════════════════════════════════════════════════
    ".align 4",
    ".long 0x1BADB002",         // magic
    ".long 0x00000003",         // flags: page-align modules + memory info
    ".long 0xE4524FFB",         // checksum = -(magic + flags)

    // ═══════════════════════════════════════════════════════════════
    // 32-bit trampoline: identity-map 1 GiB, enable long mode
    // ═══════════════════════════════════════════════════════════════
    ".section .boot_text, \"ax\"",
    ".code32",
    ".global _start",
    "_start:",
    "cli",

    // Save multiboot info pointer (passed in %ebx)
    "movl %ebx, %edi",

    // Set up temporary boot stack
    "leal boot_stack_top, %esp",

    // Zero page tables: PML4 + PDPT + PD = 12 KiB = 3072 dwords
    "pushl %edi",
    "leal boot_pml4, %edi",
    "xorl %eax, %eax",
    "movl $3072, %ecx",
    "rep stosl",
    "popl %edi",

    // PML4[0] -> PDPT | PRESENT | WRITABLE
    "leal boot_pdpt, %eax",
    "orl $0x3, %eax",
    "movl %eax, boot_pml4",

    // PDPT[0] -> PD | PRESENT | WRITABLE
    "leal boot_pd, %eax",
    "orl $0x3, %eax",
    "movl %eax, boot_pdpt",

    // Fill PD[0..512] with 2 MiB identity-mapped pages (covers 1 GiB)
    "xorl %ecx, %ecx",
    "2:",
    "movl %ecx, %eax",
    "shll $21, %eax",              // eax = ecx * 2 MiB
    "orl $0x83, %eax",             // PRESENT | WRITABLE | PAGE_SIZE (2 MiB)
    "leal boot_pd(,%ecx,8), %edx",
    "movl %eax, (%edx)",
    "movl $0, 4(%edx)",            // high 32 bits = 0
    "incl %ecx",
    "cmpl $512, %ecx",
    "jb 2b",

    // Enable PAE (CR4.PAE = bit 5)
    "movl %cr4, %eax",
    "orl $0x20, %eax",
    "movl %eax, %cr4",

    // Load PML4 into CR3
    "leal boot_pml4, %eax",
    "movl %eax, %cr3",

    // Enable Long Mode (IA32_EFER.LME = bit 8)
    "movl $0xC0000080, %ecx",
    "rdmsr",
    "orl $0x100, %eax",
    "wrmsr",

    // Enable Paging (CR0.PG = bit 31)
    "movl %cr0, %eax",
    "orl $0x80000000, %eax",
    "movl %eax, %cr0",

    // Load 64-bit GDT
    "lgdt gdt64_ptr",

    // Far jump to 64-bit code segment via lret
    "pushl $0x08",                  // Code64 segment selector
    "pushl $_start64",              // 32-bit target address
    "lret",

    // ═══════════════════════════════════════════════════════════════
    // 64-bit entry: reload segments, set kernel stack, call main
    // ═══════════════════════════════════════════════════════════════
    ".section .text",
    ".code64",
    ".global _start64",
    "_start64:",

    // Reload data segment registers with data selector
    "movw $0x10, %ax",
    "movw %ax, %ds",
    "movw %ax, %es",
    "movw %ax, %fs",
    "movw %ax, %gs",
    "movw %ax, %ss",

    // Set up the real kernel stack (defined in linker script)
    "leaq __stack_top(%rip), %rsp",
    "xorq %rbp, %rbp",

    // Jump to kernel_main — never returns
    "call kernel_main",

    // Safety halt loop
    "3: hlt",
    "jmp 3b",

    // ═══════════════════════════════════════════════════════════════
    // GDT for the 32-to-64-bit transition
    // ═══════════════════════════════════════════════════════════════
    ".section .rodata",
    ".align 16",
    "gdt64:",
    ".quad 0",                           // 0x00: Null descriptor
    ".quad 0x00AF9A000000FFFF",          // 0x08: Code64 (L=1 D=0 P=1 DPL=0)
    ".quad 0x00CF92000000FFFF",          // 0x10: Data   (P=1 DPL=0 W=1)
    "gdt64_ptr:",
    ".short 23",                         // limit = 3*8 - 1
    ".long gdt64",                       // base (32-bit address, used in .code32)

    // ═══════════════════════════════════════════════════════════════
    // Boot-time BSS: page tables + temporary stack
    // ═══════════════════════════════════════════════════════════════
    ".section .bss",
    ".align 4096",
    "boot_pml4: .space 4096",
    "boot_pdpt: .space 4096",
    "boot_pd: .space 4096",
    ".align 16",
    "boot_stack_bottom: .space 16384",   // 16 KiB temporary boot stack
    "boot_stack_top:",

    options(att_syntax),
);
