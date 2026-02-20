/* OpenClaw Unikernel — Linker Script
 * Identity-mapped kernel at low physical addresses.
 * Entry point: _start (defined in src/kernel/boot/entry.rs)
 */

ENTRY(_start)

SECTIONS
{
    /* Physical load address at 1 MiB (above legacy BIOS area) */
    . = 1M;

    .boot :
    {
        KEEP(*(.multiboot_header))
        *(.boot_text)
    }

    /* Kernel sections starting at 2 MiB */
    . = 2M;

    .text ALIGN(4K) :
    {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) :
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4K) :
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    .bss ALIGN(4K) :
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Stack: 64 KiB */
    . = ALIGN(4K);
    __stack_bottom = .;
    . += 64K;
    __stack_top = .;

    /* Heap region: 512 MiB — accounts for allocator fragmentation over 100 cycles */
    . = ALIGN(4K);
    __heap_start = .;
    . += 512M;
    __heap_end = .;

    /* Network buffer pool: 4 MiB */
    . = ALIGN(4K);
    __net_buffer_start = .;
    . += 4M;
    __net_buffer_end = .;

    __kernel_end = .;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.comment)
        *(.note.*)
    }
}
