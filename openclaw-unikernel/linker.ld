/* OpenClaw Unikernel — Linker Script
 * Maps the kernel into the higher-half of virtual memory.
 * Entry point: _start (defined in src/kernel/boot/entry.rs)
 */

ENTRY(_start)

KERNEL_OFFSET = 0xFFFFFF8000000000;

SECTIONS
{
    /* Physical load address at 1 MiB (above legacy BIOS area) */
    . = 1M;

    .boot :
    {
        KEEP(*(.multiboot_header))
    }

    /* Kernel code mapped at higher-half */
    . = KERNEL_OFFSET + 2M;

    .text ALIGN(4K) :  AT(ADDR(.text) - KERNEL_OFFSET)
    {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_OFFSET)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_OFFSET)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_OFFSET)
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

    /* Heap region: 16 MiB initial, growable */
    . = ALIGN(4K);
    __heap_start = .;
    . += 16M;
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
