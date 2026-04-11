/*
 * REAL BOOT SEQUENCE - Mapped from decompiled sqlservr_FULL.c
 *
 * This documents the EXACT order of operations the real ELF host performs.
 * Our drawbridge-host must replicate this sequence.
 *
 * Phase 1: FUN_00204ee0 - PAL Instance Creation
 * ================================================
 * 1. Allocate 0x20 bytes for PAL instance wrapper
 * 2. Set DAT_0036f598 = param_1 (PAL instance pointer)
 * 3. Set PAL instance fields:
 *    [+0x138] = symbol/module loader
 *    [+0x140] = reference data
 *    [+0x108], [+0x120] = image base info
 *    [+0x180] = data segment
 *    [+0x188] = code segment
 *
 * Phase 2: FUN_0020ba60 - WINDOWS_LIBOS_PARAMETERS Setup
 * ========================================================
 * Called as: FUN_0020ba60(PAL_instance + 400, ...)
 * Sets:
 *   params[0]  = 0x90 (Size)
 *   params[1]  = 0x38 (SubHeaderSize)
 *   params[2]  = &DAT_00369ec8 (HostAbiTable template)
 *   params[3]  = &DAT_003b2138 (RuntimeCallbackState)
 *   params[4]  = 0x18 (StackReservation)
 *   params[7]  = data segment ptr
 *   params[8]  = code segment ptr
 * Then calls FUN_0020bcf0 to init PE sections.
 *
 * Phase 3: FUN_00204680 - PAL Boot (one-time init)
 * ==================================================
 * Guarded by DAT_0036f618 (set to 1 when done).
 * Order of operations:
 *
 *  1. FUN_00354250/60   - Setup runtime parameters
 *  2. FUN_00279cd0      - Initialize logging
 *  3. FUN_0027a2f0      - Setup debugger (conditional)
 *  4. FUN_001bd660      - Check if threading needed
 *  5. FUN_00204bb0      - Create logger thread (conditional)
 *  6. FUN_0021a7d0      - Initialize dynamic linking
 *  7. FUN_0021d1c0      - Module loader setup → FUN_0028e530 check
 *  8. FUN_0021a750      - Library initialization
 *  9. FUN_00252b70      - Open /dev/null → DAT_00369ea8
 * 10. FUN_002890a0      - Thread subsystem init:
 *     a. config = {0xffff00000400, 0, 0, 0xe10}
 *     b. FUN_00355d60(&config) - register scheduler
 *     c. FUN_00279f90(FUN_00252bf0) - register AIO callback
 * 11. FUN_00353a90(1,4,0x400) - setrlimit (soft)
 * 12. FUN_00353a90(2,4,0x400) - setrlimit (hard)
 * 13. FUN_00354270/80   - get/set file descriptor limits
 * 14. DAT_0036f618 = 1  - Mark init complete
 * 15. FUN_0022a5a0      - Further init
 * 16. FUN_00235a80      - Further init
 * 17. FUN_00244790      - Further init
 * 18. FUN_001f1c50      - Create FileIoCompletionPort:
 *     a. Allocate 0x1c0 bytes
 *     b. FUN_001f1fd0() - constructor
 *     c. io_setup(0x400, &ctx) via FUN_00202100
 * 19. FUN_00279f10      - Finalize I/O
 * 20. Set PAL[+8] = 1   - Boot status = booted
 * 21. Allocate event objects (0x20 bytes each)
 * 22. FUN_00204da0      - Kernel version logging
 *
 * Phase 4: Thread Creation (FUN_00252e60)
 * ========================================
 * Allocates 0xAA0 bytes for KTHREAD.
 * Fields set:
 *   [+0x12] = thread ID (from global counter DAT_003b21c0)
 *   [+0x13] = next thread (linked list)
 *   [+0x14] = prev thread
 *   [+0x58] = entry function
 *   [+0x60] = thread parameter
 *   [+0x68] = event object (optional)
 *   [+0x70] = stack size hint
 *   [+0x15] = thread dispatcher function
 *
 * Phase 5: Thread Entry Thunk (FUN_00253350)
 * ============================================
 * Per-thread setup:
 *   1. FUN_003553f0   - Get thread-local memory
 *   2. FUN_00355400/10/3e0 - Allocate and init stack
 *   3. Set thread[+0x18] = stack base
 *   4. Set thread[+0x10] = stack top
 *   5. FUN_001fa9c0   - Allocate TEB (malloc 0x10000)
 *      Stores at thread[+0x88], memset 0xb0 bytes to 0
 *   6. FUN_00252c90   - Set GS/FS base (arch_prctl)
 *   7. Jump to thread entry
 *
 * GLOBALS WRITTEN DURING BOOT:
 * =============================
 * DAT_0036f598 = PAL instance pointer
 * DAT_0036f5a0 = PAL smart pointer
 * DAT_0036f618 = boot complete flag (1)
 * DAT_00369ea8 = /dev/null fd
 * DAT_003b2198 = thread list mutex
 * DAT_003b21c0 = thread ID counter
 * DAT_003b21c8 = thread list head
 * DAT_00369ec8 = HostAbiTable template {0x10, 0x38, sentinel}
 * DAT_003b2138 = RuntimeCallbackState (256 bytes)
 */
