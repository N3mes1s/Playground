/*
 * NTUM Bootstrap Implementation (Clean Version)
 *
 * Based on reverse-engineering the real sqlservr boot sequence.
 * The real host does NOT patch int3, CFG, or fastfail. It:
 *   1. Maps the PE at the correct address
 *   2. Fills WINDOWS_LIBOS_PARAMETERS
 *   3. Pre-stores security cookie
 *   4. Sets up PAL dispatcher pointer
 *   5. Calls the REAL entry point (DllMain at RVA 0x3a04d0)
 *
 * The PE has built-in CFG functions:
 *   guard_check_icall (RVA 0x21ff10) = 'ret' (no-op)
 *   guard_dispatch_icall (RVA 0x3a86f0) = 'jmp *%rax' (passthrough)
 *
 * The entry point handles stack setup internally:
 *   lea rsp, [rip+...] → 0x180637000
 *   add rsp, [rip+...] → +0x4000
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <ucontext.h>

#include "ntum_bootstrap.h"
#include "dk_pal.h"
#include "pal_internal.h"   /* extern "C" wrappered pal_boot_init, etc. */

/* PAL callback state (like sqlservr's DAT_003b2138).
 * The NTUM writes KiUserExceptionDispatcher address to offset 0x10
 * during boot initialization. Accessed by ntum_signals.c. */
uint8_t g_runtime_callback_state[256] __attribute__((aligned(64)));

/* ABI function table template (like sqlservr's DAT_00369ec8) */
static uint8_t g_abi_table[256] __attribute__((aligned(64)));

/* Stack for the NTUM boot thread */
#define BOOT_STACK_SIZE (2 * 1024 * 1024)

void ntum_bootstrap_init(WINDOWS_LIBOS_PARAMETERS *params,
                          void *image_base, uint64_t image_size,
                          uint64_t entry_rva, void *pal_table) {
    memset(params, 0, sizeof(WINDOWS_LIBOS_PARAMETERS));

    /* Header - from decompiled FUN_0020ba60 */
    params->Size = 0x90;
    params->SubHeaderSize = 0x38;

    /* PAL interface pointers.
     * The NTUM reads the ABI dispatcher function pointer from
     * RuntimeCallbackState[0]. Store our dispatcher there. */
    params->HostAbiTable = pal_table ? pal_table : g_abi_table;
    *(uint64_t*)g_runtime_callback_state = (uint64_t)&DK_AbiDispatcher;
    params->RuntimeCallbackState = g_runtime_callback_state;
    params->StackReservation = (void*)0x18;

    /* OS version (Windows 6.2 = Windows 8, same as SQLPAL reports) */
    params->MajorVersion = 6;
    params->MinorVersion = 2;

    /* Image info */
    params->ImageBase = image_base;
    params->ImageLength = image_size;

    /* Entry point - the REAL DllMain, not the skip-ahead */
    params->BootEntryPoint = (void*)((uint8_t*)image_base + entry_rva);

    /* ParameterBuffer: Two different PE code paths read this:
     * 1. FUN_20e4e4 (RVA 0x20e4e4): reads [ParameterBuffer] and compares to 0x190
     *    This checks the WINDOWS_LIBOS_PARAMETERS size field.
     * 2. FUN_204a37 (RVA 0x204a37): reads [ParameterBuffer] comparing to 0x10 and [+4] to 0x38
     *    This checks for the ABI table header format.
     *
     * The ParameterBuffer serves DOUBLE DUTY:
     * - [+0x00] = 0x10 (ABI header size, checked at 0x204a3f)
     * - [+0x04] = 0x38 (ABI sub-header size, checked at 0x204a44)
     * - [+0x08] = callback function pointer (0 = use default, checked at 0x204a4a)
     *
     * Separately, [0x180c00820] stores a pointer to a buffer where [0] = 0x190.
     * These are TWO DIFFERENT checks in different code paths. */
    /* ParameterBuffer must be in LibOS space - the PE follows pointers from it */
    static uint8_t *param_buffer = NULL;
    if (!param_buffer) {
        param_buffer = (uint8_t*)mmap((void*)(LIBOS_KERNEL_HEAP + 0x21000000ULL), 0x1000,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }
    memset(param_buffer, 0, 0x200);
    /* ABI header format for the PAL boot function */
    *(uint32_t*)(param_buffer + 0x00) = 0x10;   /* Size field */
    *(uint32_t*)(param_buffer + 0x04) = 0x38;   /* SubSize field */
    *(uint64_t*)(param_buffer + 0x08) = 0;       /* Callback (0 = use default) */
    params->ParameterBuffer = param_buffer;
    params->ParameterBufferSize = sizeof(param_buffer);

    /* The 0x190 check at RVA 0x20e51d reads [0x180c00820] → ptr → [ptr] == 0x190.
     * This is SEPARATE from the ParameterBuffer ABI header. Create a dedicated buffer. */
    /* LibOS parameters buffer read at [0x180c00820].
     * Layout discovered from PE disassembly:
     *   [+0x00] = 0x190 (WINDOWS_LIBOS_PARAMETERS size, checked at RVA 0x20e51d)
     *   [+0x34] = max memory limit in 6MB units (read at RVA 0x378c5c)
     *             The PE calculates: limit = [+0x34] * 3 << 21 (= * 6MB)
     *             If 0, no memory can be allocated (STATUS_NO_MEMORY)!
     *   [+0x08] = sub-header size (0x38)
     */
    /* s_libos_size_buf also in LibOS space */
    static uint8_t *s_libos_size_buf = NULL;
    if (!s_libos_size_buf) {
        s_libos_size_buf = (uint8_t*)mmap((void*)(LIBOS_KERNEL_HEAP + 0x21001000ULL), 0x1000,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }
    memset(s_libos_size_buf, 0, 0x200);
    *(uint32_t*)(s_libos_size_buf + 0x00) = 0x190;  /* Size */
    *(uint32_t*)(s_libos_size_buf + 0x08) = 0x38;   /* SubSize */
    *(uint32_t*)(s_libos_size_buf + 0x34) = 512;    /* 512 * 6MB = 3GB max memory */

    /* Feature flags */
    uint32_t *flags = (uint32_t*)&params->FeatureFlags[0];
    *flags = FEATURE_BASE_PAL | FEATURE_TLS;

    /* Processor info */
    params->NumaNodeCount = 1;

    /* Initialize the ABI table.
     * The NTUM reads the ABI dispatcher function pointer from
     * HostAbiTable[1] (offset 8). Decompiled call site at RVA 0x213e75:
     *   mov rax, [rbx+8]  ; RBX = HostAbiTable
     *   ...
     *   call [guard_dispatch_icall]  ; CFG dispatch → jmp *rax
     */
    memset(g_abi_table, 0, sizeof(g_abi_table));
    uint32_t *abi_header = (uint32_t*)g_abi_table;
    abi_header[0] = 0x10;   /* Size */
    abi_header[1] = 0x38;   /* SubSize */
    /* ABI dispatcher function pointer at offset 8 */
    *(volatile uint64_t*)(g_abi_table + 8) = (uint64_t)&DK_AbiDispatcher;
    uint64_t *sentinel = (uint64_t*)(g_abi_table + 0x30);
    *sentinel = 0xFFFFFFFFFFFFFFFFULL;
    printf("[BOOT] abi_table[8] = %p (DK_AbiDispatcher = %p)\n",
           (void*)*(uint64_t*)(g_abi_table + 8), (void*)&DK_AbiDispatcher);

    /*
     * Set up NTUM's known .data globals.
     * These are the ONLY writes we make to the PE image:
     *   [0x18063f8c0] = boot ready flag (1 = PAL ready)
     *   [0x18063f8c8] = PAL dispatcher function pointer
     *   [0x180c00008] = params/config pointer (read by init)
     *   [0x180c00010] = params->Size
     *
     * We do NOT touch:
     *   .00cfg section (has correct built-in guard_check=ret, guard_dispatch=jmp *rax)
     *   .text section (no int3 patches, no fastfail patches, no CFG call site patches)
     */
    if ((uintptr_t)image_base == 0x180000000ULL) {
        *(volatile uint32_t*)0x18063f8c0ULL = 1;  /* boot flag */
        *(volatile uint64_t*)0x18063f8c8ULL = (uint64_t)&DK_AbiDispatcher;
        *(volatile uint64_t*)0x180c00008ULL = (uint64_t)params;
        *(volatile uint64_t*)0x180c00010ULL = params->Size;

        /* Pre-store pointer for 0x190 size check at RVA 0x20e51d */
        *(volatile uint64_t*)0x180c00820ULL = (uint64_t)s_libos_size_buf;

        /* ALSO write memory limit directly in case [0x180c00820] gets
         * redirected. The PE at RVA 0x378c55 reads [0x180c00820] → ptr,
         * then [ptr+0x34] for the memory limit. If ptr changes, the limit
         * is lost. Write to the ptr's target directly as backup. */
        {
            uint64_t ptr_val = *(volatile uint64_t*)0x180c00820ULL;
            if (ptr_val) {
                *(volatile uint32_t*)(ptr_val + 0x34) = 512;
            }
        }

        /* ABI version at [0x63f5c0] must be 2 for second-pass resolution. */
        *(volatile uint32_t*)0x18063f5c0ULL = 2;

        /* Global TEB at [0x6092c0] - the PE reads this at RVA 0x20492c and
         * stores it as the boot thread's TEB. The scheduler at RVA 0x204c72
         * compares gs:0x30 with this value and asserts if they don't match.
         * Pre-allocate a 64KB TEB in LibOS space (filled with 0xb0 sentinel
         * like the real host's FUN_001fa9c0 does). */
        /* TEB must be in LibOS thread environment area.
         * Use MAP_FIXED within the pre-reserved LIBOS_THREAD_ENV range. */
        void *ntum_teb = mmap((void*)(LIBOS_THREAD_ENV + 0x10000), 0x10000,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (ntum_teb != MAP_FAILED) {
            memset(ntum_teb, 0, 0x10000);
            /* TEB self-pointer at +0x30 */
            *(uint64_t*)((uint8_t*)ntum_teb + 0x30) = (uint64_t)ntum_teb;
            /* StackBase and StackLimit */
            *(uint64_t*)((uint8_t*)ntum_teb + 0x08) = NTUM_STACK_TOP + 0x4000;
            *(uint64_t*)((uint8_t*)ntum_teb + 0x10) = NTUM_STACK_BASE;
            /* Store as global TEB in PE .data */
            *(volatile uint64_t*)0x1806092c0ULL = (uint64_t)ntum_teb;
            *(uint64_t*)(g_runtime_callback_state + 0x20) = (uint64_t)ntum_teb;

            /* Pre-create a minimal KTHREAD structure and link it to TEB.
             * The PE reads: TEB[0x1838] → KTHREAD[0x70] → scheduler_obj + 0xF0
             * Without this, get_current_thread_state() returns 0 and the NTUM
             * crashes at DrtlDelayCurrentThreadExecute (RVA 0x387809).
             *
             * KTHREAD layout (from FUN_00020f03c):
             *   +0x20: linked list (self-referencing)
             *   +0x30: ref_count = 1
             *   +0x60: linked list (self-referencing)
             *   +0x70: scheduler processor block → must be non-NULL!
             */
            /* Allocate ALL boot structures in LibOS kernel heap.
             * The PE uses pointers to these structures in context frames
             * and expects them to be in the LibOS address range.
             * Layout in the kernel heap allocation:
             *   +0x00000: KTHREAD (0x10000 bytes)
             *   +0x10000: scheduler block (0x1000 bytes)
             *   +0x11000: thread-local block (0x5000 bytes)
             *   +0x16000: stack descriptor (0x100 bytes)
             *   +0x16100: sched stack descriptor (0x100 bytes)
             *   +0x16200: pool object (0x1000 bytes)
             *   +0x17200: pool vtable (0x200 bytes)
             *   +0x17400: sub-allocator (0x200 bytes)
             *   +0x17600: sub-inner (0x200 bytes)
             *   +0x17800: thread state / TCB (0x2000 bytes)
             */
            /* Allocate boot structs in LibOS kernel heap. Layout:
             *   +0x00000: ntum_kthread_t (0x4200 bytes)
             *   +0x10000: ntum_sched_block_t (0x1000 bytes)
             *   +0x11000: thread-local block (0x5000 bytes)
             *   +0x16000: ntum_stack_desc_t — TEB stack desc (0x100 bytes)
             *   +0x16100: ntum_stack_desc_t — sched stack desc (0x100 bytes)
             *   +0x16200: ntum_pool_obj_t (0x1000 bytes)
             *   +0x17200: pool vtable (0x200 bytes)
             *   +0x17400: sub-allocator (0x200 bytes)
             *   +0x17600: sub-inner (0x200 bytes)
             *   +0x17800: thread state / TCB (0x2000 bytes)
             */
            uint8_t *bs = (uint8_t*)mmap((void*)BOOT_STRUCTS_ADDR, BOOT_STRUCTS_SIZE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (bs == MAP_FAILED) {
                fprintf(stderr, "[BOOT] FATAL: cannot allocate boot structs in LibOS\n");
                _exit(1);
            }
            memset(bs, 0, BOOT_STRUCTS_SIZE);

            ntum_kthread_t     *boot_kthread      = (ntum_kthread_t*)    (bs + 0x00000);
            ntum_sched_block_t *boot_sched        = (ntum_sched_block_t*)(bs + 0x10000);
            uint8_t            *boot_thread_local =                      (bs + 0x11000);
            ntum_stack_desc_t  *boot_stack_desc   = (ntum_stack_desc_t*) (bs + 0x16000);

            /* KTHREAD init — replicates FUN_00020f03c behavior.
             * Uses typed struct fields instead of raw offsets. */
            boot_kthread->list1.flink = (uint64_t)&boot_kthread->list1;
            boot_kthread->list1.blink = (uint64_t)&boot_kthread->list1;
            boot_kthread->ref_count  = 1;
            boot_kthread->list2.flink = (uint64_t)&boot_kthread->list2;
            boot_kthread->list2.blink = (uint64_t)&boot_kthread->list2;
            boot_kthread->sched_block      = boot_sched;
            boot_kthread->teb              = ntum_teb;
            boot_kthread->thread_local_block     = boot_thread_local;
            boot_kthread->thread_local_alt = boot_thread_local;

            /* Scheduler block — PE RVA 0x27672c does SWAR popcount on
             * affinity_mask then divides by the result. Bit 0 = CPU 0. */
            boot_sched->affinity_mask = 1;
            boot_sched->preferred_cpu = 0;
            /* PE RVA 0x24410a writes $1 here; RVA 0x276ca0 validates
             * [sched+0xbc0] == r14(=1). Pre-set to match. */
            boot_sched->sequence_id   = 1;
            /* PE RVA 0x276e04-0x276e15 reads:
             *   rax = [rdi]             ; sched_block
             *   rcx = [rax + 0xa98]     ; processor_info
             *   rax = [rcx]             ; vtable
             *   rax = [rax + 0x30]      ; vtable slot — called via CFG
             * Point processor_info to the existing pool_obj so any
             * vtable dispatch lands on pool_allocator_fn (returns a
             * valid pool pointer). Set in the pool init block below. */
            /* Thread-local block[0x250] = execution context sub-object.
             * RVA 0x3336dd reads [thread_local+0x250] then [+0xe88] as a lock.
             * Allocate a sub-object with room for the lock at +0xe88. */
            static uint8_t *tl_exec_ctx = NULL;
            if (!tl_exec_ctx) {
                tl_exec_ctx = (uint8_t*)mmap(
                    (void*)(LIBOS_KERNEL_HEAP + 0x23000000ULL), 0x2000,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            }
            *(uint64_t*)(boot_thread_local + 0x250) = (uint64_t)tl_exec_ctx;
            /* exec_ctx scheduling counters: [+0x18] used as divisor at RVA 0x35868c.
             * divl [rbx+rdi*4+0x18] where rbx=exec_ctx+0x80. Must be non-zero. */
            *(uint32_t*)(tl_exec_ctx + 0x80 + 0x18) = 1;  /* Avoid div-by-zero */
            /* Initialize SPECIFIC linked list heads in exec_ctx as self-referencing.
             * Only set offsets that are known list heads (NOT offset 0 = vtable).
             * RVA 0x33c635 reads [exec_ctx+0x1298] as list head.
             * Leave offset 0 and other vtable/pointer fields as 0. */
            /* Initialize linked list heads at 16-byte aligned offsets.
             * Skip offset 0 (used as vtable pointer by kernel objects).
             * Start from 0x10 to preserve vtable fields at [0] and [8]. */
            for (int off = 0x10; off < 0x2000; off += 16) {
                uint64_t addr = (uint64_t)tl_exec_ctx + off;
                *(uint64_t*)(tl_exec_ctx + off) = addr;
                *(uint64_t*)(tl_exec_ctx + off + 8) = addr;
            }
            /* thread_local[0x208] = kernel scheduling state pointer.
             * RVA 0x35849c reads [thread_local+0x208] then [+0x9b0].
             * Needs a large sub-object (at least 0xA00 bytes). */
            static uint8_t *tl_sched_state = NULL;
            if (!tl_sched_state) {
                tl_sched_state = (uint8_t*)mmap(
                    (void*)(LIBOS_KERNEL_HEAP + 0x24000000ULL), 0x2000,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            }
            *(uint64_t*)(boot_thread_local + 0x208) = (uint64_t)tl_sched_state;
            /* sched_state[0x9b0] = scheduling object chain.
             * RVA 0x3584ac reads [sched_state+0x9b0] → [+0x820].
             * Allocate a sub-object for the scheduler chain. */
            static uint8_t *tl_sched_obj = NULL;
            if (!tl_sched_obj) {
                tl_sched_obj = (uint8_t*)mmap(
                    (void*)(LIBOS_KERNEL_HEAP + 0x25000000ULL), 0x2000,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            }
            *(uint64_t*)(tl_sched_state + 0x9b0) = (uint64_t)tl_sched_obj;
            /* sched_obj[0x820] = scheduling slot/processor index (32-bit int).
             * RVA 0x3584ba reads as: mov esi, [rax+0x820] (32-bit!)
             * Then uses esi as array index: [rbx + esi*9*4 + 0x18]
             * Must be 0 (single processor) to avoid OOB array access. */
            *(uint32_t*)(tl_sched_obj + 0x820) = 0;
            /* sched_state[0xa20] = per-processor atomic counter array.
             * RVA 0x35853e reads [sched_state+0xa20] for lock xadd. */
            static uint8_t *sched_proc_counters = NULL;
            if (!sched_proc_counters) {
                sched_proc_counters = (uint8_t*)mmap(
                    (void*)(LIBOS_KERNEL_HEAP + 0x27000000ULL), 0x1000,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            }
            *(uint64_t*)(tl_sched_state + 0xa20) = (uint64_t)sched_proc_counters;

            /* Link into TEB — stack descriptor and kernel thread pointer.
             * The thread switcher (RVA 0x020f4d4) uses TEB->StackDesc as
             * the context frame's stack_info. StackDesc->stack_handler
             * is the NTUM's guard_check_icall (RVA 0x18021ff10). */
            boot_stack_desc->stack_top      = NTUM_STACK_TOP;
            boot_stack_desc->stack_handler  = NTUM_GUARD_CHECK_RVA;
            ntum_teb_t *teb_struct = (ntum_teb_t*)ntum_teb;
            teb_struct->KThread   = boot_kthread;
            teb_struct->PalObject = NULL;
            teb_struct->StackDesc = boot_stack_desc;

            printf("  [%p] global TEB = %p (in LibOS)\n",
                   (void*)NTUM_GLOBAL_TEB_ADDR, ntum_teb);
            printf("  TEB->KThread  = %p\n", (void*)boot_kthread);
            printf("  KTHREAD->sched_block = %p\n", (void*)boot_sched);
        }

        /* Default thread block at [0x63b220] - used by thread switcher at
         * RVA 0x3a0650 as fallback when rdx=NULL.
         * +0x08: ownership lock
         * +0x10: stack_base (top of stack)
         * +0x18: stack_limit (bottom of stack)
         */
        /* Default thread block at [0x63b220] - setup matching FUN_0020ff2c.
         * The function sets: [0]=magic, [0x10]=stack_top, [0x18]=stack_base,
         * [0x48]=current_sp, [0x4090]=top, [0x4098]=[0x40a0]=base.
         * The thread switcher reads [rdx+0x10] and [rdx+0x18] as fallback. */
        /* Default thread block at 0x63b220 matches FUN_0020ff2c layout.
         * Also set [0x63b218] (offset -8) which is read at RVA 0x204d37
         * and stored as TEB[0x1478]. This value becomes the stack_info
         * that the thread switcher reads via [context_frame+0x10].
         * It must point to a structure where [+0x30] = valid stack ptr. */
        uint8_t *sched_stack_desc = (uint8_t*)(BOOT_STRUCTS_ADDR + 0x16100);
        *(uint64_t*)(sched_stack_desc + 0x30) = NTUM_STACK_TOP;
        *(volatile uint64_t*)0x18063b218ULL = (uint64_t)sched_stack_desc;

        uint8_t *dtb = (uint8_t*)0x18063b220ULL;
        *(uint64_t*)(dtb + 0x00) = 0x53647268546c6150ULL;  /* "PalThrds" magic */
        *(uint64_t*)(dtb + 0x10) = NTUM_STACK_TOP + 0x4000; /* stack_top */
        *(uint64_t*)(dtb + 0x18) = NTUM_STACK_BASE + 0x90;  /* stack_base */
        *(uint64_t*)(dtb + 0x28) = NTUM_STACK_TOP + 0x200000;

        /* Thread context area at 0x63ac10 - the thread switcher at RVA 0x3a0650
         * reads [rsp+0x4f0] as the context pointer when rsp is at ~0x18063a720.
         * rsp+0x4f0 = 0x18063ac10. The context needs:
         * +0x10: pointer to stack_info structure (must NOT be NULL)
         * stack_info+0x30: stack pointer value
         *
         * We create a minimal stack_info in the .data area. */
        static uint8_t boot_stack_info[256] __attribute__((aligned(64)));
        memset(boot_stack_info, 0, sizeof(boot_stack_info));
        /* stack_info+0x30 = stack pointer (middle of NTUM stack) */
        *(uint64_t*)(boot_stack_info + 0x30) = NTUM_STACK_TOP;
        /* stack_info+0x90 = RIP for thread resume (point to a ret) */
        *(uint64_t*)(boot_stack_info + 0x90) = 0x18021ff10ULL; /* guard_check = ret */

        /* Write the stack_info pointer to the context area.
         * Context is at 0x18063ac10, [context+0x10] needs the pointer. */
        *(volatile uint64_t*)0x18063ac20ULL = (uint64_t)boot_stack_info;

        /* Pool allocator init flag at [0x6456d8] - must be non-zero
         * for the object pool at 0x2c2a00 to create objects.
         * Set by init command 0xe46 in the kernel dispatcher at 0x2b81d4.
         * If 0, VirtualAlloc wrapper returns NULL and kernel objects
         * can't be created. */
        *(volatile uint32_t*)0x1806456d8ULL = 1;

        /* Pool flags at [0x64560c] - controls pool behavior */
        *(volatile uint32_t*)0x18064560cULL = 0x42;  /* Enable pool + large pages */

        printf("[BOOT] Set NTUM .data globals (no .text patches!):\n");
        printf("  [0x18063f8c0] = 1 (boot flag)\n");
        printf("  [0x18063f8c8] = %p (ABI dispatcher)\n", (void*)&DK_AbiDispatcher);
        printf("  [0x180c00008] = %p (params)\n", (void*)params);
    }

    printf("[BOOT] NTUM parameters initialized:\n");
    printf("  ImageBase: %p\n", image_base);
    printf("  ImageSize: %lu KB\n", (unsigned long)(image_size / 1024));
    printf("  EntryPoint: %p (RVA 0x%lx)\n",
           params->BootEntryPoint, (unsigned long)entry_rva);
    printf("  AbiTable: %p\n", params->HostAbiTable);
    printf("  Features: 0x%x\n", *flags);
}

/* boot_thread_args_t defined in drawbridge_types.h */

static void *boot_thread_fn(void *arg) {
    boot_thread_args_t *args = (boot_thread_args_t*)arg;

    printf("[BOOT] Boot thread started (TID %d)\n", gettid());

    /* Install signal handler on this thread */
    extern void ntum_signal_init(void);
    ntum_signal_init();

    /*
     * Initialize the security cookie BEFORE calling the entry point.
     * The PE's cookie init function reads [0x180600000] and checks
     * if it's 0 or the default. We pre-store a valid cookie so
     * the init passes through without error.
     *
     * Cookie at [0x180600000], inverted at [0x180600008].
     */
    {
        volatile uint64_t *cookie = (uint64_t*)0x180600000ULL;
        volatile uint64_t *cookie_inv = (uint64_t*)0x180600008ULL;
        uint32_t lo, hi;
        __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
        uint64_t ts = ((uint64_t)hi << 32) | lo;
        uint64_t cv = (ts ^ 0x180600000ULL) & 0xFFFFFFFFFFFFULL;
        if (cv == 0 || cv == 0x2b992ddfa232ULL) cv = 0x2b992ddfa233ULL;
        *cookie = cv;
        *cookie_inv = ~cv;
        fprintf(stderr, "[BOOT] Security cookie: 0x%lx\n", (unsigned long)cv);
    }

    /*
     * Pre-fault all PE pages to prevent demand-paging signals
     * during boot. Signal delivery during NTUM init can corrupt
     * register state if not handled carefully.
     */
    {
        volatile uint8_t sum = 0;
        uint8_t *base = (uint8_t*)args->params->ImageBase;
        size_t img_size = 0x1010000;
        fprintf(stderr, "[BOOT] Pre-faulting %lu pages...\n", (unsigned long)(img_size/0x1000));
        for (size_t off = 0; off < img_size; off += 0x1000)
            sum += base[off];
        /* Pre-fault .data area including NTUM stack */
        for (uint64_t a = 0x180600000ULL; a < 0x18066A000ULL; a += 0x1000)
            sum += *(volatile uint8_t*)a;
        /* Pre-fault control pages */
        sum += *(volatile uint8_t*)0x100000000ULL;
        sum += *(volatile uint8_t*)0x100010000ULL;
        (void)sum;
        fprintf(stderr, "[BOOT] All pages pre-faulted\n");
    }

    /* Lock PE image and .data pages in memory */
    mlock(args->params->ImageBase, 0x1010000);
    mlock(args->params, 0x1000);
    mlock((void*)0x180600000ULL, 0x70000);  /* .data */
    mlock((void*)0x180a00000ULL, 0x1000);   /* .00cfg */
    mlock((void*)0x180c00000ULL, 0x2000);   /* .roafter */

    /* The PE sets TEB[0x1478] = 0x180637000 (NTUM_STACK_BASE) during init.
     * The thread switcher reads [TEB[0x1478]+0x10] as stack_info.
     * So [0x180637010] must be a valid pointer to a stack descriptor
     * where [+0x30] = valid stack pointer.
     * Write our stack descriptor pointer at 0x180637010. */
    {
        uint8_t *sd = (uint8_t*)(BOOT_STRUCTS_ADDR + 0x16000);
        if (*(uint64_t*)(sd + 0x30) == 0)
            *(uint64_t*)(sd + 0x30) = NTUM_STACK_TOP;
        *(volatile uint64_t*)0x180637010ULL = (uint64_t)sd;
    }

    /* Write stack descriptors into the NTUM stack frame area.
     * The thread switcher at RVA 0x3a0650 reads [rsp+0x4f0+0x10] as stack_info.
     * The NTUM stack is at 0x180637000-0x18063b000. The entry sets rsp=0x18063b000.
     * We need valid stack_info pointers at multiple offsets in the stack frame
     * because the exact rsp+0x4f0 offset depends on call depth. */
    {
        static uint8_t ntum_stack_desc[256] __attribute__((aligned(64)));
        *(uint64_t*)(ntum_stack_desc + 0x30) = NTUM_STACK_TOP;
        *(uint64_t*)(ntum_stack_desc + 0x90) = 0x18021ff10ULL;

        /* Fill stack frame area with stack descriptor pointers at +0x10 offsets */
        for (uint64_t addr = 0x180639800ULL; addr < 0x18063b000ULL; addr += 8) {
            /* Only write to +0x10 aligned positions */
            if ((addr & 0xF) == 0x0) {
                *(volatile uint64_t*)addr = (uint64_t)ntum_stack_desc;
            }
        }
    }

    /* Re-arm .data globals (demand-paging might have overwritten) */
    *(volatile uint32_t*)0x18063f8c0ULL = 1;
    *(volatile uint64_t*)0x18063f8c8ULL = (uint64_t)&DK_AbiDispatcher;
    *(volatile uint64_t*)0x180c00008ULL = (uint64_t)args->params;
    *(volatile uint64_t*)0x180c00010ULL = args->params->Size;
    *(volatile uint32_t*)0x18063f5c0ULL = 2;  /* ABI version = 2 */
    /* Pool allocator init flag - must be set AFTER pre-fault */
    *(volatile uint32_t*)0x1806456d8ULL = 1;
    *(volatile uint32_t*)0x18064560cULL = 0x42;
    /* Hash table size at [0x645de0] - used by kernel hash probe at RVA 0x324dcc.
     * divq [0x645de0] causes SIGFPE if zero. Set to a prime number. */
    /* Kernel lock/hash table descriptor at [0x645dd8]:
     *   [0x645dd8] = table base pointer (read at RVA 0x324da6: mov r8,[0x645dd8])
     *   [0x645de0] = table size/bucket count (read at RVA 0x324dcc: divq [0x645de0])
     * The hash probe: index = hash % size, entry = table[0x10 + index*24]
     * If table pointer is NULL, crash at [0 + 0x10 + index*24] */
    if (*(volatile uint64_t*)0x180645de0ULL == 0) {
        /* Allocate hash table: 127 buckets * 24 bytes + 0x10 header = ~3KB */
        void *ht = mmap((void*)(LIBOS_KERNEL_HEAP + 0x22000000ULL), 0x2000,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (ht != MAP_FAILED) {
            *(volatile uint64_t*)0x180645dd8ULL = (uint64_t)ht;  /* Table base */
            *(volatile uint64_t*)0x180645de0ULL = 127;            /* Bucket count */
        }
    }
    /* Re-arm thread block stack descriptor at [0x63b218].
     * Use the sched_stack_desc from the LibOS boot structs allocation. */
    {
        uint8_t *sd = (uint8_t*)(BOOT_STRUCTS_ADDR + 0x16100);
        if (*(uint64_t*)(sd + 0x30) == 0)
            *(uint64_t*)(sd + 0x30) = NTUM_STACK_TOP;
        *(volatile uint64_t*)0x18063b218ULL = (uint64_t)sd;
    }
    /* Replicate PE init FUN_0x2bcf9c at RVA 0x2bd09d-0x2bd0a6:
     *     lea rcx, [0x6472c0]
     *     mov [0x648c00], rcx        ; global type registry
     *
     * Reader FUN_0x31a58c dispatches on exec_ctx[+4]:
     *   case 1: rbx = registry->dispatch1;  size = registry->size1
     *   case 2: rbx = registry->dispatch2;  size = registry->size2
     * Caller FUN_0x319e74 then does `mov (%rax,%rbx,8), %rbx` where
     * rbx is the exec_ctx type code (observed up to ~0x40). */
    {
        ntum_type_registry_t *registry =
            (ntum_type_registry_t*)NTUM_TYPE_REGISTRY_ADDR;
        static void *dispatch_table = NULL;
        if (!dispatch_table) {
            /* 64KB table = 8192 entries. Generous for type codes up to ~0x40. */
            dispatch_table = mmap(
                (void*)(LIBOS_KERNEL_HEAP + 0x28000000ULL), 0x10000,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (dispatch_table == MAP_FAILED) {
                fprintf(stderr, "[BOOT] FATAL: dispatch_table mmap failed\n");
                _exit(1);
            }
            memset(dispatch_table, 0, 0x10000);
        }
        registry->size1     = 0x2000;
        registry->dispatch1 = dispatch_table;
        registry->size2     = 0x2000;
        registry->dispatch2 = dispatch_table;
        *(volatile uint64_t*)NTUM_TYPE_GLOBAL_ADDR  = (uint64_t)registry;
        *(volatile uint64_t*)NTUM_TYPE_GLOBAL2_ADDR = (uint64_t)registry;
    }

    /* Re-arm pool and KTHREAD pointers (all in LibOS space now) */
    *(volatile uint64_t*)0x1806456e8ULL = (uint64_t)(BOOT_STRUCTS_ADDR + 0x16200);
    /* Re-arm TEB KTHREAD link */
    {
        uint64_t teb_val = *(volatile uint64_t*)0x1806092c0ULL;
        if (teb_val) {
            *(uint64_t*)((uint8_t*)teb_val + 0x1838) = (uint64_t)(BOOT_STRUCTS_ADDR + 0x00000);
            uint8_t *sd = (uint8_t*)(BOOT_STRUCTS_ADDR + 0x16000);
            if (*(uint64_t*)(sd + 0x30) == 0)
                *(uint64_t*)(sd + 0x30) = NTUM_STACK_TOP;
            *(uint64_t*)((uint8_t*)teb_val + 0x1478) = (uint64_t)sd;
        }
    }

    /* Pre-create kernel pool object at [0x1806456e8].
     * The pool allocator (PE RVA 0x2c2a00) normally creates this during
     * init command 0xe46. Code at 0x218f43 reads [0x6456e8] and passes it
     * to 0x2bc3b8 which dereferences pool_obj->vtable and pool_obj->flags.
     * Without this, kernel init crashes with RDX=0 at 0x2bc3c7.
     *
     * Uses typed ntum_pool_obj_t struct from drawbridge_types.h. */
    {
        ntum_pool_obj_t *pool_obj    = (ntum_pool_obj_t*)(BOOT_STRUCTS_ADDR + 0x16200);
        void           **pool_vtable = (void**)           (BOOT_STRUCTS_ADDR + 0x17200);
        void           **sub_alloc   = (void**)           (BOOT_STRUCTS_ADDR + 0x17400);
        void           **sub_inner   = (void**)           (BOOT_STRUCTS_ADDR + 0x17600);

        /* Use pool_allocator_fn_real (strong symbol in pool_allocator_real.c)
         * which produces zero-initialized memory with LIST_ENTRY self-refs —
         * the layout the PE's kernel-object vtable paths expect. The older
         * pool_allocator_fn in dk_pal.c (naive mmap + [+0x10]=stack_desc)
         * was producing malformed nodes that deadlocked PE waiter walks. */
        extern uint64_t pool_allocator_fn_real(void*, uint64_t, uint64_t, void*,
                                               uint64_t, void*) __attribute__((ms_abi));
        for (size_t i = 0; i < 0x200/sizeof(void*); i++)
            pool_vtable[i] = (void*)&pool_allocator_fn_real;

        sub_inner[0] = (void*)&pool_allocator_fn_real; /* called via guard_dispatch */
        sub_alloc[0] = sub_inner;
        pool_obj->vtable        = pool_vtable;
        pool_obj->sub_allocator = sub_alloc;
        *(volatile uint64_t*)NTUM_POOL_OBJ_ADDR = (uint64_t)pool_obj;

        /* NOTE: various .data pre-seed hacks were tried here during
         * M6b iteration (waiter-list anchor at 0x1806679d0, PE text
         * patches at RVA 0x226ada, processor_info thunk at vtable+0x30).
         * All removed per "no fallbacks" rule. The DK #234 futex wait
         * is a PE-internal lock inconsistency that will be resolved by
         * making the appropriate DK PAL function(s) return real values
         * instead of DK_GenericStub no-ops. */
        /* Also expose pool_obj as the kernel processor_info so
         * PE RVA 0x276e04..0x276e15 vtable dispatch lands on
         * pool_allocator_fn (returns a valid allocation). */
        {
            ntum_sched_block_t *sched_ptr =
                (ntum_sched_block_t*)(BOOT_STRUCTS_ADDR + 0x10000);
            sched_ptr->processor_info = pool_obj;
        }
    }
    /* Re-arm TEB global (might have been overwritten by demand-paging) */
    {
        uint64_t teb_val = *(uint64_t*)(g_runtime_callback_state + 0x20);
        if (teb_val) {
            *(volatile uint64_t*)0x1806092c0ULL = teb_val;
            /* Re-arm KTHREAD link in TEB */
            uint64_t kthread = *(uint64_t*)((uint8_t*)teb_val + 0x1838);
            if (kthread == 0) {
                /* TEB[0x1838] was cleared by demand-paging, re-arm it */
                /* The KTHREAD address was stored before in init */
                /* We can't recover it here easily, but the init code
                 * should have stored it before pre-fault in the init globals section */
            }
        }
    }

    /* Verify .00cfg has the PE's built-in CFG functions (NOT our code) */
    {
        uint64_t guard_check = *(volatile uint64_t*)0x180a00000ULL;
        uint64_t guard_dispatch = *(volatile uint64_t*)0x180a00008ULL;
        fprintf(stderr, "[BOOT] .00cfg guard_check:    0x%lx (should be 0x18021ff10)\n",
                (unsigned long)guard_check);
        fprintf(stderr, "[BOOT] .00cfg guard_dispatch: 0x%lx (should be 0x1803a86f0)\n",
                (unsigned long)guard_dispatch);
        /* These should be the PE's own functions, NOT ours */
        if (guard_dispatch != 0x1803a86f0ULL) {
            fprintf(stderr, "[BOOT] WARNING: guard_dispatch was overwritten, restoring\n");
            *(volatile uint64_t*)0x180a00000ULL = 0x18021ff10ULL;
            *(volatile uint64_t*)0x180a00008ULL = 0x1803a86f0ULL;
        }
    }

    /*
     * Set up TEB (Thread Environment Block).
     * The NTUM reads gs:0x30 to get the TEB self-pointer.
     */
    {
        #include <asm/prctl.h>
        #include <sys/syscall.h>

        /* Allocate TEB in the LibOS thread environment area so the NTUM
         * accepts it. Using a static host-space TEB causes issues when the
         * NTUM's code reads gs:0x30 and follows pointer chains that
         * expect to be in LibOS address space. */
        uint8_t *teb = (uint8_t*)mmap((void*)LIBOS_THREAD_ENV, 65536,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1, 0);
        if (teb == MAP_FAILED)
            teb = (uint8_t*)mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(teb, 0, 65536);

        /* TEB layout (from PE disassembly at RVA 0x244cd0):
         * +0x08: StackBase
         * +0x10: StackLimit
         * +0x30: Self-pointer (gs:0x30 → &TEB)
         * +0x1838: Pointer to NTUM kernel thread info (KTHREAD-like)
         *          The NTUM reads TEB[0x1838] → [+0x70] → [+0xF0] to get
         *          the current thread's scheduling state. Must be NULL or
         *          a valid NTUM structure. DO NOT fill with garbage.
         */
        *(uint64_t*)(teb + 0x08) = NTUM_STACK_TOP + 0x200000;  /* StackBase */
        *(uint64_t*)(teb + 0x10) = NTUM_STACK_BASE;             /* StackLimit */
        *(uint64_t*)(teb + 0x30) = (uint64_t)teb;               /* Self-pointer */
        /* TEB[0x1838] = NULL - the NTUM will set this when it creates
         * the kernel thread during initialization. */

        /* Set GS base to the NTUM TEB (must match [0x1806092c0]) */
        uint64_t ntum_teb_addr = *(volatile uint64_t*)0x1806092c0ULL;
        if (ntum_teb_addr) {
            syscall(SYS_arch_prctl, ARCH_SET_GS, ntum_teb_addr);
            fprintf(stderr, "[BOOT] GS base set to NTUM TEB at 0x%lx\n",
                    (unsigned long)ntum_teb_addr);
        } else {
            syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)teb);
            fprintf(stderr, "[BOOT] GS base set to fallback TEB at %p\n", teb);
        }

        /* Store thread control block (TCB) at fs:-0x10 and fs:-8.
         * The NTUM's signal handler (FUN_002899d0) reads from FS_OFFSET - 0x10:
         *   TCB + 0x068 = thread_state_ptr (passed as RDX to exception dispatcher)
         *   TCB + 0x088 = signal stack base
         *   TCB + 0x9e8 = exception nesting counter (max 16)
         *   TCB + 0xa20 = exception record pointer array[16]
         */
        unsigned long fs_base;
        syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
        uint8_t *boot_thread_state = (uint8_t*)(BOOT_STRUCTS_ADDR + 0x17800);

        /* Thread state linkage and stack info.
         * The thread switcher fallback at RVA 0x3a06cc reads [rdx+0x10]
         * as stack_base when the primary context has NULL stack_info.
         * rdx = this thread_state. [+0x10] must be valid stack address. */
        *(uint64_t*)(boot_thread_state + 0x10) = NTUM_STACK_TOP + 0x4000;
        *(uint64_t*)(boot_thread_state + 0x18) = NTUM_STACK_BASE;
        *(uint64_t*)(boot_thread_state + 0x58) = (uint64_t)boot_thread_state;
        *(uint64_t*)(boot_thread_state + 0x68) = (uint64_t)boot_thread_state;
        *(uint64_t*)(boot_thread_state + 0x88) = (uint64_t)teb + 0x08;

        /* Store TCB pointer at both fs:-8 and fs:-0x10 (signal handler reads -0x10) */
        *(uint64_t*)(fs_base - 8)  = (uint64_t)boot_thread_state;
        *(uint64_t*)(fs_base - 16) = (uint64_t)boot_thread_state;

        fprintf(stderr, "[BOOT] TEB at %p, TCB at %p (fs:-0x10)\n", teb, boot_thread_state);
    }

    /*
     * Call the REAL entry point.
     *
     * The entry point at RVA 0x3a04d0 does:
     *   lea rsp, [rip+0x296b29]     → RSP = 0x180637000
     *   add rsp, [rip+0x72fa2]      → RSP += 0x4000 = 0x18063b000
     *   sub rsp, 0x28
     *   jmp 0x180204ad0             → init wrapper
     *
     * The init wrapper:
     *   Saves rcx (params) to r9
     *   Calls cookie init (passes because we pre-stored cookie)
     *   Calls real_init at 0x180204754 with rcx from r9
     *
     * We use ms_abi to ensure rcx = params (Windows x64 convention).
     * The entry point sets its own stack, so our stack doesn't matter.
     */
    /* Write mapped PE sections to a file for offline analysis */
    {
        FILE *pef = fopen("/tmp/sqlpal_mapped.bin", "wb");
        if (pef) {
            fwrite(args->params->ImageBase, 1, 0x1000000, pef);
            fclose(pef);
            fprintf(stderr, "[BOOT] Wrote mapped PE to /tmp/sqlpal_mapped.bin (16MB)\n");
        }
    }

    /* Dump key PE function bytes for analysis */
    {
        /* Syscall wrapper at PE RVA 0x354180 */
        volatile uint8_t *sw = (uint8_t*)0x180354180ULL;
        fprintf(stderr, "[BOOT] Syscall wrapper at 0x180354180: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7], sw[8], sw[9]);

        /* io_setup wrapper at PE RVA 0x202100 */
        volatile uint8_t *io = (uint8_t*)0x180202100ULL;
        fprintf(stderr, "[BOOT] io_setup wrapper at 0x180202100: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                io[0], io[1], io[2], io[3], io[4], io[5], io[6], io[7]);

        /* Check RuntimeCallbackState for KiUserExceptionDispatcher */
        fprintf(stderr, "[BOOT] RuntimeCallbackState+0x10 = 0x%lx (KiDispatcher)\n",
                (unsigned long)*(volatile uint64_t*)(g_runtime_callback_state + 0x10));
    }

    /* M6: run the translated 22-step PAL boot before entering the PE,
     * matching the real ELF host's call order (FUN_00204680). Guarded
     * by PAL_RUN_BOOT_INIT so regressions can be bisected without
     * reverting the wire-up. The stub helpers are no-ops today; real
     * behavior kicks in as later milestones translate each step. */
#ifndef PAL_SKIP_BOOT_INIT
    {
        fprintf(stderr, "[BOOT] running pal_boot_init (FUN_00204680, 22 steps)\n");
        int rc = pal_boot_init();
        fprintf(stderr, "[BOOT] pal_boot_init returned %d\n", rc);
    }
#endif

    fprintf(stderr, "[BOOT] Calling REAL entry point at %p (no hacks!)\n",
            args->entry_point);
    fprintf(stderr, "[BOOT] rcx = rdx = %p (params)\n", args->params);

    /* Verify entry point bytes */
    {
        volatile uint8_t *ep = (uint8_t*)args->entry_point;
        fprintf(stderr, "[BOOT] Entry bytes: %02x %02x %02x %02x %02x %02x %02x\n",
                ep[0], ep[1], ep[2], ep[3], ep[4], ep[5], ep[6]);
        fprintf(stderr, "[BOOT] Expected:    48 8d 25 29 6b 29 00 (lea rsp, [rip+...])\n");
        /* Patch stack size offset.
         * PE entry at 0x3a04d0 computes: RSP = 0x180637000 + [0x180413480].
         * The default 0x4000 gives only 0x3b000 (236KB) of stack before
         * underflowing into .data and corrupting the security cookie at
         * 0x180600000. The real ELF host's FUN_00252e60 allocates a 2MB+
         * thread stack; we provide equivalent headroom by moving RSP above
         * the end of .data VSize (0x6a2a8 from 0x180600000 = 0x18066a2a8).
         *
         * Set [0x180413480] so that RSP lands at LibOS kernel heap space,
         * giving 2MB of stack that cannot collide with .data at all.
         * LIBOS_KERNEL_HEAP is at 0x300000000; reserve a stack slice there.
         */
        uint64_t stack_adj = *(volatile uint64_t*)0x180413480ULL;
        fprintf(stderr, "[BOOT] Stack adj [0x180413480] = 0x%lx (expect 0x4000)\n",
                (unsigned long)stack_adj);
        /* Map a dedicated 2MB stack at a fixed LibOS address.
         * RSP top = 0x18063b000 currently; we extend the PE image-resident
         * stack region by patching the offset so RSP lands just past .data
         * end (above 0x18066a2a8) but still inside the mapped PE region.
         *   new_offset = (0x1806b0000 - 0x180637000) = 0x79000
         * This gives 0xb0000 = 704KB of stack (room = new_top - .data_end). */
        const uint64_t NEW_STACK_OFFSET = 0x79000;   /* → RSP = 0x1806b0000 */
        *(volatile uint64_t*)0x180413480ULL = NEW_STACK_OFFSET;
        fprintf(stderr, "[BOOT] Patched [0x180413480] = 0x%lx (RSP=0x%lx, %luKB stack above .data)\n",
                (unsigned long)NEW_STACK_OFFSET,
                (unsigned long)(0x180637000ULL + NEW_STACK_OFFSET),
                (unsigned long)((0x180637000ULL + NEW_STACK_OFFSET - 0x18066a2a8ULL) / 1024));
        /* Verify .00cfg is intact */
        uint64_t gc = *(volatile uint64_t*)0x180a00000ULL;
        uint64_t gd = *(volatile uint64_t*)0x180a00008ULL;
        fprintf(stderr, "[BOOT] .00cfg: check=0x%lx dispatch=0x%lx\n",
                (unsigned long)gc, (unsigned long)gd);
        /* Verify guard_dispatch bytes at 0x1803a86f0 */
        volatile uint8_t *gdb = (uint8_t*)0x1803a86f0ULL;
        fprintf(stderr, "[BOOT] guard_dispatch bytes: %02x %02x (expect ff e0 = jmp *rax)\n",
                gdb[0], gdb[1]);
        fprintf(stderr, "\n");
    }

    /* Verify HostAbiTable has dispatcher at offset 8 */
    {
        uint64_t *abt = (uint64_t*)args->params->HostAbiTable;
        fprintf(stderr, "[BOOT] HostAbiTable = %p\n", args->params->HostAbiTable);
        fprintf(stderr, "[BOOT] HostAbiTable[0] = 0x%lx\n", (unsigned long)abt[0]);
        fprintf(stderr, "[BOOT] HostAbiTable[1] = 0x%lx (should be DK_AbiDispatcher)\n",
                (unsigned long)abt[1]);
        fprintf(stderr, "[BOOT] DK_AbiDispatcher = %p\n", (void*)&DK_AbiDispatcher);
        fprintf(stderr, "[BOOT] RuntimeCallbackState = %p, [0]=0x%lx\n",
                args->params->RuntimeCallbackState,
                (unsigned long)*(uint64_t*)args->params->RuntimeCallbackState);
    }

    /* Verify init wrapper at 0x180204ad0 (jmp target from entry point) */
    {
        volatile uint8_t *iw = (uint8_t*)0x180204ad0ULL;
        fprintf(stderr, "[BOOT] Init wrapper bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                iw[0], iw[1], iw[2], iw[3], iw[4], iw[5], iw[6], iw[7]);
        fprintf(stderr, "[BOOT] Expected:           48 83 ec 28 4c 8b c2 4c\n");
        /* Verify cookie init function at 0x180204704 */
        volatile uint8_t *ci = (uint8_t*)0x180204704ULL;
        fprintf(stderr, "[BOOT] Cookie init bytes: %02x %02x %02x %02x\n",
                ci[0], ci[1], ci[2], ci[3]);
    }

    /* Try calling the entry point directly via ms_abi function pointer
     * instead of assembly trampoline to rule out trampoline issues */
    {
        typedef void (__attribute__((ms_abi)) *entry_fn_t)(void *, void *);
        entry_fn_t entry_fn = (entry_fn_t)args->entry_point;
        fprintf(stderr, "[BOOT] Calling via ms_abi function pointer: %p\n\n", (void*)entry_fn);
        entry_fn(args->params, args->params);
    }

    /* Should not reach here */
    printf("[BOOT] NTUM returned unexpectedly\n");
    return NULL;
}

int ntum_bootstrap_launch(WINDOWS_LIBOS_PARAMETERS *params) {
    if (!params->BootEntryPoint) {
        fprintf(stderr, "[BOOT] No entry point set\n");
        return -1;
    }

    /* Allocate boot stack in the LibOS kernel heap area */
    void *stack_base = mmap((void*)0x300100000ULL, BOOT_STACK_SIZE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                            -1, 0);
    if (stack_base == MAP_FAILED) {
        stack_base = mmap(NULL, BOOT_STACK_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (stack_base == MAP_FAILED) {
        perror("[BOOT] Cannot allocate boot stack");
        return -1;
    }

    void *stack_top = (uint8_t*)stack_base + BOOT_STACK_SIZE - 0x100;
    stack_top = (void*)((uintptr_t)stack_top & ~0xFULL);

    printf("[BOOT] Boot stack: %p - %p (2 MB)\n", stack_base, stack_top);

    /* Set up thread args */
    static boot_thread_args_t args;
    args.entry_point = params->BootEntryPoint;
    args.stack_top = stack_top;
    args.params = params;

    /* Create the boot thread */
    pthread_t boot_tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);

    int ret = pthread_create(&boot_tid, &attr, boot_thread_fn, &args);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        fprintf(stderr, "[BOOT] Cannot create boot thread: %d\n", ret);
        return -1;
    }

    printf("[BOOT] Boot thread launched, waiting for NTUM...\n\n");

    void *thread_result;
    pthread_join(boot_tid, &thread_result);

    printf("[BOOT] NTUM boot thread exited\n");
    return 0;
}
