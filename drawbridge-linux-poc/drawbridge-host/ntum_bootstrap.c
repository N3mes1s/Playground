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

    /* ParameterBuffer: the NTUM reads [ParameterBuffer] and expects first dword = 0x190 */
    static uint8_t param_buffer[0x200] __attribute__((aligned(16)));
    *(uint32_t*)param_buffer = 0x190;
    params->ParameterBuffer = param_buffer;
    params->ParameterBufferSize = sizeof(param_buffer);

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

        /* Pre-store ParameterBuffer pointer */
        *(volatile uint64_t*)0x180c00820ULL = (uint64_t)params->ParameterBuffer;

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

    /* Re-arm .data globals (demand-paging might have overwritten) */
    *(volatile uint32_t*)0x18063f8c0ULL = 1;
    *(volatile uint64_t*)0x18063f8c8ULL = (uint64_t)&DK_AbiDispatcher;
    *(volatile uint64_t*)0x180c00008ULL = (uint64_t)args->params;
    *(volatile uint64_t*)0x180c00010ULL = args->params->Size;

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

        static uint8_t teb[65536] __attribute__((aligned(4096)));
        memset(teb, 0, sizeof(teb));

        /* TEB self-pointer at offset 0x30 */
        *(uint64_t*)(teb + 0x30) = (uint64_t)teb;
        /* TEB.StackBase at offset 0x08 */
        *(uint64_t*)(teb + 0x08) = 0x18063b000ULL + 0x200000;
        /* TEB.StackLimit at offset 0x10 */
        *(uint64_t*)(teb + 0x10) = 0x180637000ULL;

        /* Fill other TEB slots with valid thread_state pointer */
        static uint8_t thread_state[0x1000] __attribute__((aligned(4096)));
        memset(thread_state, 0, sizeof(thread_state));
        for (int off = 0; off < 8192; off += 8)
            *(uint64_t*)(teb + off) = (uint64_t)thread_state;
        /* Re-set critical TEB fields after the fill */
        *(uint64_t*)(teb + 0x30) = (uint64_t)teb;
        *(uint64_t*)(teb + 0x08) = 0x18063b000ULL + 0x200000;
        *(uint64_t*)(teb + 0x10) = 0x180637000ULL;

        /* Set GS base to our TEB */
        syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)teb);

        /* Store thread control block (TCB) at fs:-0x10 and fs:-8.
         * The NTUM's signal handler (FUN_002899d0) reads from FS_OFFSET - 0x10:
         *   TCB + 0x068 = thread_state_ptr (passed as RDX to exception dispatcher)
         *   TCB + 0x088 = signal stack base
         *   TCB + 0x9e8 = exception nesting counter (max 16)
         *   TCB + 0xa20 = exception record pointer array[16]
         */
        unsigned long fs_base;
        syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
        static uint8_t boot_thread_state[0x2000] __attribute__((aligned(4096)));
        memset(boot_thread_state, 0, sizeof(boot_thread_state));

        /* Self-references and thread state linkage */
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
    fprintf(stderr, "[BOOT] Calling REAL entry point at %p (no hacks!)\n",
            args->entry_point);
    fprintf(stderr, "[BOOT] rcx = rdx = %p (params)\n", args->params);

    /* Verify entry point bytes */
    {
        volatile uint8_t *ep = (uint8_t*)args->entry_point;
        fprintf(stderr, "[BOOT] Entry bytes: %02x %02x %02x %02x %02x %02x %02x\n",
                ep[0], ep[1], ep[2], ep[3], ep[4], ep[5], ep[6]);
        fprintf(stderr, "[BOOT] Expected:    48 8d 25 29 6b 29 00 (lea rsp, [rip+...])\n");
        /* Verify .rdata stack adj is accessible */
        uint64_t stack_adj = *(volatile uint64_t*)0x180413480ULL;
        fprintf(stderr, "[BOOT] Stack adj [0x180413480] = 0x%lx (expect 0x4000)\n",
                (unsigned long)stack_adj);
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
