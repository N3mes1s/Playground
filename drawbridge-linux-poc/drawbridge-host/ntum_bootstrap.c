/*
 * NTUM Bootstrap Implementation
 *
 * Sets up WINDOWS_LIBOS_PARAMETERS and launches the NTUM boot thread
 * using the trampoline that switches from SysV to Windows x64 ABI.
 *
 * Reverse-engineered from sqlservr functions:
 *   0x10ba60 - GuestOS initialization
 *   0x105430 - OS boot thread launch
 *   0x15a520 - ABI trampoline
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

#include "ntum_bootstrap.h"
#include "dk_pal.h"

/* PAL callback state (lives in BSS like sqlservr's 0x2b2138) */
static uint8_t g_runtime_callback_state[256] __attribute__((aligned(64)));

/* ABI function table template (like sqlservr's 0x269ec8) */
static uint8_t g_abi_table[256] __attribute__((aligned(64)));

/* Stack for the NTUM boot thread (2MB in LibOS address space) */
#define BOOT_STACK_SIZE (2 * 1024 * 1024)

void ntum_bootstrap_init(WINDOWS_LIBOS_PARAMETERS *params,
                          void *image_base, uint64_t image_size,
                          uint64_t entry_rva, void *pal_table) {
    memset(params, 0, sizeof(WINDOWS_LIBOS_PARAMETERS));

    /* Header */
    params->Size = 0x90;
    params->SubHeaderSize = 0x38;

    /* PAL interface pointers */
    params->HostAbiTable = pal_table ? pal_table : g_abi_table;
    params->RuntimeCallbackState = g_runtime_callback_state;
    params->StackReservation = (void*)0x18;

    /* OS version (Windows 6.2 = Windows 8, same as SQLPAL reports) */
    params->MajorVersion = 6;
    params->MinorVersion = 2;

    /* Image info */
    params->ImageBase = image_base;
    params->ImageLength = image_size;

    /* Entry point */
    params->BootEntryPoint = (void*)((uint8_t*)image_base + entry_rva);

    /* Feature flags - base PAL features */
    uint32_t *flags = (uint32_t*)&params->FeatureFlags[0];
    *flags = FEATURE_BASE_PAL | FEATURE_TLS;

    /* Processor info */
    params->NumaNodeCount = 1;

    /* Initialize the ABI table template */
    memset(g_abi_table, 0, sizeof(g_abi_table));
    /* Size=0x10, SubSize=0x38 (matching sqlservr's 0x269ec8) */
    uint32_t *abi_header = (uint32_t*)g_abi_table;
    abi_header[0] = 0x10;   /* Size */
    abi_header[1] = 0x38;   /* SubSize */
    /* Sentinel at offset 0x30 */
    uint64_t *sentinel = (uint64_t*)(g_abi_table + 0x30);
    *sentinel = 0xFFFFFFFFFFFFFFFFULL;

    /*
     * Patch critical locations in sqlpal.dll's .data section.
     * These are hardcoded addresses discovered by disassembly:
     *
     * [0x18063f8c0] = boot ready flag (must be 1)
     * [0x18063f8c8] = PAL dispatch function pointer
     * [0x180c00010] = PAL table/params pointer (Size field from params)
     * [0x180a00008] = ABI call handler function pointer
     */
    if ((uintptr_t)image_base == 0x180000000ULL) {
        volatile uint32_t *boot_flag = (uint32_t*)0x18063f8c0ULL;
        volatile uint64_t *dispatch_fn = (uint64_t*)0x18063f8c8ULL;
        volatile uint64_t *pal_params = (uint64_t*)0x180c00010ULL;
        volatile uint64_t *abi_call = (uint64_t*)0x180a00008ULL;

        *boot_flag = 1;
        *dispatch_fn = (uint64_t)&DK_AbiDispatcher;
        *pal_params = (uint64_t)params;  /* Full params pointer as context */
        *abi_call = (uint64_t)&DK_AbiDispatcher;

        /* Patch ALL int3 assertions in the boot path.
         * The NTUM has multiple debug traps that fire during init. */

        /* 0x1802046e5: PAL call thunk boot flag check */
        volatile uint8_t *p1 = (uint8_t*)0x1802046e5ULL;
        p1[0] = 0x90; p1[1] = 0x90; p1[2] = 0x90;

        /* 0x180204ac9: post-init error handler */
        volatile uint8_t *p2 = (uint8_t*)0x180204ac9ULL;
        p2[0] = 0x90; p2[1] = 0x90; p2[2] = 0x90;

        /* 0x180204aba: init call chain error */
        volatile uint8_t *p3 = (uint8_t*)0x180204abaULL;
        p3[0] = 0x90;

        /* 0x180204aea: after second init function */
        volatile uint8_t *p4 = (uint8_t*)0x180204aeaULL;
        p4[0] = 0x90;

        /* Patch SPECIFIC int3 locations (discovered by tracing).
         * Only patch int3 bytes that are standalone debug traps,
         * NOT bytes that are part of multi-byte instructions. */
        int patched = 4;  /* The 4 specific patches above */

        /* Patch ALL standalone int3 bytes in .text that follow ret/nop/int3.
         * These are debug padding between functions.
         * DO NOT patch 0xCC that follows non-terminating instructions. */
        volatile uint8_t *code = (uint8_t*)0x180200000ULL;
        size_t text_size = 0x1AA000;  /* .text section size */
        for (size_t i = 1; i < text_size; i++) {
            if (code[i] == 0xCC) {
                uint8_t prev = code[i-1];
                /* Safe to patch if previous byte is ret, nop, or another int3 */
                if (prev == 0xC3 || prev == 0x90 || prev == 0xCC) {
                    code[i] = 0x90;
                    patched++;
                }
            }
        }

        printf("[BOOT] Patched %d int3+jmp traps in .text\n", patched);
        printf("[BOOT] Patched NTUM data section:\n");
        printf("  [0x18063f8c0] = 1 (boot ready flag)\n");
        printf("  [0x18063f8c8] = %p (PAL dispatch)\n", (void*)(uintptr_t)*dispatch_fn);
        printf("  [0x180a00008] = %p (ABI dispatcher)\n", (void*)(uintptr_t)*abi_call);
    }

    printf("[BOOT] NTUM parameters initialized:\n");
    printf("  ImageBase: %p\n", image_base);
    printf("  ImageSize: %lu KB\n", (unsigned long)(image_size / 1024));
    printf("  EntryPoint: %p (RVA 0x%lx)\n",
           params->BootEntryPoint, (unsigned long)entry_rva);
    printf("  AbiTable: %p\n", params->HostAbiTable);
    printf("  Features: 0x%x\n", *flags);
}

/*
 * Trampoline: switches from SysV ABI to Windows x64 and enters NTUM.
 *
 * Replicating sqlservr's trampoline at 0x15a520:
 *   push %rbp; mov %rsp,%rbp
 *   mov %rcx,%rax; mov %rdx,%rcx; mov %rax,%rdx
 *   mov $0,%rbp; mov %rsi,%rsp; jmp *%rdi
 *
 * In SysV ABI:
 *   rdi = entry_point (StartModule)
 *   rsi = new stack pointer (LibOS stack)
 *   rdx = WINDOWS_LIBOS_PARAMETERS* (becomes rcx in Win64)
 *   rcx = additional param (becomes rdx in Win64)
 */
__attribute__((naked))
void ntum_trampoline(void *entry_point, void *stack_ptr,
                     void *param1, void *param2) {
    __asm__ volatile (
        "push   %%rbp\n"
        "mov    %%rsp, %%rbp\n"
        /* Shuffle args: SysV -> Windows x64 */
        "mov    %%rcx, %%rax\n"     /* save rcx (param2) */
        "mov    %%rdx, %%rcx\n"     /* rdx (param1/LIBOS_PARAMS) -> rcx */
        "mov    %%rax, %%rdx\n"     /* saved rcx -> rdx */
        /* Set up clean frame */
        "xor    %%rbp, %%rbp\n"     /* zero frame pointer */
        "mov    %%rsi, %%rsp\n"     /* switch to LibOS stack */
        /* Jump to NTUM entry */
        "jmp    *%%rdi\n"           /* entry_point */
        ::: "memory"
    );
}

/* Thread function for the NTUM boot */
#include <signal.h>
#include <ucontext.h>

static void boot_sigtrap_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t*)ctx;
    fprintf(stderr, "\n[BOOT] Signal %d at %p\n", sig, info->si_addr);
    fprintf(stderr, "[BOOT] RIP=0x%016llx RSP=0x%016llx\n",
            (unsigned long long)uc->uc_mcontext.gregs[REG_RIP],
            (unsigned long long)uc->uc_mcontext.gregs[REG_RSP]);
    fprintf(stderr, "[BOOT] RCX=0x%016llx RDX=0x%016llx\n",
            (unsigned long long)uc->uc_mcontext.gregs[REG_RCX],
            (unsigned long long)uc->uc_mcontext.gregs[REG_RDX]);
    fprintf(stderr, "[BOOT] RAX=0x%016llx RBX=0x%016llx\n",
            (unsigned long long)uc->uc_mcontext.gregs[REG_RAX],
            (unsigned long long)uc->uc_mcontext.gregs[REG_RBX]);
    fprintf(stderr, "[BOOT] RSI=0x%016llx RDI=0x%016llx\n",
            (unsigned long long)uc->uc_mcontext.gregs[REG_RSI],
            (unsigned long long)uc->uc_mcontext.gregs[REG_RDI]);
    _exit(128 + sig);
}

typedef struct {
    void *entry_point;
    void *stack_top;
    WINDOWS_LIBOS_PARAMETERS *params;
} boot_thread_args_t;

static void *boot_thread_fn(void *arg) {
    boot_thread_args_t *args = (boot_thread_args_t*)arg;

    printf("[BOOT] Boot thread started (TID %d)\n", gettid());
    printf("[BOOT] Entering NTUM at %p with stack %p\n",
           args->entry_point, args->stack_top);
    printf("[BOOT] Switching to Windows x64 ABI...\n\n");

    /* Install SIGTRAP handler for debugging */
    struct sigaction sa = {0};
    sa.sa_sigaction = boot_sigtrap_handler;
    sa.sa_flags = SA_SIGINFO;
    extern void ntum_signal_init(void); ntum_signal_init(); /* Install on boot thread */

    /*
     * Initialize the security cookie ourselves (what 0x180204704 does),
     * then call the REAL init at 0x180204754 directly, skipping the
     * wrapper at 0x1803a04d0 that uses volatile r8/r9 for params.
     */

    /* Security cookie at [0x180600000] and inverted at [0x180600008] */
    volatile uint64_t *cookie = (uint64_t*)0x180600000ULL;
    volatile uint64_t *cookie_inv = (uint64_t*)0x180600008ULL;
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    uint64_t ts = ((uint64_t)hi << 32) | lo;
    uint64_t cv = (ts ^ 0x180600000ULL) & 0xFFFFFFFFFFFFULL;
    if (cv == 0 || cv == 0x2b992ddfa232ULL) cv = 0x2b992ddfa233ULL;
    *cookie = cv;
    *cookie_inv = ~cv;

    /* Set up the NTUM's internal stack at 0x180637000 (from .data).
     * The entry point normally does: lea rsp,[rip+offset] → 0x180637000
     * plus add rsp,[rip+offset] (stack adjustment from .rdata) */
    uint64_t ntum_stack_base = 0x180637000ULL;
    uint64_t *stack_adj_ptr = (uint64_t*)0x180413480ULL;  /* .rdata offset */
    uint64_t ntum_stack = ntum_stack_base + *stack_adj_ptr - 0x50;  /* Adjusted for skipping entry+wrapper */

    printf("[BOOT] Cookie: 0x%lx at 0x180600000\n", (unsigned long)cv);
    printf("[BOOT] NTUM stack: 0x%lx (base 0x%lx + adj 0x%lx)\n",
           (unsigned long)ntum_stack, (unsigned long)ntum_stack_base,
           (unsigned long)*stack_adj_ptr);

    /* Jump directly to 0x180204754 (the real init) using our trampoline.
     * rcx = LIBOS_PARAMS, rdx = LIBOS_PARAMS (config context) */
    void *real_init = (void*)((uint8_t*)args->params->ImageBase + 0x204754); /* REAL INIT DIRECT */
    /* Verify the bytes at the target haven't been patched incorrectly */
    volatile uint8_t *target = (uint8_t*)real_init;
    printf("[BOOT] Entering REAL init at %p bytes: %02x %02x %02x %02x %02x\n",
           real_init, target[0], target[1], target[2], target[3], target[4]);
    printf("[BOOT] Expected: 48 89 5c 24 18 (mov [rsp+0x18], rbx)\n");
    printf("[BOOT] Params ptr: %p\n\n", (void*)args->params);

    /*
     * PRE-FAULT all PE pages to prevent demand-paging signals during boot.
     * Signal delivery during NTUM init corrupts register state.
     */
    {
        volatile uint8_t sum = 0;
        uint8_t *base = (uint8_t*)args->params->ImageBase;
        size_t img_size = 0x1010000;
        fprintf(stderr, "[BOOT] Pre-faulting %lu pages...\n", (unsigned long)(img_size/0x1000));
        for (size_t off = 0; off < img_size; off += 0x1000)
            sum += base[off];
        /* Pre-fault NTUM stack and .data area */
        for (uint64_t a = 0x180600000ULL; a < 0x18066A000ULL; a += 0x1000)
            sum += *(volatile uint8_t*)a;
        /* Pre-fault control pages */
        sum += *(volatile uint8_t*)0x100000000ULL;
        sum += *(volatile uint8_t*)0x100010000ULL;
        (void)sum;
        fprintf(stderr, "[BOOT] All pages pre-faulted\n");
    }

    /* mlock the PE image */
    mlock(args->params->ImageBase, 0x1010000);

    /* DON'T block signals - we need the crash handler to work */

    /*
     * Pre-store params at the NTUM's known global addresses.
     * The real_init function at 0x180204784 stores rdx at [0x180c00008].
     * At 0x18020479c it reads [rcx] = params->Size.
     * If rcx is corrupted, the NTUM crashes. But if we pre-populate
     * [0x180c00008] and [0x180c00010], the NTUM's later code can use them.
     *
     * ALSO: patch the entry to skip the cookie function entirely.
     * Replace the wrapper at 0x180204ad0 to directly call real_init.
     */
    {
        /* Pre-store params pointers at NTUM globals */
        volatile uint64_t *g_config = (uint64_t*)0x180c00008ULL;
        volatile uint64_t *g_size   = (uint64_t*)0x180c00010ULL;
        *g_config = (uint64_t)args->params;  /* config/params pointer */
        *g_size = args->params->Size;         /* params->Size = 0x90 */

        /* Pre-store HostAbiTable + ParameterBuffer pointers */
        volatile uint64_t *g_param_buf = (uint64_t*)0x180c00820ULL;
        *g_param_buf = (uint64_t)args->params->ParameterBuffer;

        fprintf(stderr, "[BOOT] Pre-stored params at NTUM globals\n");

        /* PATCH: Replace wrapper to skip cookie and jump directly to real_init.
         * Original at 0x180204ad0:
         *   sub rsp, 0x28; mov r8,rdx; mov r9,rcx; call cookie; restore; call init
         * New: just pass through to real_init
         *   48 83 ec 28           sub rsp, 0x28
         *   e8 7b fc ff ff        call 0x180204754 (real_init)
         *   90 90 90 90 90 90 90  nop padding
         */
        volatile uint8_t *wrapper = (uint8_t*)0x180204ad0ULL;
        /* Keep sub rsp, 0x28 (first 4 bytes) */
        /* Replace bytes 4-8 with direct call to real_init */
        /* call rel32 = E8 + (target - (current+5)) */
        /* At 0x180204ad4: call 0x180204754 → offset = 0x204754 - 0x204ad9 = -0x385 = 0xFFFFFC7B */
        wrapper[4] = 0xE8;
        wrapper[5] = 0x7B;
        wrapper[6] = 0xFC;
        wrapper[7] = 0xFF;
        wrapper[8] = 0xFF;
        /* Nop the rest */
        for (int i = 9; i < 26; i++) wrapper[i] = 0x90;

        fprintf(stderr, "[BOOT] Patched wrapper to skip cookie init\n");
    }

    /* Use assembly trampoline (drawbridge_enter_ntum from trampoline.S) */
    extern uint64_t DK_GenericStub(uint64_t,uint64_t,uint64_t,uint64_t) __attribute__((ms_abi));
extern void drawbridge_enter_ntum(void *entry, void *stack, void *params);
    fprintf(stderr, "[BOOT] Byte at 0x1803a05d5: 0x%02x (expect 0x90)\n", *(volatile uint8_t*)0x1803a05d5ULL);
    ntum_patch_rcx_to_global(); ntum_patch_abi_call();
    /* Disable CFG in PE header */
    { uint8_t *pe_base = (uint8_t*)0x180000000ULL;
      uint32_t pe_off = *(uint32_t*)(pe_base + 60);
      uint16_t *dc = (uint16_t*)(pe_base + pe_off + 24 + 70);
      *dc &= ~0x4000;
      fprintf(stderr, "[BOOT] Disabled CFG (0x%04x)\n", *dc); }

    /* RE-APPLY all data section patches right before trampoline.
     * Demand-paging might have overwritten them. */
    *(volatile uint32_t*)0x18063f8c0ULL = 1;  /* boot flag */
    *(volatile uint64_t*)0x18063f8c8ULL = (uint64_t)&DK_AbiDispatcher;
    *(volatile uint64_t*)0x180a00008ULL = (uint64_t)&DK_AbiDispatcher;
    *(volatile uint64_t*)0x180c00008ULL = (uint64_t)args->params;
    *(volatile uint64_t*)0x180c00010ULL = args->params->Size;
    /* mlock params and all patched pages */
    mlock(args->params, 0x1000);
    mlock((void*)0x180600000ULL, 0x70000);  /* .data */
    mlock((void*)0x180a00000ULL, 0x1000);   /* .00cfg */

    /* CRITICAL: Write our pointers to .00cfg and make it READ-ONLY.
     * The NTUM's CFG init tries to zero this page - making it RO
     * causes SIGSEGV which our handler silently ignores (mprotect path). */
    *(volatile uint64_t*)0x180a00000ULL = (uint64_t)&DK_AbiDispatcher;  /* __guard_check_icall */
    *(volatile uint64_t*)0x180a00008ULL = (uint64_t)&DK_AbiDispatcher;  /* __guard_dispatch_icall */

    /* Write dispatcher to external page (will be re-armed by dispatcher on each call) */
    *(volatile uint64_t*)0x181100000ULL = (uint64_t)&DK_AbiDispatcher;
    mlock((void*)0x181100000ULL, 0x1000);
    fprintf(stderr, "[BOOT] Dispatcher at 0x181100000 = 0x%lx\n",
            (unsigned long)*(volatile uint64_t*)0x181100000ULL);
    mlock((void*)0x180c00000ULL, 0x2000);   /* .roafter */

    /* Verify key values */
    fprintf(stderr, "[BOOT] Verify: params->Size=0x%lx AbiTable=%p [0x180a00008]=0x%lx\n",
            (unsigned long)args->params->Size,
            args->params->HostAbiTable,
            (unsigned long)*(volatile uint64_t*)0x180a00008ULL);

    drawbridge_enter_ntum(real_init, (void*)ntum_stack, args->params);

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
        /* Fall back to any address */
        stack_base = mmap(NULL, BOOT_STACK_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (stack_base == MAP_FAILED) {
        perror("[BOOT] Cannot allocate boot stack");
        return -1;
    }

    /* Stack grows downward - top is base + size */
    void *stack_top = (uint8_t*)stack_base + BOOT_STACK_SIZE - 0x100; /* Leave some room */

    /* Align stack to 16 bytes (required by both ABIs) */
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
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024); /* 8MB thread stack */

    int ret = pthread_create(&boot_tid, &attr, boot_thread_fn, &args);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        fprintf(stderr, "[BOOT] Cannot create boot thread: %d\n", ret);
        return -1;
    }

    printf("[BOOT] Boot thread launched, waiting for NTUM...\n\n");

    /* Wait for the boot thread to complete */
    void *thread_result;
    pthread_join(boot_tid, &thread_result);

    printf("[BOOT] NTUM boot thread exited\n");
    return 0;
}

/* Direct call to NTUM init using ms_abi */
typedef void (__attribute__((ms_abi)) *ntum_init_fn)(void *rcx, void *rdx);

void ntum_direct_call(void *entry, void *stack, void *params) {
    /* Switch stack manually then call */
    register void *rsp_save asm("r12");
    rsp_save = __builtin_frame_address(0);
    
    /* Set rsp to NTUM stack */
    __asm__ volatile ("mov %0, %%rsp" :: "r"(stack) : "memory");
    
    /* Call the function with ms_abi convention */
    ntum_init_fn fn = (ntum_init_fn)entry;
    fn(params, params);
    
    /* Restore rsp (never reached) */
    __asm__ volatile ("mov %0, %%rsp" :: "r"(rsp_save) : "memory");
}

/* EXTRA: Patch NTUM init to read params from global [0x180c00008] 
 * instead of rcx register (works around the rcx corruption) */
void ntum_patch_rcx_to_global(void) {
    /* 0x18020478b: mov r14, rcx → mov r14, [rip+0x9fb876] = [0x180c00008] */
    volatile uint8_t *p1 = (uint8_t*)0x18020478bULL;
    p1[0] = 0x4c; p1[1] = 0x8b; p1[2] = 0x35;  /* mov r14, [rip+...] */
    p1[3] = 0x76; p1[4] = 0xb8; p1[5] = 0x9f; p1[6] = 0x00;  /* offset = 0x9fb876 */

    /* Fix: the original instruction was 3 bytes, new is 7 bytes.
     * We overwrite into 'mov esi, 0xc000000d' which starts at 0x18020478e.
     * The new mov r14 ends at 0x180204792. The mov esi starts at 0x18020478e
     * but we overwrote 4 bytes of it. We need to rewrite it at 0x180204792. */
    volatile uint8_t *p2 = (uint8_t*)0x180204792ULL;
    p2[0] = 0xbe; p2[1] = 0x0d; p2[2] = 0x00; p2[3] = 0x00; p2[4] = 0xc0;

    /* 0x180204797: test rcx, rcx → test r14, r14 */
    volatile uint8_t *p3 = (uint8_t*)0x180204797ULL;
    p3[0] = 0x4d; p3[1] = 0x85; p3[2] = 0xf6;  /* test r14, r14 */

    /* 0x18020479c: mov r8, [rcx] → mov r8, [r14] */
    volatile uint8_t *p4 = (uint8_t*)0x18020479cULL;
    p4[0] = 0x4d; p4[1] = 0x8b; p4[2] = 0x06;  /* mov r8, [r14] */

    /* Also patch 0x180204781: mov rdi, rdx → mov rdi, [rip+0x9fb880] = [0x180c00008] 
     * to also read params from global for the rdi copy */
    volatile uint8_t *p5 = (uint8_t*)0x180204781ULL;
    /* Original: 48 8b fa = mov rdi, rdx (3 bytes) */
    /* New: 48 8b 3d 80 b8 9f 00 = mov rdi, [rip+0x9fb880] (7 bytes) */
    /* But this needs 7 bytes and we only have 3. Skip this - use a different approach */
    /* Actually: mov rdi,rdx is fine because rdx = params from trampoline too */

    /* Also patch rdx→rdi to read from global (rdx might also be corrupted) */
    /* 0x180204781: mov rdi, rdx (3 bytes) → mov rdi, [rip+0x9fb880] (7 bytes)
     * RIP after = 0x180204788, target = 0x180c00008, offset = 0x180c00008-0x180204788=0x9fb880 */
    volatile uint8_t *p6 = (uint8_t*)0x180204781ULL;
    p6[0] = 0x48; p6[1] = 0x8b; p6[2] = 0x3d;  /* mov rdi, [rip+...] */
    p6[3] = 0x80; p6[4] = 0xb8; p6[5] = 0x9f; p6[6] = 0x00;

    /* The original 'mov [rip+...], rdx' at 0x180204784 was overwritten.
     * Rewrite it at 0x180204788 (after our 7-byte mov rdi):
     * We skip this store since it's just saving rdx to a global - not critical. */
    volatile uint8_t *p7 = (uint8_t*)0x180204788ULL;
    p7[0] = 0x90; p7[1] = 0x90; p7[2] = 0x90;  /* nop nop nop (was part of mov [rip],rdx) */

    /* Also need to fix 0x1802047c9: cmp [rdx+0x10], 0 → cmp [rdi+0x10], 0
     * Original: 48 83 7a 10 00 → 48 83 7f 10 00 */
    volatile uint8_t *p8 = (uint8_t*)0x1802047c9ULL;
    p8[2] = 0x7f;  /* Change 7a (rdx offset) to 7f (rdi offset) */

    /* 0x1802047ce: mov rax, [rdx+0x48] → mov rax, [rdi+0x48]
     * Original: 48 8b 42 48 → 48 8b 47 48 */
    volatile uint8_t *p9 = (uint8_t*)0x1802047ceULL;
    p9[2] = 0x47;

    /* 0x1802047f1: mov rdx, [rdx+0x10] → mov rdx, [rdi+0x10]
     * Original: 48 8b 52 10 → 48 8b 57 10 */
    volatile uint8_t *p10 = (uint8_t*)0x1802047f1ULL;
    p10[2] = 0x57;

    fprintf(stderr, "[BOOT] Patched NTUM init: rcx+rdx→globals at [0x180c00008]\n");

    /* Patch ALL __fastfail (int 0x29 = CD 29) in .text to nop nop */
    volatile uint8_t *text = (uint8_t*)0x180200000ULL;
    int ff_count = 0;
    for (size_t i = 0; i < 0x1AA000 - 1; i++) {
        if (text[i] == 0xCD && text[i+1] == 0x29) {
            text[i] = 0x90;
            text[i+1] = 0x90;
            ff_count++;
        }
    }
    fprintf(stderr, "[BOOT] Patched %d __fastfail (int 0x29) calls\n", ff_count);
}

/* Patch ALL indirect calls through [0x180a00008] to use [0x181100000] instead.
 * The .00cfg section gets zeroed by CFG initialization.
 * We store our ABI dispatcher at 0x181100000 (.data) which is safe. */
void ntum_patch_abi_call(void) {
    /* Store our dispatcher address at 0x181100000 (.data section) */
    *(volatile uint64_t*)0x181100000ULL = (uint64_t)&DK_AbiDispatcher;

    /* Scan .text for all 'ff 15 XX XX XX XX' instructions that target 0x180a00008.
     * Rewrite them to target 0x181100000 instead. */
    volatile uint8_t *text = (uint8_t*)0x180200000ULL;
    size_t text_size = 0x1AA000;
    int patched = 0;

    for (size_t i = 0; i + 6 <= text_size; i++) {
        if (text[i] == 0xFF && (text[i+1] == 0x15 || text[i+1] == 0x25)) {
            /* Indirect call/jmp through [rip+disp32] */
            int32_t disp = *(int32_t*)&text[i+2];
            uint64_t rip = 0x180200000ULL + i + 6;
            uint64_t target = rip + disp;
            if (target == 0x180a00008ULL) {
                /* Rewrite displacement to point to 0x181100000 */
                int32_t new_disp = (int32_t)(0x181100000ULL - rip);
                *(volatile int32_t*)&text[i+2] = new_disp;
                patched++;
            }
        }
    }

    /* Also patch mov rax, [0x180a00000] at 0x1803a0244 */
    *(volatile uint64_t*)0x180640008ULL = (uint64_t)&DK_AbiDispatcher; /* CFG check */
    volatile uint8_t *cfg = (uint8_t*)0x1803a0247ULL; /* offset bytes of the mov */
    int32_t cfg_disp = (int32_t)(0x180640008ULL - 0x1803a024bULL);
    *(volatile int32_t*)cfg = cfg_disp;
    fprintf(stderr, "[BOOT] Patched CFG check to use .data at [0x180640008]\n");
    fprintf(stderr, "[BOOT] Patched %d ABI calls: [0x180a00008] → [0x181100000]\n", patched);
}
