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
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

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
    uint64_t ntum_stack = ntum_stack_base + *stack_adj_ptr;

    printf("[BOOT] Cookie: 0x%lx at 0x180600000\n", (unsigned long)cv);
    printf("[BOOT] NTUM stack: 0x%lx (base 0x%lx + adj 0x%lx)\n",
           (unsigned long)ntum_stack, (unsigned long)ntum_stack_base,
           (unsigned long)*stack_adj_ptr);

    /* Jump directly to 0x180204754 (the real init) using our trampoline.
     * rcx = LIBOS_PARAMS, rdx = LIBOS_PARAMS (config context) */
    void *real_init = (void*)((uint8_t*)args->params->ImageBase + 0x204754);
    /* Verify the bytes at the target haven't been patched incorrectly */
    volatile uint8_t *target = (uint8_t*)real_init;
    printf("[BOOT] Entering REAL init at %p bytes: %02x %02x %02x %02x %02x\n",
           real_init, target[0], target[1], target[2], target[3], target[4]);
    printf("[BOOT] Expected: 48 89 5c 24 18 (mov [rsp+0x18], rbx)\n");
    printf("[BOOT] Params ptr: %p\n\n", (void*)args->params);

    /* Direct trampoline via inline asm - no function call overhead.
     * This avoids any naked/ms_abi confusion. */
    void *entry = real_init;
    void *stack = (void*)ntum_stack;
    void *p1 = args->params;
    void *p2 = args->params;

    __asm__ volatile (
        /* Set up Win64 args: rcx=p1, rdx=p2 */
        "movq %2, %%rcx\n"       /* rcx = params (Win64 arg1) */
        "movq %3, %%rdx\n"       /* rdx = params (Win64 arg2) */
        /* Switch to NTUM stack */
        "movq %1, %%rsp\n"       /* rsp = ntum_stack */
        /* Zero frame pointer */
        "xorq %%rbp, %%rbp\n"
        /* Jump to init function */
        "jmpq *%0\n"
        :
        : "r"(entry), "r"(stack), "r"(p1), "r"(p2)
        : "rcx", "rdx", "rbp", "memory"
    );

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
