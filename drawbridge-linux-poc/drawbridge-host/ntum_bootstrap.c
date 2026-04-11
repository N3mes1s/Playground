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

    /* Call the trampoline - this doesn't return normally */
    ntum_trampoline(args->entry_point,
                    args->stack_top,
                    args->params,   /* becomes rcx = LIBOS_PARAMS */
                    NULL);          /* becomes rdx = 0 */

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
