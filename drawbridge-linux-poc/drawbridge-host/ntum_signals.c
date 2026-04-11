#include <stdint.h>
/*
 * NTUM Signal Handler - Forwards signals to the NTUM's exception dispatcher
 *
 * The NTUM (sqlpal.dll) uses signals for:
 * 1. Guard page faults (stack growth)
 * 2. Demand paging of PE sections
 * 3. Structured Exception Handling (SEH)
 *
 * We register a signal handler that checks if the fault address is
 * in the LibOS address space. If yes, we handle it (e.g., by mapping
 * the faulted page). If no, we let it crash.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>

/* LibOS address range */
#define LIBOS_VM_START  0x10000ULL
#define LIBOS_VM_END    0x400000000000ULL

/* PE image range */
#define PE_IMAGE_START  0x180000000ULL
#define PE_IMAGE_END    0x181010000ULL  /* SizeOfImage + extra */

/* Heap ranges */
#define KERNEL_HEAP_START 0x300000000ULL
#define KERNEL_HEAP_END   0x340000000ULL
#define APP_HEAP_START    0x500000000ULL
#define APP_HEAP_END      0x540000000ULL

static int ntum_fault_count = 0;

/*
 * Check if an address is in the LibOS VM range and handle the fault.
 * Returns 1 if handled, 0 if not (should crash).
 */
static int handle_libos_fault(void *fault_addr, int is_write, ucontext_t *uc) {
    uintptr_t addr = (uintptr_t)fault_addr;

    /* Align to page boundary */
    uintptr_t page = addr & ~0xFFFULL;

    /* Check if in LibOS range */
    if (addr < LIBOS_VM_START || addr >= LIBOS_VM_END)
        return 0;  /* Not in LibOS range - real crash */

    /* Try to map the faulted page.
     * This handles guard pages and demand-paged sections.
     * The NTUM's internal memory manager expects pages to
     * become available when accessed. */
    void *result = mmap((void*)page, 0x1000,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                         -1, 0);
    if (result != MAP_FAILED) {
        ntum_fault_count++;
        if (ntum_fault_count <= 50) {
            /* Log first 50 faults for debugging */
            fprintf(stderr, "[FAULT] Mapped page 0x%lx (fault #%d, %s)\n",
                    (unsigned long)page, ntum_fault_count,
                    is_write ? "write" : "read");
        }
        return 1;  /* Handled - resume execution */
    }

    return 0;  /* Cannot map - real crash */
}

static void ntum_signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t*)ctx;
    void *fault_addr = info->si_addr;
    int is_write = (uc->uc_mcontext.gregs[REG_ERR] & 0x2) != 0;

    if (sig == SIGSEGV || sig == SIGBUS) {
        if (handle_libos_fault(fault_addr, is_write, uc)) {
            return;  /* Handled - resume execution */
        }
    }

    /* Unhandled fault - write() is async-signal-safe */
    char msg[512];
    int len = snprintf(msg, sizeof(msg),
        "\n[CRASH] sig=%d addr=%p RIP=0x%llx RCX=0x%llx faults=%d\n",
        sig, fault_addr,
        (unsigned long long)uc->uc_mcontext.gregs[REG_RIP],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RCX],
        ntum_fault_count);
    write(STDERR_FILENO, msg, len);
    _exit(128 + sig);
}

/*
 * Install the NTUM signal handler.
 * Uses sigaltstack for a separate signal stack (like the real sqlservr).
 */
void ntum_signal_init(void) {
    /* Set up alternate signal stack (8MB) */
    stack_t ss;
    ss.ss_sp = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ss.ss_size = 8 * 1024 * 1024;
    ss.ss_flags = 0;
    if (ss.ss_sp != MAP_FAILED) {
        sigaltstack(&ss, NULL);
    }

    /* Register signal handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ntum_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    /* Do NOT handle SIGTRAP - let the NTUM use int3 for its own purposes */

    fprintf(stderr, "[SIGNAL] Handler installed (SIGSEGV/SIGBUS/SIGFPE) altstack=%p\n", ss.ss_sp);
}
