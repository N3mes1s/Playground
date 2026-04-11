#define _GNU_SOURCE
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

/* PE image data source for demand-paging.
 * When a page in the PE range faults, we copy data from the raw PE. */
static uint8_t *g_pe_raw_data = NULL;  /* Raw PE file data mapped from SFP */
static size_t   g_pe_raw_size = 0;
static uint64_t g_pe_image_base = 0;

/* PE section info for demand-paging */
typedef struct {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;     /* PointerToRawData in file */
    uint32_t raw_size;       /* SizeOfRawData */
} pe_section_info_t;

static pe_section_info_t g_pe_sections[16];
static int g_pe_num_sections = 0;

void ntum_signal_set_pe_data(void *raw_data, size_t raw_size, uint64_t image_base) {
    g_pe_raw_data = (uint8_t*)raw_data;
    g_pe_raw_size = raw_size;
    g_pe_image_base = image_base;

    /* Parse PE sections from the raw data */
    if (raw_data && raw_size > 0x200) {
        uint8_t *d = (uint8_t*)raw_data;
        uint32_t pe_off = *(uint32_t*)(d + 60);
        if (pe_off + 24 < raw_size) {
            uint16_t num_sec = *(uint16_t*)(d + pe_off + 6);
            uint16_t opt_size = *(uint16_t*)(d + pe_off + 20);
            uint8_t *sec_hdr = d + pe_off + 24 + opt_size;
            g_pe_num_sections = (num_sec > 16) ? 16 : num_sec;
            for (int i = 0; i < g_pe_num_sections; i++) {
                g_pe_sections[i].virtual_address = *(uint32_t*)(sec_hdr + i*40 + 12);
                g_pe_sections[i].virtual_size = *(uint32_t*)(sec_hdr + i*40 + 8);
                g_pe_sections[i].raw_offset = *(uint32_t*)(sec_hdr + i*40 + 20);
                g_pe_sections[i].raw_size = *(uint32_t*)(sec_hdr + i*40 + 16);
            }
            fprintf(stderr, "[SIGNAL] PE sections loaded: %d sections for demand-paging\n",
                    g_pe_num_sections);
        }
    }
}

/*
 * Check if an address is in the LibOS VM range and handle the fault.
 * Returns 1 if handled, 0 if not (should crash).
 */
static int handle_libos_fault(void *fault_addr, int is_write, ucontext_t *uc) {
    uintptr_t addr = (uintptr_t)fault_addr;

    /* Align to page boundary */
    uintptr_t page = addr & ~0xFFFULL;

    /* Check if in LibOS range. Reject NULL page (real crash). */
    if (addr >= LIBOS_VM_END)
        return 0;  /* NULL or outside range - real crash */

    /* Try to map the faulted page.
     * This handles guard pages and demand-paged sections.
     * The NTUM's internal memory manager expects pages to
     * become available when accessed. */
    /* Use MAP_FIXED_NOREPLACE first - if the page is already mapped
     * (has our patches), DON'T replace it. Only map truly unmapped pages. */
    void *result = mmap((void*)page, 0x1000,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                         -1, 0);
    if (result == MAP_FAILED) {
        /* Page already mapped but faulted anyway (permission issue).
         * Change permissions to RWX and return. */
        mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
        ntum_fault_count++;
        return 1;
    }
    if (result != MAP_FAILED) {
        ntum_fault_count++;

        /* If this page is within the PE image, copy actual section data.
         * SKIP .data and .roafter sections because we wrote runtime values
         * there (boot flag, dispatcher, cookie) that would be overwritten. */
        int is_patched_section = 0;
        if (addr >= g_pe_image_base) {
            uint64_t rva = page - g_pe_image_base;
            if (rva >= 0x600000 && rva < 0x670000) is_patched_section = 1;  /* .data */
            if (rva >= 0xc00000 && rva < 0xc02000) is_patched_section = 1;  /* .roafter */
            /* .00cfg is NOT protected - its PE-native values are correct */
        }
        if (g_pe_raw_data && addr >= g_pe_image_base && !is_patched_section) {
            uint64_t rva = page - g_pe_image_base;  /* RVA of the faulted page */

            /* Find which section this RVA falls in */
            for (int s = 0; s < g_pe_num_sections; s++) {
                uint32_t sec_va = g_pe_sections[s].virtual_address;
                uint32_t sec_vs = g_pe_sections[s].virtual_size;
                if (rva >= sec_va && rva < sec_va + sec_vs) {
                    /* Found the section - calculate raw file offset */
                    uint32_t offset_in_section = (uint32_t)(rva - sec_va);
                    uint32_t raw_off = g_pe_sections[s].raw_offset + offset_in_section;
                    uint32_t raw_remain = 0;
                    if (offset_in_section < g_pe_sections[s].raw_size)
                        raw_remain = g_pe_sections[s].raw_size - offset_in_section;
                    size_t copy_sz = (raw_remain > 0x1000) ? 0x1000 : raw_remain;
                    if (copy_sz > 0 && raw_off + copy_sz <= g_pe_raw_size) {
                        memcpy(result, g_pe_raw_data + raw_off, copy_sz);
                        /* No patches - use the PE's original code as-is.
                         * The PE has built-in CFG functions, and the SIGTRAP
                         * handler deals with int3 bytes at runtime. */
                    }
                    break;
                }
            }

            /* Headers (RVA < first section) */
            if (rva < 0x1000 && g_pe_raw_size >= 0x1000)
                memcpy(result, g_pe_raw_data + rva, 0x1000);
        }

        if (ntum_fault_count <= 200) {
            uintptr_t rip = uc ? uc->uc_mcontext.gregs[REG_RIP] : 0;
            fprintf(stderr, "[FAULT] #%d 0x%lx %s RIP=0x%lx%s\n",
                    ntum_fault_count, (unsigned long)page,
                    is_write ? "W" : "R",
                    (unsigned long)rip,
                    (addr >= g_pe_image_base && addr < g_pe_image_base + g_pe_raw_size)
                        ? " +PE" : "");
        }
        return 1;
    }

    return 0;  /* Cannot map - real crash */
}

static void ntum_signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t*)ctx;
    void *fault_addr = info->si_addr;
    int is_write = (uc->uc_mcontext.gregs[REG_ERR] & 0x2) != 0;

    if (sig == SIGSEGV || sig == SIGBUS) {
        /* Dump full register state and stack for first fault */
        if (ntum_fault_count < 2) {
            uint64_t rsp = uc->uc_mcontext.gregs[REG_RSP];
            char msg[1024];
            int l = snprintf(msg, sizeof(msg),
                "[REGS] FAULT#%d addr=%p sig=%d\n"
                "  RIP=0x%llx RSP=0x%llx RBP=0x%llx\n"
                "  RAX=0x%llx RBX=0x%llx RCX=0x%llx\n"
                "  RDX=0x%llx RSI=0x%llx RDI=0x%llx\n"
                "  R8=0x%llx R9=0x%llx R14=0x%llx R15=0x%llx\n"
                "  [RSP]=0x%llx [RSP+8]=0x%llx [RSP+16]=0x%llx\n",
                ntum_fault_count, fault_addr, sig,
                (unsigned long long)uc->uc_mcontext.gregs[REG_RIP],
                (unsigned long long)rsp,
                (unsigned long long)uc->uc_mcontext.gregs[REG_RBP],
                (unsigned long long)uc->uc_mcontext.gregs[REG_RAX],
                (unsigned long long)uc->uc_mcontext.gregs[REG_RBX],
                (unsigned long long)uc->uc_mcontext.gregs[REG_RCX],
                (unsigned long long)uc->uc_mcontext.gregs[REG_RDX],
                (unsigned long long)uc->uc_mcontext.gregs[REG_RSI],
                (unsigned long long)uc->uc_mcontext.gregs[REG_RDI],
                (unsigned long long)uc->uc_mcontext.gregs[REG_R8],
                (unsigned long long)uc->uc_mcontext.gregs[REG_R9],
                (unsigned long long)uc->uc_mcontext.gregs[REG_R14],
                (unsigned long long)uc->uc_mcontext.gregs[REG_R15],
                rsp >= 0x180000000ULL ? (unsigned long long)*(uint64_t*)rsp : 0ULL,
                rsp >= 0x180000000ULL ? (unsigned long long)*(uint64_t*)(rsp+8) : 0ULL,
                rsp >= 0x180000000ULL ? (unsigned long long)*(uint64_t*)(rsp+16) : 0ULL);
            write(2, msg, l);
        }
        if (handle_libos_fault(fault_addr, is_write, uc)) {
            return;  /* Handled - resume execution */
        }
    }

    /* Handle SIGTRAP (int3) - skip the int3 byte and continue */
    if (sig == SIGTRAP) {
        uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
        /* Check if RIP is in NTUM code and the byte before is 0xCC (int3) */
        if (rip >= PE_IMAGE_START && rip < PE_IMAGE_END) {
            /* int3 already executed, RIP points AFTER the CC byte.
             * Patch the byte to NOP for future executions and resume. */
            uint8_t *cc = (uint8_t*)(rip - 1);
            if (*cc == 0xCC) *cc = 0x90;
            ntum_fault_count++;
            return;  /* Resume execution after the (now-patched) int3 */
        }
    }

    /* Unhandled fault */
    char msg[512];
    int len = snprintf(msg, sizeof(msg),
        "\n[CRASH] sig=%d addr=%p RIP=0x%llx faults=%d\n"
        "  [0x181100000]=0x%llx [0x180a00008]=0x%llx\n"
        "  RCX=0x%llx RDX=0x%llx RSP=0x%llx\n",
        sig, fault_addr,
        (unsigned long long)uc->uc_mcontext.gregs[REG_RIP],
        ntum_fault_count,
        (unsigned long long)*(volatile uint64_t*)0x181100000ULL,
        (unsigned long long)*(volatile uint64_t*)0x180a00008ULL,
        (unsigned long long)uc->uc_mcontext.gregs[REG_RCX],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RDX],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RSP]);
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
    sigaction(SIGTRAP, &sa, NULL);  /* Handle SIGTRAP from remaining int3 bytes */

    fprintf(stderr, "[SIGNAL] Handler installed (SIGSEGV/SIGBUS/SIGFPE) altstack=%p\n", ss.ss_sp);
}
