/*
 * NTUM Signal Handler - Exception forwarding to NTUM kernel
 *
 * Reverse-engineered from FUN_002899d0 (signal handler) and
 * FUN_002897e0 (exception record builder) in sqlservr.
 *
 * The NTUM uses Linux signals as a mechanism to implement Windows
 * Structured Exception Handling (SEH):
 *
 *   1. Signal occurs in NTUM code (SIGSEGV, SIGTRAP, etc.)
 *   2. Host signal handler builds Windows EXCEPTION_RECORD from ucontext
 *   3. Host rewrites RIP → KiUserExceptionDispatcher (in NTUM)
 *   4. Host passes exception record in RCX, thread state in RDX
 *   5. Signal handler returns → NTUM resumes at its exception dispatcher
 *
 * See analysis/EXCEPTION_DISPATCH_RE.md for full documentation.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>

#include "drawbridge_types.h"

/* ================================================================
 * Exception Record (0x280 = 640 bytes)
 *
 * From FUN_002897e0: builds this from ucontext_t registers.
 * The NTUM's KiUserExceptionDispatcher receives a pointer to this.
 * ================================================================ */

typedef struct {
    uint32_t error_code;         /* 0x000: from EFLAGS (gregs[REG_EFL]) */
    uint16_t cs_low;             /* 0x004: CS segment low */
    uint32_t zero;               /* 0x006: always 0 */
    uint16_t cs_high;            /* 0x00a: CS >> 32 */
    uint16_t selector;           /* 0x00c: = 0x2b (code selector) */
    uint16_t _pad0;              /* 0x00e */
    uint64_t rax;                /* 0x010 */
    uint64_t rbx;                /* 0x018 */
    uint64_t rcx;                /* 0x020 */
    uint64_t rdx;                /* 0x028 */
    uint64_t rsi;                /* 0x030 */
    uint64_t r8_r9[2];           /* 0x038: R8, R9 (from param_1+0x70) */
    uint64_t rdi;                /* 0x048 */
    uint64_t rbp;                /* 0x050 */
    uint64_t rsp;                /* 0x058 */
    uint64_t r10;                /* 0x060 */
    uint64_t r11;                /* 0x068 */
    uint64_t r12;                /* 0x070 */
    uint64_t r13;                /* 0x078 */
    uint64_t r14;                /* 0x080 */
    uint64_t r15;                /* 0x088 */
    uint64_t rip;                /* 0x090 */
    uint8_t  fpu_state[0x1a0];   /* 0x0a0: FPU/XMM register state */
    uint8_t  _reserved[0x40];    /* 0x240: padding to 0x280 */
} dk_exception_record_t;

/* Exception info passed to the allocation function */
typedef struct {
    uint32_t exception_code;     /* Windows exception code */
    uint32_t _pad;
    uint64_t fault_address;      /* RIP at fault */
    uint64_t params[5];          /* Exception parameters */
} dk_exception_info_t;

/* ================================================================
 * Globals
 * ================================================================ */

static int g_fault_count = 0;

/* PE image data source for demand-paging */
static uint8_t *g_pe_raw_data = NULL;
static size_t   g_pe_raw_size = 0;
static uint64_t g_pe_image_base = 0;

/* PE section info for demand-paging */
static pe_section_info_t g_pe_sections[MAX_PE_SECTIONS];
static int g_pe_num_sections = 0;

/* RuntimeCallbackState - the NTUM writes KiUserExceptionDispatcher
 * address to offset 0x10 during boot initialization.
 * DAT_003b2148 = DAT_003b2138 + 0x10, where DAT_003b2138 is
 * RuntimeCallbackState passed as param_6 to FUN_0020ba60. */
extern uint8_t g_runtime_callback_state[];

/* Thread control block pointer (from FS_OFFSET - 0x10).
 * Set up during boot_thread_fn in ntum_bootstrap.c */

/* ================================================================
 * PE Data Setup (for demand-paging)
 * ================================================================ */

void ntum_signal_set_pe_data(void *raw_data, size_t raw_size,
                              uint64_t image_base) {
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
            g_pe_num_sections = (num_sec > MAX_PE_SECTIONS) ? MAX_PE_SECTIONS : num_sec;
            for (int i = 0; i < g_pe_num_sections; i++) {
                g_pe_sections[i].virtual_address = *(uint32_t*)(sec_hdr + i*40 + 12);
                g_pe_sections[i].virtual_size    = *(uint32_t*)(sec_hdr + i*40 + 8);
                g_pe_sections[i].raw_offset      = *(uint32_t*)(sec_hdr + i*40 + 20);
                g_pe_sections[i].raw_size        = *(uint32_t*)(sec_hdr + i*40 + 16);
            }
            fprintf(stderr, "[SIGNAL] PE sections loaded: %d sections for demand-paging\n",
                    g_pe_num_sections);
        }
    }
}

/* ================================================================
 * Demand-Paging: Handle page faults in LibOS address space
 *
 * Maps anonymous pages and copies PE section data into them.
 * Protected sections (.data, .roafter) are NOT overwritten because
 * they contain runtime values (boot flag, dispatcher, cookie).
 * ================================================================ */

static int handle_libos_fault(void *fault_addr, ucontext_t *uc) {
    uintptr_t addr = (uintptr_t)fault_addr;
    uintptr_t page = addr & ~0xFFFULL;

    if (addr >= LIBOS_VM_END)
        return 0;

    /* Don't map NULL page or very low addresses - these are real crashes */
    if (addr < LIBOS_VM_START) {
        uintptr_t rip = uc ? uc->uc_mcontext.gregs[REG_RIP] : 0;
        fprintf(stderr, "[FAULT] NULL deref at 0x%lx from RIP=0x%lx - not mapped\n",
                (unsigned long)addr, (unsigned long)rip);
        return 0;
    }

    /* Map the faulted page (MAP_FIXED_NOREPLACE preserves existing maps) */
    void *result = mmap((void*)page, 0x1000,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        -1, 0);
    if (result == MAP_FAILED) {
        /* Already mapped but faulted (permission issue) - fix permissions */
        mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
        g_fault_count++;
        return 1;
    }

    g_fault_count++;

    /* If page is in PE image, copy actual section data.
     * Skip .data and .roafter (contain our runtime patches). */
    int is_patched = 0;
    if (addr >= g_pe_image_base) {
        uint64_t rva = page - g_pe_image_base;
        if (rva >= (NTUM_DATA_START - g_pe_image_base) &&
            rva < (NTUM_DATA_END - g_pe_image_base))
            is_patched = 1;
        if (rva >= (NTUM_ROAFTER_START - g_pe_image_base) &&
            rva < (NTUM_ROAFTER_END - g_pe_image_base))
            is_patched = 1;
    }

    if (g_pe_raw_data && addr >= g_pe_image_base && !is_patched) {
        uint64_t rva = page - g_pe_image_base;

        for (int s = 0; s < g_pe_num_sections; s++) {
            uint32_t sec_va = g_pe_sections[s].virtual_address;
            uint32_t sec_vs = g_pe_sections[s].virtual_size;
            if (rva >= sec_va && rva < sec_va + sec_vs) {
                uint32_t off_in_sec = (uint32_t)(rva - sec_va);
                uint32_t raw_off = g_pe_sections[s].raw_offset + off_in_sec;
                uint32_t raw_remain = 0;
                if (off_in_sec < g_pe_sections[s].raw_size)
                    raw_remain = g_pe_sections[s].raw_size - off_in_sec;
                size_t copy_sz = (raw_remain > 0x1000) ? 0x1000 : raw_remain;
                if (copy_sz > 0 && raw_off + copy_sz <= g_pe_raw_size)
                    memcpy(result, g_pe_raw_data + raw_off, copy_sz);
                break;
            }
        }

        /* Headers (RVA < first section) */
        if (rva < 0x1000 && g_pe_raw_size >= 0x1000)
            memcpy(result, g_pe_raw_data + rva, 0x1000);
    }

    if (g_fault_count <= 200) {
        uintptr_t rip = uc ? uc->uc_mcontext.gregs[REG_RIP] : 0;
        fprintf(stderr, "[FAULT] #%d 0x%lx RIP=0x%lx%s\n",
                g_fault_count, (unsigned long)page, (unsigned long)rip,
                (addr >= g_pe_image_base && addr < g_pe_image_base + g_pe_raw_size)
                    ? " +PE" : "");
    }
    return 1;
}

/* ================================================================
 * Exception Forwarding to NTUM
 *
 * This is the critical mechanism from FUN_002899d0.
 * Builds a Windows exception record and rewrites RIP to the
 * NTUM's KiUserExceptionDispatcher.
 * ================================================================ */

/*
 * Build exception record from ucontext (FUN_002897e0).
 * Copies CPU register state into the dk_exception_record_t format.
 */
static void build_exception_record(ucontext_t *uc, dk_exception_record_t *rec) {
    memset(rec, 0, sizeof(*rec));

    greg_t *gregs = uc->uc_mcontext.gregs;

    /* Header fields from ucontext */
    rec->error_code = (uint32_t)gregs[REG_EFL];
    uint64_t csgsfs = (uint64_t)gregs[REG_CSGSFS];
    rec->cs_low     = (uint16_t)csgsfs;
    rec->zero       = 0;
    rec->cs_high    = (uint16_t)(csgsfs >> 32);
    rec->selector   = 0x2b;

    /* GPRs - matching FUN_002897e0 field order */
    rec->rax = (uint64_t)gregs[REG_RAX];
    rec->rbx = (uint64_t)gregs[REG_RBX];
    rec->rcx = (uint64_t)gregs[REG_RCX];
    rec->rdx = (uint64_t)gregs[REG_RDX];
    rec->rsi = (uint64_t)gregs[REG_RSI];
    rec->r8_r9[0] = (uint64_t)gregs[REG_R8];
    rec->r8_r9[1] = (uint64_t)gregs[REG_R9];
    rec->rdi = (uint64_t)gregs[REG_RDI];
    rec->rbp = (uint64_t)gregs[REG_RBP];
    rec->rsp = (uint64_t)gregs[REG_RSP];
    rec->r10 = (uint64_t)gregs[REG_R10];
    rec->r11 = (uint64_t)gregs[REG_R11];
    rec->r12 = (uint64_t)gregs[REG_R12];
    rec->r13 = (uint64_t)gregs[REG_R13];
    rec->r14 = (uint64_t)gregs[REG_R14];
    rec->r15 = (uint64_t)gregs[REG_R15];
    rec->rip = (uint64_t)gregs[REG_RIP];

    /* FPU/XMM state */
    if (uc->uc_mcontext.fpregs) {
        memcpy(rec->fpu_state, uc->uc_mcontext.fpregs,
               sizeof(rec->fpu_state) < 512 ? sizeof(rec->fpu_state) : 512);
    }
}

/*
 * Forward an exception to the NTUM's KiUserExceptionDispatcher.
 *
 * This implements the core of FUN_002899d0 (LAB_0028a269):
 *   1. Allocate exception record (0x280 bytes)
 *   2. Fill with CPU state from ucontext
 *   3. Rewrite RIP to KiUserExceptionDispatcher
 *   4. Pass record pointer in RCX
 *   5. Pass thread state in RDX
 */
static int forward_exception_to_ntum(int sig, ucontext_t *uc) {
    /* Read KiUserExceptionDispatcher address from RuntimeCallbackState + 0x10 */
    uint64_t ki_dispatcher = *(volatile uint64_t*)(g_runtime_callback_state + 0x10);

    if (ki_dispatcher == 0 || ki_dispatcher < PE_IMAGE_START || ki_dispatcher >= PE_IMAGE_END) {
        /* NTUM hasn't set up the exception dispatcher yet - can't forward.
         * This is expected during early boot. Fall back to demand-paging. */
        return 0;
    }

    /* Allocate exception record in LibOS address space */
    dk_exception_record_t *record = (dk_exception_record_t*)
        mmap(NULL, sizeof(dk_exception_record_t),
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (record == MAP_FAILED) return 0;

    /* Build exception record from ucontext */
    build_exception_record(uc, record);

    /* For SIGTRAP (int3): adjust RIP back by 1 (past the int3 byte) */
    if (sig == SIGTRAP && !(uc->uc_mcontext.gregs[REG_EFL] & 0x100)) {
        record->rip = (uint64_t)uc->uc_mcontext.gregs[REG_RIP] - 1;
        uc->uc_mcontext.gregs[REG_RIP] -= 1;
    }

    /* Get thread state from FS_OFFSET - 0x10 */
    unsigned long fs_base;
    __asm__ volatile("mov %%fs:(-0x10), %0" : "=r"(fs_base));
    uint64_t thread_state = 0;
    if (fs_base) {
        thread_state = *(uint64_t*)(fs_base + 0x68);
    }

    /* Clear trap flag (TF) in EFLAGS */
    uc->uc_mcontext.gregs[REG_EFL] &= ~0x100;

    /* Rewrite ucontext to resume at KiUserExceptionDispatcher:
     *   RIP = KiUserExceptionDispatcher
     *   RCX = pointer to exception record
     *   RDX = thread state pointer
     */
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)ki_dispatcher;
    uc->uc_mcontext.gregs[REG_RCX] = (greg_t)(uint64_t)record;
    uc->uc_mcontext.gregs[REG_RDX] = (greg_t)thread_state;

    static int fwd_count = 0;
    fwd_count++;
    if (fwd_count <= 50) {
        fprintf(stderr, "[EXCEPTION] #%d sig=%d → KiUserExceptionDispatcher at 0x%lx "
                "(record=%p, thread_state=0x%lx)\n",
                fwd_count, sig, (unsigned long)ki_dispatcher,
                record, (unsigned long)thread_state);
    }

    return 1;  /* Exception forwarded - signal handler will return */
}

/* ================================================================
 * Main Signal Handler
 * ================================================================ */

static void ntum_signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t*)ctx;
    void *fault_addr = info->si_addr;
    uintptr_t rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];

    /* ---- SIGSEGV/SIGBUS: Try demand-paging first ---- */
    if (sig == SIGSEGV || sig == SIGBUS) {
        /* Dump registers for first few faults */
        if (g_fault_count < 2) {
            fprintf(stderr, "[REGS] sig=%d addr=%p RIP=0x%llx RSP=0x%llx\n"
                    "  RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                    sig, fault_addr,
                    (unsigned long long)uc->uc_mcontext.gregs[REG_RIP],
                    (unsigned long long)uc->uc_mcontext.gregs[REG_RSP],
                    (unsigned long long)uc->uc_mcontext.gregs[REG_RAX],
                    (unsigned long long)uc->uc_mcontext.gregs[REG_RBX],
                    (unsigned long long)uc->uc_mcontext.gregs[REG_RCX],
                    (unsigned long long)uc->uc_mcontext.gregs[REG_RDX]);
        }

        /* Try demand-paging */
        if (handle_libos_fault(fault_addr, uc))
            return;

        /* Special handling for thread switcher NULL dereference at RVA 0x3a0674:
         * [rcx+0x10] = NULL (stack_info not set). Instead of crashing, redirect
         * to the fallback path at 0x3a06c9 which uses [rdx+0x10] (thread block
         * stack_base) instead. This simulates what would happen if the comparison
         * at 0x3a067c failed (r9 < r10). */
        /* Log thread switcher crashes with diagnostic info */
        if (rip == (PE_IMAGE_START + 0x3a0674) && (uintptr_t)fault_addr < 0x1000) {
            uint64_t gs_val = 0;
            __asm__ volatile("mov %%gs:(0x30), %0" : "=r"(gs_val));
            fprintf(stderr, "[FATAL] Thread switcher NULL at 0x3a0674\n"
                    "  rcx=%p [rcx+0x10]=0x%lx\n"
                    "  gs:0x30=0x%lx [gs+0x1478]=0x%lx\n"
                    "  [0x63b218]=0x%lx\n",
                    (void*)uc->uc_mcontext.gregs[REG_RCX],
                    *(uint64_t*)((uint8_t*)uc->uc_mcontext.gregs[REG_RCX] + 0x10),
                    (unsigned long)gs_val,
                    gs_val ? (unsigned long)*(uint64_t*)((uint8_t*)gs_val + 0x1478) : 0,
                    (unsigned long)*(volatile uint64_t*)0x18063b218ULL);
        }
    }

    /* ---- SIGTRAP: Boot sync + exception forwarding for int3 callbacks ---- */
    if (sig == SIGTRAP) {
        static int trap_count = 0;
        trap_count++;

        if (rip >= PE_IMAGE_START && rip < PE_IMAGE_END) {
            uint8_t *cc = (uint8_t*)(rip - 1);

            /* Check for int3 byte */
            if (*cc == 0xCC) {
                uint8_t *next = (uint8_t*)rip;

                /* Check for CC EB FD pattern (int3 + jmp -3 = boot spin loop).
                 * The NTUM spins here waiting for the host to set a flag.
                 * Must handle this BEFORE exception forwarding is available. */
                if (next[0] == 0xEB && next[1] == 0xFD) {
                    uint8_t *prev2 = (uint8_t*)(rip - 3);
                    int is_boot_sync = (prev2[0] == 0x74);  /* je = conditional */

                    if (is_boot_sync) {
                        /* Boot sync: set flag, patch spin loop to nops */
                        extern uint64_t DK_AbiDispatcher(uint64_t,uint64_t,uint64_t,void*,uint64_t,void*) __attribute__((ms_abi));
                        *(volatile uint32_t*)NTUM_BOOT_FLAG_ADDR = 1;
                        *(volatile uint64_t*)NTUM_ABI_DISPATCHER_ADDR = (uint64_t)&DK_AbiDispatcher;
                        cc[0] = 0x90; next[0] = 0x90; next[1] = 0x90;
                        if (trap_count <= 20) {
                            fprintf(stderr, "[TRAP] #%d Boot sync at 0x%lx - flag set, patched\n",
                                    trap_count, (unsigned long)(rip - 1));
                        }
                        return;
                    } else {
                        /* Debug assertion - don't forward to thread switcher.
                         * Patch to ret and continue. */
                        cc[0] = 0xC3; next[0] = 0x90; next[1] = 0x90;
                        uc->uc_mcontext.gregs[REG_RIP] = rip - 1;
                        if (trap_count <= 20) {
                            fprintf(stderr, "[TRAP] #%d Assert at 0x%lx ESI=0x%llx (patched to ret)\n",
                                    trap_count, (unsigned long)(rip-1),
                                    (unsigned long long)uc->uc_mcontext.gregs[REG_RSI]);
                        }
                        return;
                    }
                }

                /* Regular int3 - RuntimeCallbackState+0x10 is the thread
                 * switcher, NOT the exception dispatcher. Don't forward.
                 * Just patch the int3 to nop and continue. */

                /* Fallback: patch to nop */
                *cc = 0x90;
                if (trap_count <= 20) {
                    fprintf(stderr, "[TRAP] #%d at 0x%lx (patched to nop, no dispatcher)\n",
                            trap_count, (unsigned long)(rip - 1));
                }
                return;
            }
        }

        if (trap_count <= 20) {
            fprintf(stderr, "[TRAP] #%d at RIP=0x%lx (outside NTUM)\n",
                    trap_count, (unsigned long)rip);
        }
        return;
    }

    /* ---- SIGFPE: Forward to NTUM ---- */
    if (sig == SIGFPE) {
        if (rip >= PE_IMAGE_START && rip < PE_IMAGE_END) {
            if (forward_exception_to_ntum(sig, uc))
                return;
        }
    }

    /* ---- Unhandled: Fatal crash ---- */
    /* Dump key .data values at crash time */
    {
        uint64_t params_ptr = *(volatile uint64_t*)0x180c00820ULL;
        fprintf(stderr, "[CRASH-DATA] [0x6092c0]=0x%lx [0x63f8c0]=0x%x [0x63f5c0]=0x%x\n"
                "  [0xc00820]=0x%lx [ptr+0]=0x%x [ptr+34]=0x%x\n",
                (unsigned long)*(volatile uint64_t*)0x1806092c0ULL,
                *(volatile uint32_t*)0x18063f8c0ULL,
                *(volatile uint32_t*)0x18063f5c0ULL,
                (unsigned long)params_ptr,
                params_ptr ? *(volatile uint32_t*)params_ptr : 0xDEAD,
                params_ptr ? *(volatile uint32_t*)(params_ptr + 0x34) : 0xDEAD);
    }
    uint64_t rsp_val = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
    char msg[1024];
    int len = snprintf(msg, sizeof(msg),
        "\n[CRASH] sig=%d addr=%p RIP=0x%llx faults=%d\n"
        "  RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n"
        "  RSI=0x%llx RDI=0x%llx RBP=0x%llx RSP=0x%llx\n"
        "  R8=0x%llx R9=0x%llx R14=0x%llx R15=0x%llx\n",
        sig, fault_addr,
        (unsigned long long)uc->uc_mcontext.gregs[REG_RIP],
        g_fault_count,
        (unsigned long long)uc->uc_mcontext.gregs[REG_RAX],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RBX],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RCX],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RDX],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RSI],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RDI],
        (unsigned long long)uc->uc_mcontext.gregs[REG_RBP],
        (unsigned long long)rsp_val,
        (unsigned long long)uc->uc_mcontext.gregs[REG_R8],
        (unsigned long long)uc->uc_mcontext.gregs[REG_R9],
        (unsigned long long)uc->uc_mcontext.gregs[REG_R14],
        (unsigned long long)uc->uc_mcontext.gregs[REG_R15]);
    /* Dump stack frames (return addresses) */
    if (rsp_val >= 0x180000000ULL && rsp_val < 0x181000000ULL) {
        len += snprintf(msg + len, sizeof(msg) - len,
            "  Stack: [+0]=0x%llx [+8]=0x%llx [+10]=0x%llx [+18]=0x%llx\n"
            "         [+20]=0x%llx [+28]=0x%llx [+30]=0x%llx [+38]=0x%llx\n"
            "         [+40]=0x%llx [+48]=0x%llx [+50]=0x%llx [+58]=0x%llx\n",
            (unsigned long long)*(uint64_t*)(rsp_val),
            (unsigned long long)*(uint64_t*)(rsp_val+0x8),
            (unsigned long long)*(uint64_t*)(rsp_val+0x10),
            (unsigned long long)*(uint64_t*)(rsp_val+0x18),
            (unsigned long long)*(uint64_t*)(rsp_val+0x20),
            (unsigned long long)*(uint64_t*)(rsp_val+0x28),
            (unsigned long long)*(uint64_t*)(rsp_val+0x30),
            (unsigned long long)*(uint64_t*)(rsp_val+0x38),
            (unsigned long long)*(uint64_t*)(rsp_val+0x40),
            (unsigned long long)*(uint64_t*)(rsp_val+0x48),
            (unsigned long long)*(uint64_t*)(rsp_val+0x50),
            (unsigned long long)*(uint64_t*)(rsp_val+0x58));
    }
    ssize_t wr = write(STDERR_FILENO, msg, len);
    (void)wr;
    _exit(128 + sig);
}

/* ================================================================
 * Signal Handler Installation
 * ================================================================ */

void ntum_signal_init(void) {
    /* Alternate signal stack (8MB) - like the real sqlservr */
    stack_t ss;
    ss.ss_sp = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ss.ss_size = 8 * 1024 * 1024;
    ss.ss_flags = 0;
    if (ss.ss_sp != MAP_FAILED)
        sigaltstack(&ss, NULL);

    /* Register handler for all relevant signals */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ntum_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);

    fprintf(stderr, "[SIGNAL] Handler installed with exception forwarding (altstack=%p)\n",
            ss.ss_sp);
}
