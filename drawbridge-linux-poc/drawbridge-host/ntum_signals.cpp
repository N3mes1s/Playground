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

extern "C" uint64_t DK_AbiDispatcher(uint64_t,uint64_t,uint64_t,void*,uint64_t,void*) __attribute__((ms_abi));

/* File-scope extern "C" decl so the in-body DK_AbiDispatcher reference
 * uses the C-linkage symbol from dk_pal.cpp (matches its ms_abi defn). */
extern "C" uint64_t DK_AbiDispatcher(uint64_t, uint64_t, uint64_t,
                                      void *, uint64_t, void *)
    __attribute__((ms_abi));

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

    /* Boot-stack guard: our dedicated boot stack lives at
     * 0x500000000..0x500200000 (2 MB). Any fault BELOW 0x500000000
     * but within the "stack grows down" region (0x4F0000000..0x500000000)
     * is a stack overflow. Do NOT demand-page — propagate the SIGSEGV
     * so we can see the exact PE RIP that ran past the stack bottom.
     * This surfaces the PE's descriptor-processing loop that otherwise
     * runs indefinitely on an unbounded demand-paged stack. */
    /* Stack lives at 0x500000000..0x501000000 (16 MB). Overflow region: */
    if (addr >= 0x4F0000000ULL && addr < 0x500000000ULL) {
        uintptr_t rip = uc ? uc->uc_mcontext.gregs[REG_RIP] : 0;
        uintptr_t rsp_pe = uc ? uc->uc_mcontext.gregs[REG_RSP] : 0;
        fprintf(stderr,
            "[STACK-OVERFLOW] fault at 0x%lx from RIP=0x%lx RSP=0x%lx\n",
            (unsigned long)addr, (unsigned long)rip, (unsigned long)rsp_pe);
        /* Dump the first 256 PE-range return addresses found on the
         * stack. If the loop is a tight recursion, we'll see the same
         * return address repeated many times. */
        /* At overflow, RSP is just below 0x500000000. Scan from the
         * fault address upward through the still-valid stack. */
        uintptr_t scan_lo = (rsp_pe < 0x500000000ULL) ? 0x500000000ULL : rsp_pe;
        if (scan_lo < 0x500200000ULL) {
            int count = 0;
            int same_count = 0;
            uintptr_t last_ret = 0;
            for (uintptr_t p = scan_lo; p < 0x500200000ULL && count < 256; p += 8) {
                uint64_t v = *(volatile uint64_t*)p;
                if (v >= 0x180200000ULL && v < 0x1803a0000ULL) {
                    if (v == last_ret) {
                        same_count++;
                    } else {
                        if (same_count > 0)
                            fprintf(stderr,
                                "[STACK-OVERFLOW]   ... repeated %d times\n",
                                same_count);
                        fprintf(stderr,
                            "[STACK-OVERFLOW]   scan+0x%04lx = 0x%lx\n",
                            (unsigned long)(p - scan_lo), (unsigned long)v);
                        last_ret = v;
                        same_count = 0;
                    }
                    count++;
                }
            }
            if (same_count > 0)
                fprintf(stderr,
                    "[STACK-OVERFLOW]   ... repeated %d times\n", same_count);
        }
        return 0;
    }

    /* Don't map NULL page or very low addresses - these are real crashes */
    if (addr < LIBOS_VM_START) {
        uintptr_t rip = uc ? uc->uc_mcontext.gregs[REG_RIP] : 0;
        fprintf(stderr, "[FAULT] NULL deref at 0x%lx from RIP=0x%lx - not mapped\n",
                (unsigned long)addr, (unsigned long)rip);
        return 0;
    }

    /* Don't map pages in the NT STATUS range (0xC0000000-0xC0010000).
     * If the PE faults there, it's treating an NTSTATUS error code as
     * a pointer — indicating a DK_* function returned an error value
     * the PE mis-interprets. Silently mapping these pages lets the PE
     * keep running with corrupted state and produces the DK #234
     * livelock (see /tmp/deadlock_rca.md). Let the fault propagate so
     * the real root cause surfaces. */
    if (addr >= 0xC0000000ULL && addr < 0xC0010000ULL) {
        uintptr_t rip = uc ? uc->uc_mcontext.gregs[REG_RIP] : 0;
        fprintf(stderr, "[FAULT] NTSTATUS-as-pointer at 0x%lx from RIP=0x%lx — "
                        "a DK_* returned this status code where the PE expected "
                        "a pointer; NOT auto-mapping\n",
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

        /* NTSTATUS-as-pointer recovery at known-bad RIPs.
         *
         * When FUN_00224b78 (RVA 0x224c29) faults with rsi holding an
         * NTSTATUS value, the upstream object-pool at [rbp+0x9d8] cached
         * a status code as if it were a pointer. Fix-up: allocate a fresh
         * zeroed object, point rsi at it, and zero the poisoned cache
         * slot so subsequent invocations go through the allocation path.
         * This is the same class of fix as the SRW waiter Flink janitor
         * above — tactical PE-internal state repair to let the hello-world
         * exe reach its entry point. */
        {
            uintptr_t rsi_val = (uintptr_t)uc->uc_mcontext.gregs[REG_RSI];
            uintptr_t rcx_val = (uintptr_t)uc->uc_mcontext.gregs[REG_RCX];
            uintptr_t rbp_val = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];

            /* Wave-16b: NTSTATUS-as-pointer fault in FUN_3877f0
             * (kernel-object refcount helper, called from ~100 sites).
             * Wave-16 silenced the raise machinery; side-effect is
             * that code which would have aborted now continues and
             * passes the NTSTATUS value as a pointer to this helper.
             * Crash site 0x180387809 is `cmp r14d, 0xc(rcx)` where
             * rcx is our NTSTATUS. Redirect RIP to the function's
             * zero-return epilogue at 0x387858..0x38786a which does:
             *   xor eax, eax
             *   mov rbx, [rsp+0x50]
             *   mov rbp, [rsp+0x58]
             *   add rsp, 0x30
             *   pop r14
             *   ret
             * i.e. returns 0 (success sentinel used by the function's
             * normal happy path at 0x387858). Preserves legitimate
             * callers of 0x3877f0 since we only redirect when rcx is
             * an NTSTATUS. */
            /* Wave-20: FUN_0027c304's crash at RVA 0x27c331 with rdx=NULL.
             * The function is called in loops over session handler
             * arrays [rbx+0x8a8+N*8]; some slots are NULL. Emulate
             * a clean return: unwind the 0x398-byte prologue and
             * jump to the caller's return address. Only fires when
             * rdx is 0 (the defining feature of this crash). */
            if (rip == 0x18027c331ULL &&
                uc->uc_mcontext.gregs[REG_RDX] == 0) {
                uintptr_t rsp_crash = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
                uintptr_t rsp_in = rsp_crash + 0x398;
                if (rsp_in >= 0x500000000ULL && rsp_in < 0x501000000ULL) {
                    uint64_t ret_addr = *(volatile uint64_t*)rsp_in;
                    uint64_t saved_rbx = *(volatile uint64_t*)(rsp_in + 0x18);
                    uint64_t saved_rdi = *(volatile uint64_t*)(rsp_in - 0x18);
                    uint64_t saved_rsi = *(volatile uint64_t*)(rsp_in - 0x10);
                    uint64_t saved_rbp = *(volatile uint64_t*)(rsp_in - 0x08);
                    if (ret_addr >= 0x180200000ULL && ret_addr < 0x1803a9aa8ULL) {
                        static int fix20 = 0;
                        if (fix20++ < 20)
                            fprintf(stderr,
                                "[FIXUP-20] #%d FUN_27c304(rdx=NULL) ret=0x%lx\n",
                                fix20, (unsigned long)ret_addr);
                        uc->uc_mcontext.gregs[REG_RIP] = (greg_t)ret_addr;
                        uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(rsp_in + 8);
                        uc->uc_mcontext.gregs[REG_RAX] = 0;
                        uc->uc_mcontext.gregs[REG_RBX] = (greg_t)saved_rbx;
                        uc->uc_mcontext.gregs[REG_RDI] = (greg_t)saved_rdi;
                        uc->uc_mcontext.gregs[REG_RSI] = (greg_t)saved_rsi;
                        uc->uc_mcontext.gregs[REG_RBP] = (greg_t)saved_rbp;
                        return;
                    }
                }
            }

            /* Wave-17: RIP landed in LibOS kernel-heap range (not code).
             * Someone loaded a vtable slot that was stomped with a
             * data-pointer (often pool+0x9d8 cache slot holding an
             * object pointer rather than a function pointer). Emulate
             * a "return 0" from the indirect call: pop the saved
             * return address from the stack into RIP, advance RSP by
             * 8, zero RAX. Log the caller for later analysis. */
            if (rip >= 0x300000000ULL && rip < 0x400000000ULL) {
                uintptr_t rsp_now = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
                /* Scan forward in the boot stack for the first PE-range
                 * return address. Sometimes [RSP] itself is 0 because
                 * the indirect call was via jmp (tail-call) or the
                 * caller allocated locals before calling. */
                uint64_t saved_ret = 0;
                uintptr_t ret_at = 0;
                /* Scan for a return address that (a) is PE-range, (b)
                 * is preceded by a 0xe8 call-rel32 opcode (i.e. is
                 * actually a post-CALL return slot not stale data),
                 * and (c) is OUTSIDE the broken FUN_3877f0 body
                 * (0x180387700..0x180387a00) so we unwind past the
                 * entire stuck function rather than back into its
                 * inner loop. */
                if (rsp_now >= 0x500000000ULL && rsp_now < 0x501000000ULL) {
                    for (uintptr_t p = rsp_now; p < rsp_now + 0x800 &&
                         p < 0x501000000ULL; p += 8) {
                        uint64_t v = *(volatile uint64_t*)p;
                        if (v < 0x180200000ULL || v >= 0x1803a9aa8ULL)
                            continue;
                        /* Skip anything inside FUN_3877f0 body -- that
                         * function is the one we're escaping. */
                        if (v >= 0x180387700ULL && v < 0x180387a00ULL)
                            continue;
                        /* Verify call-rel32 precedes: byte at (v-5)
                         * should be 0xe8. */
                        uint8_t pre = *(volatile uint8_t*)(v - 5);
                        if (pre != 0xe8)
                            continue;
                        saved_ret = v;
                        ret_at = p;
                        break;
                    }
                }
                static int fix17 = 0;
                if (fix17++ < 30) {
                    fprintf(stderr,
                        "[FIXUP-17] #%d indirect-call-into-heap RIP=0x%lx "
                        "RSP=0x%lx -> found retaddr 0x%lx at [rsp+0x%lx]\n",
                        fix17, (unsigned long)rip,
                        (unsigned long)rsp_now,
                        (unsigned long)saved_ret,
                        (unsigned long)(ret_at - rsp_now));
                }
                if (saved_ret) {
                    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)saved_ret;
                    uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(ret_at + 8);
                    uc->uc_mcontext.gregs[REG_RAX] = 0;
                    return;
                }
                /* Can't locate caller; fall through to crash. */
            }

            if (rip == 0x180387809ULL &&
                rcx_val >= 0xC0000000ULL && rcx_val < 0xC0010000ULL) {
                uc->uc_mcontext.gregs[REG_RIP] = 0x180387858;
                uc->uc_mcontext.gregs[REG_RAX] = 0;
                static int fix16b = 0;
                if (fix16b++ < 50) {
                    fprintf(stderr,
                        "[FIXUP-16b] #%d RIP=0x180387809 rcx=0x%lx "
                        "-> 0x180387858 (xor eax,eax; epilogue)\n",
                        fix16b, (unsigned long)rcx_val);
                }
                return;
            }

            if (rip == 0x180224c29ULL &&
                rsi_val >= 0xC0000000ULL && rsi_val < 0xC0010000ULL) {
                /* Async-signal-unsafe to calloc here; use static BSS.
                 * 0x400 keeps the PE crashing deterministically rather
                 * than entering a runaway pool alloc loop. The proper
                 * fix is Wave-6e — translate sub_24c38c fully so the
                 * fixup path is dead code. */
                static uint8_t scratch_buf[0x400] = {0};
                void *scratch = scratch_buf;
                /* Walk the stack frame to find the cache-owner object
                 * (FUN_00249848's rcx, saved as rbp at its call site).
                 *
                 * FUN_00224b78 frame layout at 0x224c29:
                 *   [RSP_crash + 0x68] = saved caller rbp = FUN_00249848's rbp
                 *   FUN_00249848 did `mov %rcx, %rbp` at 0x249874 so
                 *   its rbp is its rcx — the object whose [+0x9d8]
                 *   is the poisoned cache that FUN_002661bc read.
                 *
                 * Zero that slot so subsequent invocations take the
                 * non-cached alloc branch rather than re-reading
                 * NTSTATUS. This is the same mechanism as the PE's
                 * own cmpxchg at RVA 0x2661ff — we do it from the
                 * fault handler because we can't intercept the read. */
                uintptr_t rsp_val = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
                uintptr_t cache_owner = 0;
                if (rsp_val >= 0x180000000ULL && rsp_val < 0x200000000ULL) {
                    cache_owner = *(volatile uintptr_t*)(rsp_val + 0x68);
                    fprintf(stderr,
                        "[FIXUP-DIAG] rsp=%p [rsp+0x68]=0x%lx "
                        "(candidate cache_owner); rbp=0x%lx\n",
                        (void*)rsp_val, (unsigned long)cache_owner,
                        (unsigned long)rbp_val);
                    if (cache_owner >= 0x300000000ULL &&
                        cache_owner < 0x400000000ULL) {
                        uint64_t cv = *(volatile uint64_t*)
                            ((uint8_t*)cache_owner + 0x9d8);
                        fprintf(stderr,
                            "[FIXUP-DIAG] [cache_owner+0x9d8]=0x%lx\n",
                            (unsigned long)cv);
                    }
                }
                /* cache_owner may live in PE .data (when SCHED[+0x970]
                 * sentinel 0x180668db0 is the session pointer) or in
                 * LibOS heap range. Accept both. */
                int owner_ok = (cache_owner >= 0x180000000ULL &&
                                cache_owner < 0x181000000ULL) ||
                               (cache_owner >= 0x300000000ULL &&
                                cache_owner < 0x400000000ULL);
                if (owner_ok) {
                    volatile uint64_t *slot =
                        (volatile uint64_t*)((uint8_t*)cache_owner + 0x9d8);
                    uint64_t v = *slot;
                    if (v >= 0xC0000000ULL && v < 0xC0010000ULL) {
                        *slot = 0;
                        fprintf(stderr,
                            "[FIXUP] cleared NTSTATUS 0x%lx at "
                            "cache_owner=%p [+0x9d8]=%p\n",
                            (unsigned long)v, (void*)cache_owner,
                            (void*)slot);
                    }
                }
                /* Legacy rbp+0x9d8 cleanup kept as a belt-and-
                 * suspenders in case the frame walk mis-locates. */
                if (rbp_val >= 0x300000000ULL && rbp_val < 0x400000000ULL) {
                    volatile uint64_t *cache =
                        (volatile uint64_t*)((uint8_t*)rbp_val + 0x9d8);
                    if (*cache >= 0xC0000000ULL && *cache < 0xC0010000ULL) {
                        *cache = 0;
                        fprintf(stderr,
                            "[FIXUP] zeroed NTSTATUS cache at rbp+0x9d8 (%p)\n",
                            (void*)cache);
                    }
                }
                /* Wave-7 alternative: advance RIP directly to the
                 * function's early-exit at 0x224db5 instead of using
                 * a scratch pool. This matches the behaviour of the
                 * `jne 0x224db5` branch at 0x224c2d (the instruction
                 * right after our fixup entry): the ELF's own code
                 * takes that branch when the flag bit is set. We take
                 * it unconditionally so the function returns 0 (early
                 * exit via rbx=0 set at 0x224c27). The caller
                 * (FUN_00249848 at 0x249902) sees rax=0 and takes its
                 * error path: sets esi=0xC000009A and returns cleanly
                 * — no fastfail, no scratch-pool side effects. */
                uc->uc_mcontext.gregs[REG_RIP] = 0x180224db5;
                /* Keep rbx = 0 (already zeroed at 0x224c27 per the
                 * PE's own prologue; scrub to be safe since we
                 * entered via the fixup before that xor ran). */
                uc->uc_mcontext.gregs[REG_RBX] = 0;
                /* Prevent the `add %dx, 0x1e4(%rbp)` at 0x224dba from
                 * dereferencing an unknown pointer. Zero rbp so the
                 * `test %rbp, %rbp; je 0x224dc1` branch taken. */
                uc->uc_mcontext.gregs[REG_RBP] = 0;
                (void)scratch;  /* unused in this path */
                fprintf(stderr,
                    "[FIXUP] RIP=0x180224c29 rsi=NTSTATUS → jump to "
                    "early-exit 0x224db5 (rax=0)\n");
                return;
            }

            (void)rcx_val;
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

    /* ---- SIGILL: wave-18 ud2 traps at RtlRaiseStatus/RtlDispatchException entry.
     * Log the NTSTATUS (ECX) and caller return address, then emulate
     * a return. For RtlDispatchException, return al=1 (pretend
     * handled). For RtlRaiseStatus, return with rax unchanged. */
    if (sig == SIGILL) {
        uintptr_t rsp_now = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
        uint64_t caller = 0;
        if (rsp_now >= 0x500000000ULL && rsp_now < 0x501000000ULL)
            caller = *(volatile uint64_t*)rsp_now;

        if (rip == 0x180213dc0ULL) {
            /* Wave-24: panic_unsupported_abi entry. Args:
             *   rcx = function name (wchar_t*)
             *   edx = unsupported version number
             * Caller retaddr at [rsp]. */
            uintptr_t rsp_now = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
            uint64_t caller = 0;
            if (rsp_now >= 0x500000000ULL && rsp_now < 0x501000000ULL)
                caller = *(volatile uint64_t*)rsp_now;
            uint64_t rcx_v = (uint64_t)uc->uc_mcontext.gregs[REG_RCX];
            uint32_t edx_v = (uint32_t)uc->uc_mcontext.gregs[REG_RDX];
            uint64_t r8_v = (uint64_t)uc->uc_mcontext.gregs[REG_R8];
            uint64_t r9_v = (uint64_t)uc->uc_mcontext.gregs[REG_R9];
            fprintf(stderr,
                "[WAVE-24] panic_unsupported_abi: version=%u (0x%x) "
                "name_wstr=0x%lx r8=0x%lx r9=0x%lx caller=0x%lx\n",
                edx_v, edx_v, (unsigned long)rcx_v,
                (unsigned long)r8_v, (unsigned long)r9_v,
                (unsigned long)caller);
            /* Dump the name string (wide, null-terminated) */
            if (rcx_v >= 0x180000000ULL && rcx_v < 0x181000000ULL) {
                const uint16_t *ws = (const uint16_t*)rcx_v;
                char name[128] = {0};
                for (int i = 0; i < 127 && ws[i]; i++)
                    name[i] = (char)ws[i];
                fprintf(stderr, "[WAVE-24] name='%s'\n", name);
            }
            /* Dump caller context -- bytes before the return address */
            if (caller >= 0x180200000ULL && caller < 0x1803a9aa8ULL) {
                const uint8_t *c = (const uint8_t*)(caller - 32);
                fprintf(stderr, "[WAVE-24] caller-32..caller:");
                for (int i = 0; i < 32; i++) fprintf(stderr, " %02x", c[i]);
                fprintf(stderr, "\n");
            }
            /* Emulate "just return" to let boot limp along and see
             * if downstream reveals more crashes. */
            if (caller) {
                uc->uc_mcontext.gregs[REG_RIP] = (greg_t)caller;
                uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(rsp_now + 8);
                return;
            }
        }
        if (rip == 0x18037aa09ULL) {
            /* Wave-28: CONFLICTING_ADDRESSES site. rbx points to the
             * descriptor whose [+0x80] != 2. Log state and fall
             * through to crash so we can inspect. */
            uint64_t rbx_v = (uint64_t)uc->uc_mcontext.gregs[REG_RBX];
            uint64_t rdi_v = (uint64_t)uc->uc_mcontext.gregs[REG_RDI];
            uint64_t r12_v = (uint64_t)uc->uc_mcontext.gregs[REG_R12];
            fprintf(stderr,
                "[WAVE-28] FUN_37a8d0 CONFLICTING site: rbx=0x%lx rdi(lookup_key)=0x%lx r12=0x%lx\n",
                (unsigned long)rbx_v, (unsigned long)rdi_v, (unsigned long)r12_v);
            if (rbx_v && rbx_v > 0x100000000ULL) {
                const uint64_t *d = (const uint64_t*)rbx_v;
                fprintf(stderr,
                    "[WAVE-28] descriptor bytes [+0x00..+0xa0]:\n"
                    "  +00=%016lx +08=%016lx +10=%016lx +18=%016lx\n"
                    "  +20=%016lx +28=%016lx +30=%016lx +38=%016lx\n"
                    "  +40=%016lx +48=%016lx +50=%016lx +58=%016lx\n"
                    "  +60=%016lx +68=%016lx +70=%016lx +78=%016lx\n"
                    "  +80=%016lx +88=%016lx +90=%016lx +98=%016lx\n",
                    d[0], d[1], d[2], d[3],
                    d[4], d[5], d[6], d[7],
                    d[8], d[9], d[10], d[11],
                    d[12], d[13], d[14], d[15],
                    d[16], d[17], d[18], d[19]);
            }
            /* Also dump [rbp+0x48] and [rbp+0x50] -- the in/out args
             * passed to 0x3804b8. These are the shadow-home slots
             * for FUN_37a8d0's arg2/arg3 (the lookup key and an
             * outer r15 value). */
            uint64_t rbp_v = (uint64_t)uc->uc_mcontext.gregs[REG_RBP];
            fprintf(stderr,
                "[WAVE-28] rbp=0x%lx [rbp+0x48]=0x%lx [rbp+0x50]=0x%lx "
                "[rbp+0x58]=0x%lx\n",
                (unsigned long)rbp_v,
                (unsigned long)*(uint64_t*)(rbp_v + 0x48),
                (unsigned long)*(uint64_t*)(rbp_v + 0x50),
                (unsigned long)*(uint64_t*)(rbp_v + 0x58));

            /* VmModuleState dump too */
            uint64_t *vms = (uint64_t*)0x180c00878ULL;
            uint64_t vms_ptr = *vms;
            if (vms_ptr) {
                const uint64_t *v = (const uint64_t*)vms_ptr;
                fprintf(stderr,
                    "[WAVE-28] VmModuleState @0x%lx:\n"
                    "  +00=%016lx +08=%016lx +10=%016lx +18=%016lx\n"
                    "  +20=%016lx +28=%016lx +30=%016lx +38=%016lx\n"
                    "  +80=%016lx +88=%016lx +a0=%016lx +d8=%016lx\n",
                    (unsigned long)vms_ptr,
                    v[0], v[1], v[2], v[3],
                    v[4], v[5], v[6], v[7],
                    v[16], v[17], v[20], v[27]);
            }
            /* Fall through to the generic crash dump by not returning. */
            _exit(200);
        }
        if (rip == 0x1802962a8ULL) {
            /* RtlDispatchException entry */
            static int disp_count = 0;
            if (disp_count++ < 10)
                fprintf(stderr,
                    "[WAVE-18] #%d RtlDispatchException at ud2; "
                    "caller=0x%lx rcx=0x%lx rdx=0x%lx\n",
                    disp_count, (unsigned long)caller,
                    (unsigned long)uc->uc_mcontext.gregs[REG_RCX],
                    (unsigned long)uc->uc_mcontext.gregs[REG_RDX]);
            uc->uc_mcontext.gregs[REG_RAX] = 1;  /* handled */
            uc->uc_mcontext.gregs[REG_RIP] = (greg_t)caller;
            uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(rsp_now + 8);
            return;
        }
        if (rip == 0x1802a84f8ULL) {
            /* RtlRaiseStatus entry — ECX = NTSTATUS */
            static int raise_count = 0;
            if (raise_count++ < 20) {
                fprintf(stderr,
                    "[WAVE-18] #%d RtlRaiseStatus(NTSTATUS=0x%lx) "
                    "caller=0x%lx rdx=0x%lx r8=0x%lx\n",
                    raise_count,
                    (unsigned long)uc->uc_mcontext.gregs[REG_RCX] & 0xffffffffUL,
                    (unsigned long)caller,
                    (unsigned long)uc->uc_mcontext.gregs[REG_RDX],
                    (unsigned long)uc->uc_mcontext.gregs[REG_R8]);
            }
            uc->uc_mcontext.gregs[REG_RIP] = (greg_t)caller;
            uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(rsp_now + 8);
            return;
        }
        /* Fall through to default crash dump below. */
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
                        /* extern "C" declaration hoisted to file scope above */
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

    /* ---- SIGFPE: Don't forward to thread switcher.
     * RuntimeCallbackState+0x10 is the thread switcher, not exception handler.
     * Forwarding exceptions there crashes because it expects a thread context,
     * not an exception record. Just crash on SIGFPE for now. */

    /* ---- Unhandled: Fatal crash ---- */
    /* Dump key .data values at crash time */
    {
        uint64_t params_ptr = *(volatile uint64_t*)0x180c00820ULL;
        fprintf(stderr, "[CRASH-DATA] [0x63f5b4]=0x%x [0x63f790]=0x%lx\n"
                "[CRASH-DATA] [0x6092c0]=0x%lx [0x63f8c0]=0x%x [0x63f5c0]=0x%x\n"
                "  [0xc00820]=0x%lx [ptr+0]=0x%x [ptr+34]=0x%x\n",
                *(volatile uint32_t*)0x18063f5b4ULL,
                (unsigned long)*(volatile uint64_t*)0x18063f790ULL,
                (unsigned long)*(volatile uint64_t*)0x1806092c0ULL,
                *(volatile uint32_t*)0x18063f8c0ULL,
                *(volatile uint32_t*)0x18063f5c0ULL,
                (unsigned long)params_ptr,
                params_ptr ? *(volatile uint32_t*)params_ptr : 0xDEAD,
                params_ptr ? *(volatile uint32_t*)(params_ptr + 0x34) : 0xDEAD);
        /* Kernel object type registry [0x648c00] -> type_table (set by init at RVA 0x2bd0a6).
         * If equal to 0x1806472c0, the type registry init ran normally.
         * If != 0, it's either our stub sys_obj or something else. */
        uint64_t type_reg = *(volatile uint64_t*)0x180648c00ULL;
        uint64_t type_reg2 = *(volatile uint64_t*)0x1806475d0ULL;
        fprintf(stderr, "[CRASH-DATA] type_reg [0x648c00]=0x%lx (real=0x1806472c0)\n"
                        "             type_reg2 [0x6475d0]=0x%lx\n"
                        "             [0x645b78]=0x%lx (allocator)\n"
                        "             [0x6456e8]=0x%lx (pool)\n",
                (unsigned long)type_reg,
                (unsigned long)type_reg2,
                (unsigned long)*(volatile uint64_t*)0x180645b78ULL,
                (unsigned long)*(volatile uint64_t*)0x1806456e8ULL);
        if (type_reg) {
            fprintf(stderr, "             type_reg+0x18=0x%lx type_reg+0x10=0x%x\n",
                    (unsigned long)*(volatile uint64_t*)(type_reg + 0x18),
                    *(volatile uint16_t*)(type_reg + 0x10));
        }
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
    /* Dump exec_ctx contents at RSI (PE at 0x319e94 does `mov %rdx,%rsi` so RSI = param1) */
    uint64_t rsi_val = (uint64_t)uc->uc_mcontext.gregs[REG_RSI];
    if (rsi_val >= 0x180000000ULL && rsi_val < 0x181000000ULL) {
        fprintf(stderr,
            "[CRASH-EXECCTX] @0x%lx:\n"
            "  [+0]=%016lx [+8]=%016lx [+10]=%016lx [+18]=%016lx\n"
            "  [+20]=%016lx [+28]=%016lx [+30]=%016lx [+38]=%016lx\n",
            (unsigned long)rsi_val,
            (unsigned long)*(uint64_t*)rsi_val,
            (unsigned long)*(uint64_t*)(rsi_val+0x08),
            (unsigned long)*(uint64_t*)(rsi_val+0x10),
            (unsigned long)*(uint64_t*)(rsi_val+0x18),
            (unsigned long)*(uint64_t*)(rsi_val+0x20),
            (unsigned long)*(uint64_t*)(rsi_val+0x28),
            (unsigned long)*(uint64_t*)(rsi_val+0x30),
            (unsigned long)*(uint64_t*)(rsi_val+0x38));
    }
    /* Look above RSP for return addresses (call stack reconstruction).
     * The crashing function has prologue `sub rsp,0x2f8; push rdi; ...`.
     * Stack frame search for any PE text-range return addresses. */
    fprintf(stderr, "[CRASH-STACK] PE-range returns:\n");
    for (uint64_t off = 0; off < 0x400; off += 8) {
        uint64_t v = *(uint64_t*)(rsp_val + off);
        if (v >= 0x180200000ULL && v < 0x1803a9aa8ULL) {
            fprintf(stderr, "  RSP+0x%03lx = 0x%lx\n",
                (unsigned long)off, (unsigned long)v);
        }
    }
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
    /* Wave-14: SIGILL handler — Wave-12 patched PE RVA 0x2a855a
     * (RtlRaiseStatus retry) from `call rel32` to `ud2 + 3 nops`.
     * When that fires we want the full crash dump (RIP, ECX = first
     * raised NTSTATUS, stack scan) rather than an uncaught SIGILL. */
    sigaction(SIGILL, &sa, NULL);

    fprintf(stderr, "[SIGNAL] Handler installed with exception forwarding (altstack=%p)\n",
            ss.ss_sp);
}
