/*
 * pal_except.cpp — Component C9: Exception Dispatch (skeleton)
 *
 * Real translation tasks (deferred to next milestone):
 *
 *   FUN_002897e0 @ 0x2897e0 — KiFillExceptionRecord: build compressed
 *                              dk_exception_record_t (0x280 bytes) from
 *                              a guest-CPU context.
 *   FUN_002899d0 @ 0x2899d0 — KiDispatchException: classify the Linux
 *                              signal, allocate a dk_exception_record_t,
 *                              fill it, and rewrite ucontext RIP/RCX/RDX
 *                              to hand control to KiUserExceptionDispatcher
 *                              (stored at RuntimeCallbackState+0x10).
 *   FUN_00252b10 @ 0x252b10 — alloc_exception_record: calloc(1, 0x280)
 *                              and copy the caller's exception_info_t.
 *   FUN_00253f80 @ 0x253f80 — DK_ExceptionRecordFree (THIS FILE):
 *                              validates the pointer lies in the LibOS
 *                              range (FUN_002801d0), decrements the TEB
 *                              exception counter, and free()s the record.
 *                              The ELF's compiled body is simply
 *                              `operator delete(record)`; we implement
 *                              it as a plain free() — the allocator
 *                              path in the NTUM is a vanilla new/delete
 *                              pair so free() is wire-compatible with
 *                              the ELF's libstdc++ operator delete.
 *
 * For this milestone the file contains only:
 *   - A strong DK_ExceptionRecordFree that overrides the weak no-op in
 *     dk_pal.cpp.
 *   - A stub pal_exception_forward that logs and returns 0 (meaning
 *     "dispatcher not yet installed; fall back").
 *
 * Signal-handler plumbing (ntum_signals.cpp) already exists; the real
 * record builder and RIP rewriter will land here next.
 */

#include "pal_except.h"

#include <cstdio>
#include <cstdlib>
#include <cstdint>

/* -----------------------------------------------------------------
 * DK_ExceptionRecordFree — ELF RVA 0x253f80 / FUN_00253f80.
 *
 * Decompiled body (abridged) in analysis/sqlservr_FULL.c:124308:
 *     if (record && FUN_002801d0(record))   // LibOS range check
 *         operator delete(record);
 *     return 0;
 *
 * The TEB-counter decrement and address-validator are skeletal for
 * now; the NTUM only cares that the pointer it handed us comes back
 * cleanly, and that the return value is 0 (DK_STATUS_SUCCESS).
 *
 * Declared ms_abi because the NTUM calls this through the DK export
 * table (id 0xa001000) which always uses the Win64 ABI.
 * ----------------------------------------------------------------- */
extern "C" uint64_t DK_ExceptionRecordFree(void *record) __attribute__((ms_abi));

extern "C" uint64_t DK_ExceptionRecordFree(void *record)
{
    /* Matches operator delete() in the ELF; NULL is a legal no-op. */
    if (record) {
        free(record);
    }
    return 0; /* DK_STATUS_SUCCESS */
}

/* -----------------------------------------------------------------
 * pal_exception_forward — entry from ntum_signals.cpp's signal handler.
 *
 * Future body (ELF FUN_002899d0):
 *   1.  Re-entry guard via per-thread bit (FUN_00254f80).
 *   2.  Load RuntimeCallbackState+0x10 (KiUserExceptionDispatcher);
 *       if NULL, return 0 and let the caller take its fallback path.
 *   3.  Allocate a dk_exception_record_t (calloc 0x280).
 *   4.  Fill the compressed-CONTEXT fields from the Linux ucontext_t
 *       gregs/fpregs (mirror of FUN_002897e0).
 *   5.  Build an embedded NT_EXCEPTION_RECORD at rec+0x28..0xa0,
 *       classifying ExceptionCode from signo/si_code
 *       (FUN_0028a410 for SIGFPE).
 *   6.  Rewrite ucontext REG_RIP = KiUserExceptionDispatcher,
 *       REG_RCX = &compressed_ctx, REG_RDX = &exception_record.
 *   7.  Return 1; the handler sigreturn()s into the NTUM dispatcher.
 *
 * For now we just note the signal and return 0 so callers fall
 * through to their existing signal-specific paths.
 * ----------------------------------------------------------------- */
extern "C" int pal_exception_forward(int signo,
                                     void *siginfo_ptr,
                                     void *ucontext_ptr)
{
    (void)siginfo_ptr;
    (void)ucontext_ptr;

    fprintf(stderr,
            "[pal_except] pal_exception_forward(signo=%d) — skeleton, "
            "real dispatcher not yet wired (C9 milestone).\n",
            signo);
    return 0;
}

/* -----------------------------------------------------------------
 * pal_exception_set_pe_data / pal_exception_demand_page — declared
 * in pal_except.h but owned by ntum_signals.cpp for this milestone.
 * They will migrate here once the real dispatcher lands.
 * ----------------------------------------------------------------- */
