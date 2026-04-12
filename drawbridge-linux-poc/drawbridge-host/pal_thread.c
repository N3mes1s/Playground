/*
 * pal_thread.c — Translated thread creation & entry thunk.
 *
 * Source functions (see analysis/sqlservr_FULL.c):
 *   FUN_001fa9c0 @ line 61607                   → pal_alloc_teb
 *   FUN_00252c90 @ lines 123381-123462          → pal_set_thread_gs_base
 *   FUN_00252e60 @ line 123466                  → pal_thread_create      (TODO M3)
 *   FUN_00253350 @ line 123665                  → pal_thread_entry_thunk (TODO M3)
 *   FUN_002890a0 @ line 156863                  → pal_thread_subsystem_init (TODO M3)
 *
 * Translated in this pass: pal_alloc_teb, pal_set_thread_gs_base.
 * The remaining three are left as empty TODO stubs — they pull in the
 * full KTHREAD allocator chain and belong to a later milestone.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

#include "pal_internal.h"
#include "drawbridge_types.h"

/* ------------------------------------------------------------------
 * Cross-subsystem helpers — real implementations live in pal_stubs.c
 * (weak) and will be superseded by later translations.
 *
 * ELF mapping:
 *   FUN_0028e070 → pal_result_init       (ctor on the local pal_result)
 *   FUN_0028e0d0 → pal_result_set        (set status/file/line)
 *   FUN_0028e130 → pal_result_fini       (dtor)
 *   FUN_0028e530 → pal_result_succeeded  (status >= 0)
 *   FUN_0028e560 → pal_result_combine    (lhs |= rhs on error)
 *   FUN_00353860 → pal_abi_errno_location (&errno)
 *   FUN_001c1100 → pal_abi_assert_fail
 * ------------------------------------------------------------------ */
extern void   pal_result_init(void *result);
extern void   pal_result_fini(void *result);
extern char   pal_result_succeeded(void *result);
extern void   pal_result_combine(void *dst, void *src);
extern void   pal_result_set(void *result, uint32_t status,
                             const char *file, int line);
extern int   *pal_abi_errno_location(void);
extern void   pal_abi_assert_fail(const char *msg, int err) __attribute__((noreturn));

/* Opaque pal_result storage — matches struct pal_result_layout in
 * pal_stubs.c (char*, int32, uint16, int32). 32 bytes is generous. */
typedef struct { uint8_t _raw[32]; } pal_result_t;


/* ==================================================================
 * pal_alloc_teb — translate FUN_001fa9c0 @ sqlservr_FULL.c:61607
 *
 * Original (Ghidra):
 *   void FUN_001fa9c0(long param_1, size_t param_2) {
 *       if (*(long*)(param_1+0x88) == 0) {
 *           pvVar1 = malloc(param_2);       // ELF variant; PE uses operator_new
 *           *(void**)(param_1+0x88) = pvVar1;
 *           if (pvVar1 != NULL) {
 *               FUN_00353430(pvVar1, 0xb0, param_2);  // zero the TEB header
 *               return;
 *           }
 *       }
 *       FUN_00354060();                     // __stack_chk_fail / abort
 *   }
 *
 * Per the task spec this is refactored into a value-returning allocator:
 *   allocate 0x10000 bytes, zero the first 0xb0 bytes, return the TEB.
 * The caller-side "write into KTHREAD+0x88" plumbing stays with the
 * not-yet-translated pal_thread_entry_thunk (FUN_00253350 line 123708).
 * ================================================================== */
ntum_teb_t *pal_alloc_teb(void)
{
    void *teb = malloc(0x10000);
    if (teb == NULL) {
        pal_abi_assert_fail("pal_alloc_teb: malloc failed", errno);
    }
    /* Zero the Nt_Tib / self-pointer / thread-state header band.
     * The bulk of the 64 KiB TEB is left untouched — matches the
     * ELF's narrow memset of only the first 0xb0 bytes. */
    memset(teb, 0, 0xb0);
    return (ntum_teb_t *)teb;
}


/* ==================================================================
 * pal_set_thread_gs_base — translate FUN_00252c90 @ line 123383
 *
 * Wraps the Linux `arch_prctl(ARCH_SET_GS, fs_base)` syscall with the
 * NTUM pal_result error pattern. The ELF reads a RegisterValues
 * descriptor (param_1) with layout:
 *   param_1[0] = RegisterValues->Arch.x64.FsBase  (must be 0 pre-set)
 *   param_1[1] = desired GS base (new TEB pointer)
 *
 * Control flow, preserved exactly:
 *   1. Init local pal_result.
 *   2. If param_1 == NULL  → set STATUS_INVALID_PARAMETER (0xc000000d),
 *      skip to cleanup.
 *   3. If local pal_result already failed (shouldn't) → cleanup.
 *   4. Assert (RegisterValues != nullptr).
 *   5. Assert (RegisterValues->Arch.x64.FsBase == 0).
 *   6. If param_1[1] != 0:
 *        a. Call arch_prctl(ARCH_SET_GS, param_1[1]).
 *        b. On failure → set STATUS_UNSUCCESSFUL (0xc0000001).
 *        c. On success: record new TEB into KTHREAD (fs:[-0x10])+0x9e0
 *                       and invoke a trace call (FUN_00353f10/0xf).
 *        d. Also notify page-table/GS observer (FUN_0020d9e0).
 *   7. Cleanup pal_result, return status.
 *
 * Unknown helpers retained as extern-or-stubbed TODO:
 *   FUN_00289740  → arch_prctl syscall wrapper (returns bool-ish)
 *   FUN_002b97a0  → pal trace-message formatter (takes 4+ args)
 *   FUN_00353f10  → pal trace-emit (channel 0xf)
 *   FUN_0020d9e0  → GS/TEB observer notify (param_1[1], kthread, 0x10000)
 * ================================================================== */

/* Local forward-declared helpers — no invention, just names bound to
 * ELF RVAs that this function relies on. All return success/no-op in
 * this translation pass until their own bodies are brought over. */
static int  pal_arch_prctl_set_gs(unsigned long gs_base);   /* FUN_00289740 */
static void pal_trace_emit_unk(unsigned ch, const void *buf,
                               long a, long b, long c);     /* FUN_00353f10 */
static void pal_trace_fmt_unk(void *out_flag, const void *fmt1,
                              const void *fmt2, uint64_t arg); /* FUN_002b97a0 */
static void pal_teb_gs_observe(long new_gs, long kthread,
                               size_t len);                 /* FUN_0020d9e0 */

/* RegisterValues layout (partial, from FUN_00252c90 use):
 *   +0x00  uint64 FsBase     (must be 0)
 *   +0x08  uint64 GsBase     (target — becomes new TEB)
 *   +0x48  uint64 unk_trace  (passed to trace formatter)
 * TODO: extend drawbridge_types.h with `ntum_register_values_t`. */

int pal_set_thread_gs_base(void *teb)
{
    long        *param_1 = (long *)teb;
    pal_result_t local_res;
    pal_result_t tmp_res;
    char         ok;
    int          status_out = 0;    /* local_30 in Ghidra */

    pal_result_init(&local_res);

    if (param_1 == NULL) {
        /* STATUS_INVALID_PARAMETER at palcalls.cpp:0x1243 (4675) */
        pal_result_set(&tmp_res, 0xc000000d, "palcalls.cpp", 0x1243);
        pal_result_combine(&local_res, &tmp_res);
        pal_result_fini(&tmp_res);
    }

    ok = pal_result_succeeded(&local_res);
    if (!ok) {
        /* LAB_00252ddc — early cleanup */
        pal_result_fini(&local_res);
        return status_out;
    }

    /* Debug asserts ported from ELF — only fire with NULL / non-zero FsBase. */
    if (param_1 == NULL) {
        pal_abi_assert_fail("RegisterValues != nullptr",
                            *pal_abi_errno_location());
    }
    if (param_1[0] != 0) {
        pal_abi_assert_fail("RegisterValues->Arch.x64.FsBase == 0",
                            *pal_abi_errno_location());
    }

    /* Only issue arch_prctl if a non-zero GS base was requested. */
    if (param_1[1] != 0) {
        ok = (char)pal_arch_prctl_set_gs((unsigned long)param_1[1]);
        if (!ok) {
            /* STATUS_UNSUCCESSFUL at palcalls.cpp:0x126d (4717) */
            pal_result_set(&tmp_res, 0xc0000001, "palcalls.cpp", 0x126d);
            pal_result_combine(&local_res, &tmp_res);
            pal_result_fini(&tmp_res);
        } else {
            /* fs:[-0x10] is the current KTHREAD pointer stashed by
             * the thread-local area (see TEB_THREAD_STATE layout). */
            long kthread = 0;
#if defined(__x86_64__)
            __asm__ volatile("mov %%fs:-0x10, %0" : "=r"(kthread));
#endif
            if (kthread != 0) {
                long new_gs = param_1[1];
                /* KTHREAD + 0x9e0 holds the live GS/TEB base for
                 * scheduler introspection (unk_ field — TODO: add
                 * `void *gs_base_live` to ntum_kthread_t). */
                *(long *)((uint8_t *)kthread + 0x9e0) = new_gs;

                /* Emit the trace message describing the switch. */
                uint8_t flag_byte = 0;
                uint8_t inline_buf[16] = {0};
                void   *trace_arg_src = NULL;
                pal_trace_fmt_unk(&flag_byte,
                                  (const void *)0 /* DAT_0013532e */,
                                  (const void *)0 /* DAT_00146165 */,
                                  (uint64_t)*(uint64_t *)((uint8_t *)new_gs + 0x48));
                trace_arg_src = (flag_byte & 1) ? NULL
                                                : (void *)inline_buf;
                pal_trace_emit_unk(0xf, trace_arg_src, 0, 0, 0);
                /* NOTE: operator_delete of the heap-formatted buffer
                 * is elided — pal_trace_fmt_unk is a stub. */
            }

            /* Notify the observer (e.g. valgrind client-request hook
             * in the original). Always runs on the success path. */
            pal_teb_gs_observe(param_1[1], kthread, 0x10000);
        }
    }

    /* LAB_00252ddc — common cleanup / return */
    pal_result_fini(&local_res);
    return status_out;
}


/* ==================================================================
 * Local static helpers — minimal stand-ins for untranslated ELF bodies
 * ================================================================== */

/* FUN_00289740 — arch_prctl(ARCH_SET_GS, gs_base).
 * ELF wraps the raw syscall and returns non-zero on success. */
static int pal_arch_prctl_set_gs(unsigned long gs_base)
{
    long rc = syscall(SYS_arch_prctl, ARCH_SET_GS, gs_base);
    return rc == 0;
}

/* FUN_002b97a0 — pal string-format helper.
 * TODO: translate in a later pass. */
static void pal_trace_fmt_unk(void *out_flag, const void *fmt1,
                              const void *fmt2, uint64_t arg)
{
    (void)fmt1; (void)fmt2; (void)arg;
    if (out_flag) *(uint8_t *)out_flag = 0;
}

/* FUN_00353f10 — pal trace emitter (channel 0xf = thread events).
 * TODO: translate in a later pass. */
static void pal_trace_emit_unk(unsigned ch, const void *buf,
                               long a, long b, long c)
{
    (void)ch; (void)buf; (void)a; (void)b; (void)c;
}

/* FUN_0020d9e0 — GS/TEB observer notification.
 * TODO: translate in a later pass. */
static void pal_teb_gs_observe(long new_gs, long kthread, size_t len)
{
    (void)new_gs; (void)kthread; (void)len;
}


/* ==================================================================
 * TODO(M3): pal_thread_create        — FUN_00252e60 @ line 123466
 * TODO(M3): pal_thread_entry_thunk   — FUN_00253350 @ line 123665
 * TODO(M3): pal_thread_subsystem_init— FUN_002890a0 @ line 156863
 * ================================================================== */

ntum_kthread_t *pal_thread_create(void *entry, void *arg)
{
    (void)entry; (void)arg;
    /* TODO: translate FUN_00252e60 (KTHREAD allocator + clone). */
    return NULL;
}

void pal_thread_entry_thunk(ntum_kthread_t *kt)
{
    (void)kt;
    /* TODO: translate FUN_00253350 (stack/TEB setup, invokes
     * pal_alloc_teb + pal_set_thread_gs_base). */
}

void pal_thread_subsystem_init(void)
{
    /* TODO: translate FUN_002890a0 (thread subsystem tables init). */
}
