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
#include <pthread.h>
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
 * pal_thread_create — FUN_00252e60 @ analysis/sqlservr_FULL.c:123466
 *
 * Creates a KTHREAD (0xaa0 bytes), links it into the global thread
 * list guarded by g_thread_list_mutex, increments the global thread
 * ID counter, stores the entry function / parameter / event object /
 * stack hint in the KTHREAD, then pthread_create()s a host thread
 * whose start routine is pal_thread_entry_thunk (FUN_00253350).
 *
 * Signature mapping:
 *   param_1 = entry  (void* — guest entry routine)
 *   param_2 = arg    (void* — entry argument, stored at KTHREAD[+0xC])
 *   param_3 = event_obj (void*, nullable — stored at [+0xE])
 *   param_4 = sched_config (uint32[4], nullable — stored at [+0xF..0x84])
 *   param_5 = is_system_thread (char — gates where arg goes)
 *   param_6 = out_event_slot (void**, nullable — receives event obj)
 *
 * We collapse to (entry, arg) for our pal_internal.h signature;
 * the other parameters become internal defaults. Full fidelity
 * can be restored in M6 by widening the signature.
 *
 * Globals (ELF DAT_* → meaningful names):
 *   DAT_003b2198 → g_thread_list_mutex
 *   DAT_003b21c0 → g_thread_id_counter
 *   DAT_003b21c8 → g_thread_list_head
 * ================================================================== */

/* ---- extern stubs for helpers still in other TUs. ---- */
/* FUN_00280200: parameter validation (returns 0 on error). */
extern char pal_thread_validate_param(void);
extern char pal_thread_validate_param_ex(void *p);
/* FUN_00354030: aligned nothrow operator_new wrapper. */
extern void *pal_nothrow_alloc(size_t size, const void *nothrow_tag);
extern const void *const pal_std_nothrow_tag;
/* FUN_001fa870: KTHREAD in-place constructor. */
extern void pal_kthread_construct(void *kt);
/* FUN_003541b0 / FUN_003541c0: pthread_mutex lock/unlock. */
extern int pal_mutex_lock(void *m);
extern int pal_mutex_unlock(void *m);
/* FUN_0025a520 / FUN_0025a540: guest-OS dispatch thunks (NT vs others). */
extern void pal_guest_dispatch_nt(void);
extern void pal_guest_dispatch_linux(void);
/* FUN_001fa5f0: allocates an "thread state" object of kind `kind`. */
extern long pal_thread_state_alloc(int kind);
/* FUN_002535c0: KTHREAD destructor + list unlink on failure paths. */
extern void pal_thread_destroy(void *kt);
/* FUN_002b6070/FUN_002b60a0/FUN_002b60d0/FUN_002b6100/FUN_002b6190:
 * thread state ref-count / attribute helpers. */
extern void    *pal_ts_acquire(long ts);
extern void     pal_ts_arm(long ts);
extern void     pal_ts_set_attached(long ts);
extern void     pal_ts_release(long ts);
extern void     pal_ts_release_alt(long ts);
/* FUN_001bbc30: Get PAL instance attribute (module handle). */
extern uint64_t pal_instance_get_attr(void *image_handle);
/* FUN_003553c0 / FUN_003553d0 / FUN_003553e0: pthread attr init / set / destroy. */
extern int pal_pthread_attr_init(void *attr);
extern int pal_pthread_attr_set_detach(void *attr, uint64_t detach_flag);
extern int pal_pthread_attr_destroy(void *attr);
/* FUN_00353f90: pthread_create(host_thread_out, attr, start, arg) wrapper. */
extern int pal_pthread_create(void *tid_out, void *attr,
                              void *(*start)(void *), void *arg);
/* FUN_0028e0f0: pal_result_set_from_errno(result, file, line, errno). */
extern void pal_result_set_from_errno(void *result, const char *file,
                                      uint16_t line, int err);
/* FUN_0028e130 / FUN_0028e1f0 / FUN_0028e200: pal_result helpers also
 * declared via pal_stubs.c. */
extern char pal_result_is_error_full(void *result);

/* DAT_0036f598: outer PAL instance context; reuse from pal_boot.c. */
extern uint8_t g_pal_instance[];
#define PAL_INSTANCE_OS_KIND_OFFSET   0x0C    /* int: 1=NT, 2=Linux */
#define PAL_INSTANCE_IMAGE_HANDLE_OFF 0x138

/* Offsets within the KTHREAD expressed in uint64 words (ELF writes
 * via puVar8[N]; N is the dword index). */
#define KT_WORD_THREAD_ID_WORD    0x12   /* int32 at byte 0x90 */
#define KT_WORD_LIST_NEXT         0x13   /* 0x98 */
#define KT_WORD_LIST_PREV         0x14   /* 0xa0 */
#define KT_WORD_ENTRY_FUNC        0xB    /* 0x58 */
#define KT_WORD_ENTRY_ARG         0xC    /* 0x60 */
#define KT_WORD_ARG2              0xD    /* 0x68 */
#define KT_WORD_EVENT_OBJ         0xE    /* 0x70 */
#define KT_WORD_SCHED_CFG_DW      0xF    /* 0x78 */
#define KT_WORD_DISPATCH_THUNK    0x15   /* 0xa8 */
#define KT_WORD_PTHREAD_HANDLE    0x4    /* 0x20 */
#define KT_WORD_THREAD_STATE_PRIM 0x0    /* 0x00 — set to ts->primary */

/* Opaque static globals (addresses known; layouts irrelevant here). */
static void *g_thread_list_mutex;          /* DAT_003b2198 — opaque mutex */
static uint32_t g_thread_id_counter;       /* DAT_003b21c0 */
static uint64_t *g_thread_list_head;       /* DAT_003b21c8 */

ntum_kthread_t *pal_thread_create(void *entry, void *arg)
{
    /* 1. Parameter validation — FUN_00280200 pair. */
    if (!pal_thread_validate_param()) {
        return NULL;  /* STATUS_INVALID_PARAMETER (0xc000000d) */
    }

    /* 2. Allocate a zero-initialized 0xaa0 KTHREAD. */
    uint64_t *kt_words = (uint64_t *)pal_nothrow_alloc(0xaa0, pal_std_nothrow_tag);
    if (kt_words == NULL) {
        pal_abi_assert_fail("t != nullptr", *pal_abi_errno_location());
    }
    pal_kthread_construct(kt_words);

    /* 3. Link into global thread list under the mutex. */
    if (pal_mutex_lock(&g_thread_list_mutex) != 0) {
        pal_abi_assert_fail("mutex_lock(g_thread_list_mutex)",
                            *pal_abi_errno_location());
    }
    uint32_t new_id = ++g_thread_id_counter;
    *(uint32_t *)&kt_words[KT_WORD_THREAD_ID_WORD] = new_id;
    uint64_t *prev_head = g_thread_list_head;
    kt_words[KT_WORD_LIST_NEXT] = (uint64_t)prev_head;
    kt_words[KT_WORD_LIST_PREV] = 0;
    if (prev_head != NULL) {
        if (prev_head[KT_WORD_LIST_PREV] != 0) {
            pal_abi_assert_fail("all_threads->tprev == nullptr",
                                *pal_abi_errno_location());
        }
        prev_head[KT_WORD_LIST_PREV] = (uint64_t)kt_words;
    }
    g_thread_list_head = kt_words;
    if (pal_mutex_unlock(&g_thread_list_mutex) != 0) {
        pal_abi_assert_fail("mutex_unlock(g_thread_list_mutex)",
                            *pal_abi_errno_location());
    }

    /* 4. Stash the entry/arg/event parameters.
     * is_system_thread (param_5) is 0 in our simplified form →
     * KT_WORD_ARG2 also gets arg (matches ELF fallthrough). */
    kt_words[KT_WORD_ENTRY_FUNC] = (uint64_t)entry;
    kt_words[KT_WORD_ENTRY_ARG]  = (uint64_t)arg;
    kt_words[KT_WORD_ARG2]       = (uint64_t)arg;
    kt_words[KT_WORD_EVENT_OBJ]  = 0;

    /* 5. Select dispatch thunk per PAL instance OS kind. */
    int os_kind = *(int *)(g_pal_instance + PAL_INSTANCE_OS_KIND_OFFSET);
    void (*dispatch_thunk)(void);
    if (os_kind == 1) {
        dispatch_thunk = pal_guest_dispatch_nt;
    } else if (os_kind == 2) {
        dispatch_thunk = pal_guest_dispatch_linux;
    } else {
        pal_abi_assert_fail("Unsupported PAL OS", *pal_abi_errno_location());
    }
    kt_words[KT_WORD_DISPATCH_THUNK] = (uint64_t)(void *)dispatch_thunk;

    /* 6. Allocate a thread-state tracking object and link it. */
    long ts = pal_thread_state_alloc(4);
    if (ts == 0) {
        pal_thread_destroy(kt_words);
        return NULL;  /* STATUS_NO_MEMORY (0xc0000017) */
    }
    pal_ts_acquire((void *)ts);
    pal_ts_arm((void *)ts);
    pal_ts_release_alt(ts);
    *(uint64_t **)(ts + 0x58) = kt_words;
    kt_words[KT_WORD_THREAD_STATE_PRIM] = (uint64_t)pal_ts_acquire((void *)ts);

    /* 7. Create the host pthread with pal_thread_entry_thunk as the
     *    start routine. The KTHREAD pointer is passed as arg; the
     *    entry thunk sets up TEB/GS then invokes the dispatch_thunk. */
    uint64_t image_attr = pal_instance_get_attr(
        *(void **)(g_pal_instance + PAL_INSTANCE_IMAGE_HANDLE_OFF));
    (void)image_attr; /* TODO: feed into pthread_attr stack size. */

    char pthread_attr[56];  /* local_70 in ELF */
    if (pal_pthread_attr_init(pthread_attr) != 0) {
        pal_abi_assert_fail("pthread_attr_init",
                            *pal_abi_errno_location());
    }
    if (pal_pthread_attr_set_detach(pthread_attr, image_attr) != 0) {
        pal_abi_assert_fail("pthread_attr_set",
                            *pal_abi_errno_location());
    }
    int rc = pal_pthread_create(&kt_words[KT_WORD_PTHREAD_HANDLE],
                                pthread_attr,
                                (void *(*)(void *))pal_thread_entry_thunk,
                                kt_words);
    if (rc != 0) {
        /* pthread_create failed — unwind the thread state and return. */
        pal_thread_destroy(kt_words);
        *(uint64_t *)(ts + 0x58) = 0;
        pal_ts_release((void *)ts);
        pal_ts_release_alt(ts);
        pal_ts_release_alt(ts);
        pal_pthread_attr_destroy(pthread_attr);
        return NULL;  /* STATUS_UNSUCCESSFUL (0xc0000001) */
    }
    if (pal_pthread_attr_destroy(pthread_attr) != 0) {
        pal_abi_assert_fail("pthread_attr_destroy",
                            *pal_abi_errno_location());
    }
    pal_ts_release_alt(ts);
    return (ntum_kthread_t *)kt_words;
}

/* ==================================================================
 * pal_thread_entry_thunk — FUN_00253350 @ line 123665 (TODO M3c)
 *
 * The host side of a freshly-created thread. Responsibilities per
 * REAL_BOOT_SEQUENCE.c Phase 5:
 *   1. Get thread-local memory
 *   2. Allocate and init stack
 *   3. thread[+0x18] = stack base; thread[+0x10] = stack top
 *   4. Call pal_alloc_teb(); store at thread[+0x88]
 *   5. Call pal_set_thread_gs_base() (arch_prctl SET_GS)
 *   6. Jump to thread entry (dispatch_thunk stored at KT_WORD_DISPATCH_THUNK)
 * ================================================================== */
void pal_thread_entry_thunk(ntum_kthread_t *kt)
{
    (void)kt;
    /* TODO(M3c): translate FUN_00253350 (stack alloc + TEB + GS set). */
}

/* ==================================================================
 * pal_thread_subsystem_init — FUN_002890a0 @ line 156863 (TODO M3c)
 * ================================================================== */
void pal_thread_subsystem_init(void)
{
    /* TODO(M3c): translate FUN_002890a0. Registers scheduler config
     * (0xffff00000400, 0, 0, 0xe10) via FUN_00355d60 and the AIO
     * callback FUN_00252bf0 via FUN_00279f90. */
}
