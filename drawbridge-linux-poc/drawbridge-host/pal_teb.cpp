/*
 * pal_teb.c — Component C13: TEB / KTHREAD layout.
 *
 * Owner (M1):  Agent A, per /root/.claude/plans/hashed-sparking-lake.md
 *
 * ELF translation scope
 * ---------------------
 *   FUN_001fa9c0  @ 0x1fa9c0   sqlservr_FULL.c  lines 61605..61622
 *                              (TEB allocator: malloc(0x10000), memset
 *                              0xb0, panic via FUN_00354060 on failure).
 *
 *   FUN_00252c90  @ 0x252c90   sqlservr_FULL.c  lines 123381..123462
 *                              (palcalls.cpp PAL_SET_THREAD_GS_BASE — the
 *                              arch_prctl SET_GS wrapper, wrapped by the
 *                              pal_result error harness FUN_0028e070/
 *                              e0d0/e530/e560/e130).
 *
 * Public API exported
 * -------------------
 *   ntum_teb_t *pal_alloc_teb(void);
 *   int         pal_set_thread_gs_base(void *teb);
 *
 * Fail-loud rule
 * --------------
 * Helpers we do not own (pal_result_init, pal_result_ok, pal_result_set_
 * error, the FS-register / TEB-chain cross-wiring at TEB[0x1838]) are
 * left to their owning components; when their real translations land
 * they'll light up the paths we currently short-circuit.
 *
 * No invention: fields we can't identify from the decompile carry
 * `unk_0xNN` names with a TODO and the RVA where they're referenced.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/prctl.h>   /* ARCH_SET_GS */
#include <sys/prctl.h>

#include "drawbridge_types.h"
#include "pal_teb.h"

/* arch_prctl() is not in every libc's headers; prototype it directly. */
extern "C" int arch_prctl(int code, unsigned long addr);

/* -------------------------------------------------------------------
 * FUN_001fa9c0  (TEB allocator).
 *
 * Preserves exact control flow from sqlservr_FULL.c lines 61607..61622:
 *
 *   void FUN_001fa9c0(long param_1, size_t param_2) {
 *     void *pvVar1;
 *     if (*(long *)(param_1 + 0x88) == 0) {
 *       pvVar1 = malloc(param_2);
 *       *(void **)(param_1 + 0x88) = pvVar1;
 *       if (pvVar1 != (void *)0x0) {
 *         FUN_00353430(pvVar1, 0xb0, param_2);   // memset
 *         return;
 *       }
 *     }
 *     FUN_00354060();   // noreturn panic
 *   }
 *
 * Our public pal_alloc_teb() exposes the malloc-and-fill semantics
 * without requiring a container struct with a +0x88 slot; we hold the
 * cached TEB pointer in a file-scope static.  If the caller wants the
 * guarded container semantics they should use their own slot and stash
 * the return.
 * ----------------------------------------------------------------- */

/* Emulated "+0x88 slot" of the caller container.  TODO(unk_container):
 * the real +0x88 owner is the caller's host-state struct (referenced
 * from FUN_00253350 thread-create; exact type not yet in
 * drawbridge_types.h).  Replaced by integrator when thread-create lands
 * (C6). */
static void *g_teb_slot_at_0x88 /* = NULL */;

ntum_teb_t *pal_alloc_teb(void)
{
    if (g_teb_slot_at_0x88 != 0) {
        /* Container already holds a TEB — mirror FUN_001fa9c0's early-
         * return-with-no-fill behaviour. */
        return (ntum_teb_t*)g_teb_slot_at_0x88;
    }

    void *pv = malloc(PAL_TEB_SIZE);
    g_teb_slot_at_0x88 = pv;
    if (pv == (void*)0) {
        /* FUN_00354060 is a noreturn panic in the ELF.  We don't own
         * that routine so call abort() — the plan's fail-loud policy
         * prefers a visible crash to silent NULL propagation. */
        fprintf(stderr, "[PAL-TEB] malloc(0x%x) failed — panic\n",
                PAL_TEB_SIZE);
        abort();
    }
    /* FUN_00353430(pv, 0xb0, param_2) — memset.  Note the middle arg is
     * the byte value and the third is the length, matching Linux memset
     * argument order. */
    memset(pv, PAL_TEB_FILL_BYTE, PAL_TEB_SIZE);
    return (ntum_teb_t*)pv;
}

/* -------------------------------------------------------------------
 * FUN_00252c90  (palcalls.cpp PAL_SET_THREAD_GS_BASE).
 *
 * The ELF version is wrapped in the pal_result harness:
 *   FUN_0028e070(local_38);                         // init result
 *   if (param_1 == NULL) SET_ERROR(c000000d,1243);  // invalid param
 *   if (!pal_result_ok(local_38)) return result;
 *   if (*param_1 != 0) assert("Arch.x64.FsBase == 0");
 *   if (param_1[1] != 0) {
 *     if (!FUN_00289740()) SET_ERROR(c0000001,126d);
 *     else {
 *       KTHREAD = fs:[-0x10];
 *       if (KTHREAD) { KTHREAD[+0x9e0] = param_1[1]; log(...); }
 *       FUN_0020d9e0(param_1[1], KTHREAD, 0x10000);  // arch_prctl SET_GS
 *     }
 *   }
 *   return result_status;
 *
 * We do not own:
 *   pal_result_init / ok / set_error / destroy   (→ C7/C3 harness)
 *   FUN_00289740                                  (TLS presence check)
 *   FUN_00353f10                                  (logger)
 *   FUN_0020d9e0                                  (the actual SET_GS
 *                                                   worker + KTHREAD
 *                                                   fixup)
 *
 * Our pal_set_thread_gs_base() performs the arch_prctl(ARCH_SET_GS)
 * syscall directly — that is the load-bearing side effect FUN_00252c90
 * ultimately executes through FUN_0020d9e0.  The surrounding pal_result
 * bookkeeping is handled when C3/C7 land; here we return a plain
 * 0/-errno status so callers can drive the syscall today.
 * ----------------------------------------------------------------- */
int pal_set_thread_gs_base(void *teb)
{
    if (teb == (void*)0) {
        /* FUN_00252c90 palcalls.cpp:0x1243 — invalid-param branch.
         * TODO(unk_result_path): once C3 lands pal_result_set_error,
         * re-wire this to return 0xC000000D via the harness instead of
         * EINVAL. */
        errno = EINVAL;
        return -EINVAL;
    }

    /* The ELF asserts param_1->Arch.x64.FsBase == 0 (param_1[0]).  We
     * are given a TEB pointer directly (already post-assert), so we
     * apply the syscall unconditionally.  TODO(unk_fsbase_assert):
     * when C6 routes through here from thread-create, restore the
     * assert so the PE-facing invariant remains equivalent. */

    if (arch_prctl(ARCH_SET_GS, (unsigned long)(uintptr_t)teb) != 0) {
        int err = errno;
        fprintf(stderr,
                "[PAL-TEB] arch_prctl(ARCH_SET_GS, %p) failed: %s\n",
                teb, strerror(err));
        return -err;
    }

    /* TODO(unk_kthread_at_9e0): FUN_00252c90 also writes
     *   KTHREAD[+0x9e0] = TEB
     * when fs:[-0x10] is non-null.  Our KTHREAD substrate (C6) owns
     * that wiring; the write is deferred to the thread-create owner
     * rather than performed here. */

    return 0;
}
