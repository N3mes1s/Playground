/*
 * pal_teb.h — Component C13: TEB / KTHREAD layout public interface.
 *
 * Owner:  pal_teb.c
 * Plan:   /root/.claude/plans/hashed-sparking-lake.md
 *
 * Exposes the TEB allocator (FUN_001fa9c0) and the GS-base setter
 * (FUN_00252c90) to the rest of the host.
 */

#ifndef PAL_TEB_H
#define PAL_TEB_H

#include "drawbridge_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Total size of the TEB block allocated by FUN_001fa9c0 (malloc 0x10000).
 * Matches sizeof(ntum_teb_t) which is padded to 0x10000 in
 * drawbridge_types.h. */
#define PAL_TEB_SIZE           0x10000

/* Byte to which FUN_001fa9c0 memsets the TEB before returning it.
 * Straight from sqlservr_FULL.c line 61616: FUN_00353430(pv,0xb0,param_2). */
#define PAL_TEB_FILL_BYTE      0xb0

/*
 * Allocate, zero-fill-with-0xb0, and return a fresh TEB.
 *
 * Mirrors FUN_001fa9c0's guard: if the caller already set a TEB on the
 * container object, the existing pointer is returned rather than
 * leaking a second allocation.  For the bare host call we emulate the
 * "container" as a one-slot static — callers that want the guarded
 * pattern should manage their own slot and cache the return themselves.
 *
 * Returns NULL on malloc failure (caller is expected to panic).
 */
ntum_teb_t *pal_alloc_teb(void);

/*
 * Set the current thread's %gs base to `teb` via arch_prctl(ARCH_SET_GS).
 * Mirrors the side-effect portion of FUN_00252c90 (sqlservr_FULL.c lines
 * 123381..123462).
 *
 * Returns 0 on success, -errno on failure.
 */
int pal_set_thread_gs_base(void *teb);

#ifdef __cplusplus
}
#endif

#endif /* PAL_TEB_H */
