/*
 * pal_kobj.h — Component C12: Kernel Object Pool public interface.
 *
 * Owner:  pal_kobj.c
 * Plan:   /root/.claude/plans/hashed-sparking-lake.md
 *
 * This component replaces pool_allocator_real.c with a clean translation of
 * the ELF's pool-object factory (FUN_002c2a00) and the sentinel/init helper
 * (FUN_00240ea0).  It provides the low-level kernel pool allocator used by
 * the type registry and dispatched via the pool-object vtable at
 * pool_obj->vtable[0x50].
 */

#ifndef PAL_KOBJ_H
#define PAL_KOBJ_H

#include "drawbridge_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Size class descriptor for LIST_ENTRY-anchor objects.
 * The 0x1d0 class is the NTUM's generic lock / waiter-list anchor.
 */
#define PAL_KOBJ_LIST_CLASS_SIZE   0x1d0

/*
 * The sentinel value written at [obj + 0x10] by FUN_00240ea0.
 * Any 0x10-offset word equal to this is treated by the NTUM as
 * "sentinel recognised — the object has been initialised by the
 * pool factory, not raw-allocated".  Extracted from the plan
 * brief for FUN_00240ea0.
 */
#define PAL_KOBJ_INIT_SENTINEL     0x12345678deaddeadULL

/*
 * Public entry point the NTUM reaches through
 * pool_obj->vtable[0x50]  (VirtualAlloc slot of the pool object).
 *
 * ms_abi — called from PE code using the Windows x64 convention.
 */
DK_API uint64_t pool_allocator_fn_real(void *pool_obj,
                                       uint64_t alloc_size,
                                       uint64_t flags,
                                       void *param4,
                                       uint64_t param5,
                                       void *param6);

/*
 * FUN_00240ea0 — sentinel-or-init lock builder.
 * If [lock + 0x10] already contains PAL_KOBJ_INIT_SENTINEL the object is
 * left alone.  Otherwise it is zeroed, its LIST_ENTRY heads at +0x18 and
 * +0x28 are initialised self-referential, and the sentinel is written.
 * Returns the same lock pointer passed in (convenience for tail calls).
 */
void *pal_kobj_sentinel_init(void *lock);

/*
 * FUN_002c2a00 — pool-object factory.
 * Allocates a 0x1d0-class block out of the kernel heap, runs the
 * sentinel-init pass, and returns the resulting object.  This is what
 * the type registry's case-1/case-2 dispatch calls to manufacture new
 * typed kernel objects.
 */
void *pal_kobj_factory_create(void);

#ifdef __cplusplus
}
#endif

#endif /* PAL_KOBJ_H */
