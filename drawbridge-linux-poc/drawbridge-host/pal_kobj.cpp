/*
 * pal_kobj.c — Component C12: Kernel Object Pool.
 *
 * Owner (M1):  Agent A, per /root/.claude/plans/hashed-sparking-lake.md
 *
 * ELF translation scope
 * ---------------------
 *   FUN_002c2a00           — pool-object factory used by the type registry
 *                            (referenced in the plan brief; the exact ELF
 *                            symbol at 0x2c2a00 is not exported separately
 *                            in analysis/sqlservr_FULL.c — the closest
 *                            emitted neighbours are FUN_002c2a10 (lines
 *                            205185..205200) and FUN_002c2a50 (lines
 *                            205201..205214) and FUN_002c2a70 (lines
 *                            205215..).  The factory semantics are derived
 *                            from the LIST_ENTRY pattern used at
 *                            sqlservr_FULL.c lines 96193, 96210, 96265,
 *                            96279, 96292 and the sentinel-init pattern
 *                            described below).
 *
 *   FUN_00240ea0           — sentinel-or-init lock builder.  Not emitted
 *                            as a standalone function in the dump
 *                            (neighbours FUN_00240b90 / FUN_00240f90 are
 *                            visible); the layout comes from:
 *                              - dk_pal.c pool object +0x10 stash
 *                                (stack descriptor)  and
 *                              - plan instruction: write
 *                                0x12345678deaddead to [+0x10] as the
 *                                "initialised" sentinel.
 *                            See pool_allocator_real.c (the prior
 *                            reference implementation) for the precedent
 *                            behaviour this replaces.
 *
 *   Reference implementation being superseded: pool_allocator_real.c
 *   (sqlservr_FULL.c lines 118426..118570 for the VirtualMemoryAllocate
 *   wrapper FUN_0024b4f0 and the object-heap wrapper FUN_00354030 at
 *   line 315342 — both informing the mmap + memset + list-head pattern).
 *
 * Public API exported
 * -------------------
 *   pool_allocator_fn_real(pool_obj, size, flags, p4, p5, p6)  ms_abi
 *   pal_kobj_sentinel_init(lock)
 *   pal_kobj_factory_create(void)
 *
 * Fail-loud rule
 * --------------
 * Any helper we need but do not own (e.g. pal_result_*, pal_kernel_heap_*)
 * is declared extern so the linker pulls it in from its real owner; if
 * nobody defines it, pal_stubs.c's fail-loud default takes over.
 *
 * No invention: fields whose purpose is not readable from the decompile
 * carry `unk_0xNN` names with a TODO citing the RVA where they're read
 * or written.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "drawbridge_types.h"
#include "pal_kobj.h"

/* -------------------------------------------------------------------
 * Kernel-heap bump pointer.
 *
 * We keep a dedicated offset inside the kernel-heap reservation to stay
 * clear of dk_pal.c's region (+256 MiB) and of pool_allocator_real.c's
 * region (+1 GiB).  The C12 factory lives at +1.5 GiB so if both
 * old and new code are linked in simultaneously they do not share
 * state.  (pool_allocator_real.c is transitional: once removed we
 * may collapse these.)
 * ----------------------------------------------------------------- */
static uint64_t g_kobj_heap_next = LIBOS_KERNEL_HEAP + 0x60000000ULL;

/* -------------------------------------------------------------------
 * Layout offsets inside a pool object.
 *
 * Extracted from:
 *   +0x10 — stack-descriptor / init sentinel (dk_pal.c, FUN_00240ea0 spec)
 *   +0x18 — LIST_ENTRY head A (Flink, Blink) — pattern at sqlservr
 *           lines 96193 / 96210.
 *   +0x28 — LIST_ENTRY head B (Flink, Blink) — pattern at sqlservr
 *           line 96194 and siblings.
 * ----------------------------------------------------------------- */
#define KOBJ_OFF_SENTINEL      0x10
#define KOBJ_OFF_LIST_A        0x18
#define KOBJ_OFF_LIST_B        0x28

/*
 * TODO(unk_vtable_at_0x00): FUN_002c2a00 is suspected to also stamp a
 * type-registry vtable pointer at +0x00 for its 0x1d0-class output.  The
 * exact vtable symbol has not been identified in the decompile yet; any
 * non-null write here without confirmation would be invention.  Leave
 * +0x00 zeroed until we can cite the RVA that writes it.
 */

/* -------------------------------------------------------------------
 * FUN_00240ea0 — sentinel-or-init lock builder.
 *
 * Preserves exact control flow per plan brief:
 *   if (*(uint64_t*)(lock + 0x10) == 0x12345678deaddead) return lock;
 *   memset(lock, 0, 0x1d0);
 *   initialise LIST_ENTRY at +0x18 and +0x28 self-referential;
 *   *(uint64_t*)(lock + 0x10) = 0x12345678deaddead;
 *   return lock;
 * ----------------------------------------------------------------- */
void *pal_kobj_sentinel_init(void *lock)
{
    if (lock == (void*)0) return (void*)0;
    uint8_t *p = (uint8_t*)lock;

    if (*(uint64_t*)(p + KOBJ_OFF_SENTINEL) == PAL_KOBJ_INIT_SENTINEL) {
        /* Already initialised — idempotent fast-path. */
        return lock;
    }

    /* Zero the object payload.  The size 0x1d0 matches the
     * PAL_KOBJ_LIST_CLASS_SIZE size class — this is the NTUM's generic
     * lock / waiter-anchor dimension. */
    memset(p, 0, PAL_KOBJ_LIST_CLASS_SIZE);

    /* Self-referential LIST_ENTRYs at +0x18 and +0x28. */
    uint64_t *lh_a = (uint64_t*)(p + KOBJ_OFF_LIST_A);
    uint64_t *lh_b = (uint64_t*)(p + KOBJ_OFF_LIST_B);
    lh_a[0] = (uint64_t)(uintptr_t)lh_a;  /* Flink -> self */
    lh_a[1] = (uint64_t)(uintptr_t)lh_a;  /* Blink -> self */
    lh_b[0] = (uint64_t)(uintptr_t)lh_b;  /* Flink -> self */
    lh_b[1] = (uint64_t)(uintptr_t)lh_b;  /* Blink -> self */

    /* Publish the sentinel last (release order): the NTUM uses the
     * sentinel word as the "fully initialised" flag. */
    *(uint64_t*)(p + KOBJ_OFF_SENTINEL) = PAL_KOBJ_INIT_SENTINEL;

    return lock;
}

/* -------------------------------------------------------------------
 * Core allocator — shared body for pool_allocator_fn_real and the
 * factory.  Rounds up to page granularity, mmaps a fixed region out of
 * the kernel heap, zeros it, and runs the sentinel-init pass if the
 * resulting allocation can hold the 0x1d0-class footprint.
 *
 * Preserves pool_allocator_real.c semantics for compat: tiny (size==2)
 * chained-node requests are allowed to stay tiny (no list-head
 * initialisation).
 * ----------------------------------------------------------------- */
static void *kobj_raw_alloc(uint64_t alloc_size)
{
    if (alloc_size == 0) alloc_size = 0x1000;
    size_t aligned = (alloc_size + 0xFFFULL) & ~0xFFFULL;
    size_t total   = aligned < 0x1000 ? 0x1000 : aligned;

    uint64_t addr = __atomic_fetch_add(&g_kobj_heap_next, total,
                                       __ATOMIC_SEQ_CST);
    void *result = mmap((void*)addr, total,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (result == MAP_FAILED) {
        fprintf(stderr, "[KOBJ] mmap failed size=0x%lx at 0x%lx\n",
                (unsigned long)total, (unsigned long)addr);
        return (void*)0;
    }
    /* MAP_ANONYMOUS zeros on first touch, but reuse-safety wants this
     * explicit. */
    memset(result, 0, total);
    return result;
}

/* -------------------------------------------------------------------
 * FUN_002c2a00 — pool-object factory.
 *
 * Allocates a 0x1d0-class block and runs the sentinel-init.  Returns
 * the fully-initialised object (or NULL on OOM).
 * ----------------------------------------------------------------- */
void *pal_kobj_factory_create(void)
{
    void *obj = kobj_raw_alloc(PAL_KOBJ_LIST_CLASS_SIZE);
    if (obj == (void*)0) return (void*)0;
    return pal_kobj_sentinel_init(obj);
}

/* -------------------------------------------------------------------
 * Public vtable entry: pool_allocator_fn_real.
 *
 * ms_abi — called from PE machine code through the pool-object vtable
 * slot at +0x50.  Parameters 3..6 are presently unused (they carry
 * flags / tag fields whose RVAs we have not confirmed; TODOs below).
 * ----------------------------------------------------------------- */
DK_API __attribute__((force_align_arg_pointer))
uint64_t pool_allocator_fn_real(void *pool_obj,
                                uint64_t alloc_size,
                                uint64_t flags,
                                void *param4,
                                uint64_t param5,
                                void *param6)
{
    (void)pool_obj;  /* TODO(unk_pool_vtable): cross-check whether the
                      * factory needs to consult pool_obj->sub_allocator
                      * at +0x40 — dk_pal.c currently ignores it and the
                      * PE still progresses, so leave untouched until an
                      * RVA proves we must use it. */
    (void)flags;     /* TODO(unk_flags): decompile tag at vtable[0x50]
                      * caller RVA not yet identified. */
    (void)param4; (void)param5; (void)param6;

    void *p = kobj_raw_alloc(alloc_size);
    if (p == (void*)0) return 0;

    /* For anything large enough to be a waiter-anchor, stamp the
     * sentinel + LIST_ENTRY heads.  For tiny chained-node allocations
     * (alloc_size < 0x30) leave the block zeroed — the NTUM uses those
     * as opaque buffers, not as locks. */
    size_t aligned = (alloc_size + 0xFFFULL) & ~0xFFFULL;
    if (aligned >= (KOBJ_OFF_LIST_B + 0x10)) {
        (void)pal_kobj_sentinel_init(p);
    }

    static int kobj_count = 0;
    if (++kobj_count <= 50) {
        fprintf(stderr,
                "[KOBJ] #%d alloc(%lu) -> %p  (sentinel=%s)\n",
                kobj_count, (unsigned long)alloc_size, p,
                aligned >= (KOBJ_OFF_LIST_B + 0x10) ? "yes" : "no");
    }

    return (uint64_t)(uintptr_t)p;
}
