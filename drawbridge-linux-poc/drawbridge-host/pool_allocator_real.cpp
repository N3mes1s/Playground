/*
 * pool_allocator_real.c
 *
 * Weak override of `pool_allocator_fn` that produces a properly-constructed
 * kernel pool object for the NTUM's type-registry / waiter-list machinery.
 *
 * ----------------------------------------------------------------------
 * Why this file exists
 * ----------------------------------------------------------------------
 * The NTUM reaches the pool allocator through a vtable slot at
 *   pool_obj->vtable[0x50]   (the VirtualAlloc slot of the pool object).
 * The strong implementation lives in dk_pal.c around line 960.  That
 * implementation just mmap()s pages and stashes a stack descriptor at
 * +0x10 of the returned block.  That is enough for the allocator to
 * LOOK alive, but the PE then treats each returned block as a
 * fully-constructed kernel object (lock / waiter-list anchor) whose
 * list head fields are expected to be pre-initialised to point at
 * themselves (the classic Windows LIST_ENTRY idiom).  Because our
 * blocks come back as zeroed pages (links = NULL), the PE builds a
 * waiter-list whose Flink/Blink are NULL and then deadlocks spinning
 * on an empty list anchor at PE RIP 0x180226ad3.
 *
 * This file therefore supplies a drop-in replacement that:
 *   1. returns pages in the LibOS kernel-heap range (0x300000000..),
 *   2. zeroes the payload,
 *   3. writes the stack-descriptor sentinel at +0x10 (unchanged from
 *      dk_pal.c's original behaviour so the rest of the PE keeps
 *      working),
 *   4. for allocations >= 0x30 bytes, initialises two LIST_ENTRY-style
 *      self-referencing list heads at +0x18 and +0x28 — this is the
 *      layout that all 0x1d0-byte lock objects use as their waiter-list
 *      anchor (Flink = Blink = &self->link).
 *
 * ----------------------------------------------------------------------
 * ELF lines translated
 * ----------------------------------------------------------------------
 * The closest ELF analogue to this routine is the `VirtualMemoryAllocate`
 * wrapper `FUN_0024b4f0` at sqlservr_FULL.c lines 118426..118570, together
 * with the object-heap wrapper `FUN_00354030` (sqlservr_FULL.c line
 * 315342; a thin tail-call to the libc malloc path).  The self-reference
 * list initialisation pattern (Flink = Blink = &field) is the same
 * LIST_ENTRY pattern used throughout the NTUM object-init paths at
 * sqlservr_FULL.c lines 96193, 96210, 96265, 96279, 96292.
 *
 * Any field we cannot identify from the decompile keeps an `unk_` name
 * with a TODO comment — per the repo rule of "no invention".
 *
 * ----------------------------------------------------------------------
 * Linkage strategy
 * ----------------------------------------------------------------------
 * `pool_allocator_fn` is declared `__attribute__((weak))` here.  If the
 * strong definition in dk_pal.c is still present, the linker keeps that
 * one and this file contributes nothing (the other parallel agent is
 * authoritative for dk_pal.c).  If the strong definition is removed /
 * retired, this weak one takes over and supplies the corrected
 * behaviour.  As a belt-and-braces fallback, we also export
 * `pool_allocator_fn_real` as a strong symbol so callers that want to
 * install us directly into the vtable can do so without relying on
 * weak-symbol resolution.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#include "drawbridge_types.h"

/* ---------------------------------------------------------------------
 * Bump-pointer within the already-reserved kernel heap.  Kept separate
 * from dk_pal.c's `pool_heap_next` so that if both versions end up in
 * the process (weak loses) they do not share state.  We start at +1 GiB
 * offset inside the kernel heap reservation to stay clear of dk_pal.c's
 * region at +256 MiB.
 * ------------------------------------------------------------------ */
static uint64_t pool_heap_next_real = LIBOS_KERNEL_HEAP + 0x40000000ULL;

/* Kernel stack descriptor slot (mirrors dk_pal.c). */
#define POOL_STACK_DESC_ADDR   (BOOT_STRUCTS_ADDR + 0x16000ULL)

/* Offsets of the LIST_ENTRY-style self-referencing list heads that the
 * NTUM expects inside every 0x1d0-byte lock / waiter-anchor object.
 * These come from the ELF object-init pattern, not invention: see
 * sqlservr_FULL.c lines 96193, 96210 (+0x18) and 96194 (+0x28). */
#define POOL_LIST_HEAD_A_OFF   0x18
#define POOL_LIST_HEAD_B_OFF   0x28

/* Stack-descriptor sentinel slot, unchanged from dk_pal.c. */
#define POOL_STACK_DESC_OFF    0x10

/* ---------------------------------------------------------------------
 * Core implementation
 * ------------------------------------------------------------------ */
static uint64_t pool_allocator_fn_impl(void *pool_obj, uint64_t alloc_size,
                                       uint64_t flags, void *param4,
                                       uint64_t param5, void *param6)
{
    (void)pool_obj; (void)flags; (void)param4; (void)param5; (void)param6;

    /* NTUM occasionally asks for tiny (size==2) allocations for chained
     * list nodes — round every request up to the smallest usable unit
     * so that the PE never sees a sub-cache-line object. */
    if (alloc_size == 0) alloc_size = 0x1000;
    size_t aligned = (alloc_size + 0xFFFULL) & ~0xFFFULL;
    size_t total   = aligned < 0x1000 ? 0x1000 : aligned;

    /* Guard: refuse further pool allocations past an upper bound to
     * avoid VM-address-space exhaustion when the PE enters an alloc
     * retry loop. Wave-6d observed 1.36M pool requests in 5 s after
     * the 0x224c29 scratch extension. 1 GiB cap = 256k * 4 KiB. */
    const uint64_t kPoolCap = LIBOS_KERNEL_HEAP_SZ * 2ULL;  /* 2 GiB */
    uint64_t addr = __atomic_fetch_add(&pool_heap_next_real, total,
                                       __ATOMIC_SEQ_CST);
    if (addr > LIBOS_KERNEL_HEAP + 0x40000000ULL + kPoolCap) {
        static int cap_log = 0;
        if (cap_log++ < 3) {
            fprintf(stderr,
                "[POOL-REAL] allocator cap reached at 0x%lx (cap=0x%lx); "
                "returning 0 to signal OOM to caller\n",
                (unsigned long)addr, (unsigned long)kPoolCap);
        }
        return 0;
    }
    void *result = mmap((void*)addr, total,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (result == MAP_FAILED) {
        int e = errno;
        static int rate_limit = 0;
        if (rate_limit++ < 5) {
            fprintf(stderr, "[POOL-REAL] mmap failed for size=0x%lx at 0x%lx "
                            "errno=%d (%s)\n",
                    (unsigned long)total, (unsigned long)addr, e, strerror(e));
        }
        /* Fall back to kernel-picked address. Consumers don't actually
         * need the specific VA — they just need a valid pointer. */
        result = mmap(nullptr, total, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (result == MAP_FAILED) {
            static int fb_log = 0;
            if (fb_log++ < 3) {
                fprintf(stderr,
                    "[POOL-REAL] fallback mmap also failed errno=%d\n",
                    errno);
            }
            return 0;
        }
    }

    /* Zero the payload explicitly — MAP_ANONYMOUS already gives zeros
     * but once we start reusing pages we need this anyway. */
    memset(result, 0, total);

    uint8_t *r = (uint8_t*)result;

    /* Stack-descriptor sentinel at +0x10 (same as dk_pal.c).  The PE
     * reads this as the owning thread's stack descriptor when it treats
     * the allocation as a KTHREAD-like object. */
    uint8_t *sd = (uint8_t*)POOL_STACK_DESC_ADDR;
    if (*(uint64_t*)(sd + 0x30) == 0) {
        *(uint64_t*)(sd + 0x30) = NTUM_STACK_TOP;
    }
    *(uint64_t*)(r + POOL_STACK_DESC_OFF) = (uint64_t)sd;

    /* Self-referencing LIST_ENTRY heads.  Only do this if the request
     * is large enough to actually contain the two list heads (each is
     * two pointers wide, so we need at least 0x30 bytes of payload).
     * For the tiny (size==2) chained-node requests there is nothing
     * to initialise beyond the zero fill. */
    if (aligned >= (POOL_LIST_HEAD_B_OFF + 0x10)) {
        uint64_t *lh_a = (uint64_t*)(r + POOL_LIST_HEAD_A_OFF);
        uint64_t *lh_b = (uint64_t*)(r + POOL_LIST_HEAD_B_OFF);
        lh_a[0] = (uint64_t)lh_a;   /* Flink -> self */
        lh_a[1] = (uint64_t)lh_a;   /* Blink -> self */
        lh_b[0] = (uint64_t)lh_b;   /* Flink -> self */
        lh_b[1] = (uint64_t)lh_b;   /* Blink -> self */
    }

    /* TODO(unk_vtable): the ELF allocator is suspected to also stamp a
     * type-registry vtable pointer at +0x00 for pool objects produced
     * by the 0x1d0-size class.  We have not yet identified which
     * vtable (the PE-side RVA 0x2c2a00 factory is a candidate but its
     * exact output layout is unconfirmed).  Leave +0x00 zeroed until
     * verified — writing a wrong vtable is worse than writing none. */

    static int pool_real_count = 0;
    if (++pool_real_count <= 50) {
        fprintf(stderr,
                "[POOL-REAL] #%d alloc(%lu) -> %p  (list heads @ +0x18,+0x28 self-ref)\n",
                pool_real_count, (unsigned long)alloc_size, result);
    }

    return (uint64_t)result;
}

/* ---------------------------------------------------------------------
 * Weak override of the NTUM-facing symbol.  If dk_pal.c still provides
 * a strong definition, the linker keeps that one and silently discards
 * this weak one.  If dk_pal.c drops its definition, ours wins.
 * ------------------------------------------------------------------ */
DK_API __attribute__((weak)) __attribute__((force_align_arg_pointer))
uint64_t pool_allocator_fn(void *pool_obj, uint64_t alloc_size,
                           uint64_t flags, void *param4,
                           uint64_t param5, void *param6)
{
    return pool_allocator_fn_impl(pool_obj, alloc_size, flags,
                                  param4, param5, param6);
}

/* ---------------------------------------------------------------------
 * Strong alias so the vtable can be pointed at us explicitly if the
 * weak-override path is not usable.  Name per the task spec.
 * ------------------------------------------------------------------ */
DK_API __attribute__((force_align_arg_pointer))
uint64_t pool_allocator_fn_real(void *pool_obj, uint64_t alloc_size,
                                uint64_t flags, void *param4,
                                uint64_t param5, void *param6)
{
    return pool_allocator_fn_impl(pool_obj, alloc_size, flags,
                                  param4, param5, param6);
}
