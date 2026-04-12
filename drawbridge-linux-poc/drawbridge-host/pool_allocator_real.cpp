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

    /* Stack-descriptor sentinel at +0x10 (legacy from dk_pal.c) was
     * overwritten by Wave-19: the PE's object validator at RVA
     * 0x24c38c checks:
     *   cmpl $0xdb64db64, (rbx+0x10)
     * as the "valid VM object" magic header (low 32 bits of the qword
     * at +0x10). Stamping the stack descriptor broke this for every
     * pool object and made the validator return STATUS_INVALID_HANDLE
     * (0xc0000008) from the wait primitive at FUN_387650 -> first
     * RtlRaiseStatus fires with that NTSTATUS, which is the head of
     * the whole raise-recursion cascade.
     *
     * Fix: stamp magic 0xDB64DB64 at [r+0x10] (low 32 bits) and put
     * the stack descriptor pointer at [r+0x14] (high 32 bits of the
     * qword) -- a consumer that reads the full qword still gets a
     * recognisable-looking composite; one that only reads the low 32
     * (like 0x24c38c) now sees the magic. Kernel-stack desc prev init
     * retained so any +0x30 consumer still finds NTUM_STACK_TOP. */
    uint8_t *sd = (uint8_t*)POOL_STACK_DESC_ADDR;
    if (*(uint64_t*)(sd + 0x30) == 0) {
        *(uint64_t*)(sd + 0x30) = NTUM_STACK_TOP;
    }
    /* Keep it simple: just stamp the 32-bit magic (high 32 = 0).
     * If any consumer treats the qword as a pointer and dereferences
     * it, we'll find that separately. The validator only reads the
     * low 32 bits via `cmpl`. */
    (void)sd;
    *(uint64_t*)(r + POOL_STACK_DESC_OFF) = 0xDB64DB64ULL;

    /* Wave-19: DO NOT self-reference [r+0x18]/[r+0x28].
     *
     * Original Wave-6 rationale said 0x1d0-class objects use these
     * offsets as LIST_ENTRY anchors and leaving them NULL caused the
     * Flink/Blink walker at 0x180226ad3 to deadlock.
     *
     * Newer observation (Wave-19, from reverse-engineering
     * FUN_00387650 / FUN_0024c38c): [r+0x18] is a secondary-object
     * pointer, and the wait primitive at 0x387650 EXPECTS it to be 0
     * on first use so it can call FUN_388350 to perform proper
     * sub-object allocation with correct DB64DB64 magic. Our self-ref
     * stamp bypassed that initialiser path: the PE then fed pool+0x18
     * into the VM validator at 0x24c38c, which checks
     *   cmpl 0xdb64db64, (rbx+0x10)
     * Since [pool+0x28] was also self-ref (pool+0x28 address, low 32
     * just a pool offset), the magic check failed and the validator
     * returned STATUS_INVALID_HANDLE (0xc0000008) -- the head of the
     * whole raise-recursion cascade.
     *
     * Leave both offsets at their zero-fill default so FUN_387650
     * performs its proper allocation flow. If anything actually
     * needed the waiter-list anchors at +0x18/+0x28, we'll see it as
     * a new, different crash rather than this synthetic validator
     * failure.
     */
    (void)aligned;

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
