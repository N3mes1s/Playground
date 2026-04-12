/*
 * pal_object.c — Component C8: Object lifecycle.
 *
 * Owner (M1):  Agent A, per /root/.claude/plans/hashed-sparking-lake.md
 *
 * ELF translation scope
 * ---------------------
 *   FUN_001a5e20  — ObjectClose semantics.  Not emitted in
 *                   analysis/sqlservr_FULL.c as a stand-alone function
 *                   in the dump snapshot; the existing (reference)
 *                   implementation is dk_pal.c:DK_ObjectClose, lines
 *                   710..723, which the plan flags as the starting
 *                   point.
 *
 *   FUN_001a5f10  — ObjectReference semantics.  Reference
 *                   implementation in dk_pal.c:DK_ObjectReference,
 *                   lines 725..729 (currently a no-op — our rewrite
 *                   gives it a real refcount bump).
 *
 *   FUN_00195440  — handle table.  Reference implementation in
 *                   dk_pal.c's g_handles[] static (lines 45..76).
 *                   We keep a parallel typed handle pool here so our
 *                   strong ObjectClose/Reference can trace and refcount
 *                   the handles they own (only objects allocated
 *                   through pal_obj_handle_alloc are refcounted; legacy
 *                   dk_pal.c handles fall through to the old path).
 *
 * Public API exported
 * -------------------
 *   DRAWBRIDGE_OBJECT_HEADER { refcount, type, dtor } typedef
 *   pal_obj_handle_alloc / payload / header
 *   DK_ObjectClose (ms_abi)      — weak until integrator weakens dk_pal.c
 *   DK_ObjectReference (ms_abi)  — weak until integrator weakens dk_pal.c
 *
 * Linkage strategy
 * ----------------
 * The plan instructs our DK_ObjectClose / DK_ObjectReference to
 * "supersede the weak/existing ones".  dk_pal.c currently defines both
 * as strong symbols — we must not break the build while the other
 * component owners catch up.  We therefore mark our copies weak here:
 * today dk_pal.c wins (identical behaviour to baseline; no regression),
 * and on the integrator-follow-up that weakens dk_pal.c's definitions
 * our copies take over with no further edits to this file.
 *
 * Fail-loud rule
 * --------------
 * Any helper we need but do not own (e.g. pal_kernel_heap_free for C12
 * payload free) is left to its component.  For handles not in our
 * table we forward to the legacy dk_pal.c behaviour through a weak
 * symbol hand-off.
 *
 * No invention: unknown fields carry `unk_0xNN` names with a TODO and
 * the relevant RVA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "drawbridge_types.h"
#include "pal_object.h"

/* -----------------------------------------------------------------
 * Typed handle pool.
 *
 * Index 0 is reserved (= DK_NULL_HANDLE).  We start allocations at a
 * high offset (2048) so this pool's indices do not collide with
 * dk_pal.c's g_handles[] (which allocates starting from 16 and rarely
 * passes ~100).  When the integrator collapses handle ownership into
 * C8 the offset can be dropped.
 * --------------------------------------------------------------- */
#define PAL_OBJ_HANDLE_BASE   2048
#define PAL_OBJ_HANDLE_COUNT  (MAX_HANDLES - PAL_OBJ_HANDLE_BASE)

typedef struct pal_obj_slot {
    DRAWBRIDGE_OBJECT_HEADER hdr;
    void *payload;
    uint8_t  in_use;
} pal_obj_slot_t;

static pal_obj_slot_t   g_obj_slots[PAL_OBJ_HANDLE_COUNT];
static pthread_mutex_t  g_obj_lock = PTHREAD_MUTEX_INITIALIZER;

static inline int handle_in_range(DK_HANDLE h)
{
    return h >= PAL_OBJ_HANDLE_BASE && h < MAX_HANDLES;
}

static inline pal_obj_slot_t *slot_for(DK_HANDLE h)
{
    if (!handle_in_range(h)) return (pal_obj_slot_t*)0;
    pal_obj_slot_t *s = &g_obj_slots[h - PAL_OBJ_HANDLE_BASE];
    return s->in_use ? s : (pal_obj_slot_t*)0;
}

/* -----------------------------------------------------------------
 * FUN_00195440 — handle table allocator.
 *
 * Linear scan for a free slot, stamp the header, return the DK_HANDLE.
 * The legacy dk_pal.c allocator (g_handles[]) does essentially the same
 * thing — we preserve that control flow, just typed.
 * --------------------------------------------------------------- */
DK_HANDLE pal_obj_handle_alloc(uint32_t type, void *dtor, void *payload)
{
    pthread_mutex_lock(&g_obj_lock);
    for (int i = 0; i < PAL_OBJ_HANDLE_COUNT; i++) {
        if (!g_obj_slots[i].in_use) {
            g_obj_slots[i].in_use       = 1;
            g_obj_slots[i].hdr.refcount = 1;
            g_obj_slots[i].hdr.type     = type;
            g_obj_slots[i].hdr.dtor     = dtor;
            g_obj_slots[i].payload      = payload;
            pthread_mutex_unlock(&g_obj_lock);
            return (DK_HANDLE)(PAL_OBJ_HANDLE_BASE + i);
        }
    }
    pthread_mutex_unlock(&g_obj_lock);
    return DK_NULL_HANDLE;
}

void *pal_obj_handle_payload(DK_HANDLE h)
{
    pthread_mutex_lock(&g_obj_lock);
    pal_obj_slot_t *s = slot_for(h);
    void *p = s ? s->payload : (void*)0;
    pthread_mutex_unlock(&g_obj_lock);
    return p;
}

DRAWBRIDGE_OBJECT_HEADER *pal_obj_handle_header(DK_HANDLE h)
{
    pthread_mutex_lock(&g_obj_lock);
    pal_obj_slot_t *s = slot_for(h);
    DRAWBRIDGE_OBJECT_HEADER *p = s ? &s->hdr : (DRAWBRIDGE_OBJECT_HEADER*)0;
    pthread_mutex_unlock(&g_obj_lock);
    return p;
}

/* -----------------------------------------------------------------
 * Legacy dk_pal.c handoff.
 *
 * Handles that sit outside our [PAL_OBJ_HANDLE_BASE..MAX_HANDLES)
 * window are owned by dk_pal.c's g_handles[] table.  When the
 * integrator weakens dk_pal.c's DK_ObjectClose/Reference so ours take
 * over, we need to still service those legacy handles without
 * reintroducing dk_pal.c-internal knowledge.  We route through the
 * weak symbols `legacy_dk_object_close` / `legacy_dk_object_reference`
 * which dk_pal.c (or its replacement) can define.  For the M1 build
 * these weak symbols are undefined (resolve to NULL) so we just
 * succeed — matching baseline behaviour for non-C8 handles.
 * --------------------------------------------------------------- */
__attribute__((weak)) uint64_t legacy_dk_object_close(DK_HANDLE h);
__attribute__((weak)) uint64_t legacy_dk_object_reference(DK_HANDLE h);

/* -----------------------------------------------------------------
 * FUN_001a5e20 — ObjectClose.
 *
 * Control flow preserved from the dk_pal.c reference at lines 710..723
 * (type dispatch) plus refcount-drop semantics from the Windows
 * ObReferenceObject / ObDereferenceObject idiom that the NTUM expects
 * on dispatcher-header-bearing objects.
 *
 *   if (handle out of range)   → STATUS_INVALID_PARAMETER
 *   if (handle in our table)   → atomic_dec(refcount)
 *                                if dropped to 0: invoke dtor, free slot
 *   else                       → legacy_dk_object_close fallback
 *
 * Weak so dk_pal.c's strong symbol wins until the integrator weakens
 * it (see file header).
 * --------------------------------------------------------------- */
DK_API __attribute__((force_align_arg_pointer))
uint64_t DK_ObjectClose(DK_HANDLE h)
{
    if (h == DK_NULL_HANDLE || h >= MAX_HANDLES) {
        return DK_STATUS_INVALID_PARAM;
    }

    if (handle_in_range(h)) {
        pthread_mutex_lock(&g_obj_lock);
        pal_obj_slot_t *s = slot_for(h);
        if (!s) {
            pthread_mutex_unlock(&g_obj_lock);
            return DK_STATUS_INVALID_PARAM;
        }
        /* Decrement; if the refcount reaches zero invoke the dtor and
         * release the slot.  TODO(unk_dtor_signature): the dtor ABI in
         * the ELF uses a (void *self) signature — we mirror that here.
         * If a future owner needs extended params, they should extend
         * DRAWBRIDGE_OBJECT_HEADER with a type-tagged union rather
         * than reinterpreting the pointer. */
        uint32_t nv = __atomic_sub_fetch(&s->hdr.refcount, 1,
                                         __ATOMIC_ACQ_REL);
        if (nv == 0) {
            void (*dtor)(void*) = (void (*)(void*))s->hdr.dtor;
            void *payload = s->payload;
            s->in_use   = 0;
            s->payload  = (void*)0;
            s->hdr.type = PAL_OBJ_TYPE_NONE;
            s->hdr.dtor = (void*)0;
            pthread_mutex_unlock(&g_obj_lock);
            if (dtor) dtor(payload);
            return DK_STATUS_SUCCESS;
        }
        pthread_mutex_unlock(&g_obj_lock);
        return DK_STATUS_SUCCESS;
    }

    /* Out of our range — legacy handle.  Forward if the integrator has
     * wired up `legacy_dk_object_close`; otherwise succeed silently so
     * we do not regress baseline behaviour. */
    if (&legacy_dk_object_close) {
        return legacy_dk_object_close(h);
    }
    return DK_STATUS_SUCCESS;
}

/* -----------------------------------------------------------------
 * FUN_001a5f10 — ObjectReference.
 *
 * Bumps the refcount on a live header.  Legacy dk_pal.c
 * DK_ObjectReference is a no-op; ours implements the real increment.
 *
 *   if (handle invalid)        → STATUS_INVALID_PARAMETER
 *   if (handle in our table)   → atomic_inc(refcount); success
 *   else                       → legacy_dk_object_reference fallback
 *
 * Weak for the same reason as DK_ObjectClose.
 * --------------------------------------------------------------- */
DK_API __attribute__((force_align_arg_pointer))
uint64_t DK_ObjectReference(DK_HANDLE h)
{
    if (h == DK_NULL_HANDLE || h >= MAX_HANDLES) {
        return DK_STATUS_INVALID_PARAM;
    }

    if (handle_in_range(h)) {
        pthread_mutex_lock(&g_obj_lock);
        pal_obj_slot_t *s = slot_for(h);
        if (!s) {
            pthread_mutex_unlock(&g_obj_lock);
            return DK_STATUS_INVALID_PARAM;
        }
        (void)__atomic_add_fetch(&s->hdr.refcount, 1, __ATOMIC_ACQ_REL);
        pthread_mutex_unlock(&g_obj_lock);
        return DK_STATUS_SUCCESS;
    }

    if (&legacy_dk_object_reference) {
        return legacy_dk_object_reference(h);
    }
    return DK_STATUS_SUCCESS;
}
