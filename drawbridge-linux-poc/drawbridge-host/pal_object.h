/*
 * pal_object.h — Component C8: Object lifecycle public interface.
 *
 * Owner:  pal_object.c
 * Plan:   /root/.claude/plans/hashed-sparking-lake.md
 *
 * Exposes:
 *   - DRAWBRIDGE_OBJECT_HEADER (refcount / type / dtor)
 *   - A small typed handle pool (pal_obj_handle_*).
 *   - DK_ObjectClose / DK_ObjectReference (ms_abi) — these replace the
 *     strong versions currently in dk_pal.c via the weak-override
 *     protocol documented in pal_object.c.
 */

#ifndef PAL_OBJECT_H
#define PAL_OBJECT_H

#include "drawbridge_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------
 * Object header — every object managed by C8 starts with this.
 * The dtor pointer is invoked (with the object) when refcount drops
 * to zero by DK_ObjectClose; dtor may be NULL.
 * --------------------------------------------------------------- */
typedef struct DRAWBRIDGE_OBJECT_HEADER {
    uint32_t refcount;     /* +0x00 */
    uint32_t type;         /* +0x04 — opaque type tag */
    void    *dtor;         /* +0x08 — void (*)(void *obj) */
} DRAWBRIDGE_OBJECT_HEADER;

/* Object type tags the host currently manufactures. */
enum pal_obj_type {
    PAL_OBJ_TYPE_NONE    = 0,
    PAL_OBJ_TYPE_FD      = 1,
    PAL_OBJ_TYPE_EVENT   = 2,
    PAL_OBJ_TYPE_MUTEX   = 3,
    PAL_OBJ_TYPE_MAPPED  = 4,
    PAL_OBJ_TYPE_THREAD  = 5,
    PAL_OBJ_TYPE_POOL    = 6,
};

/*
 * Allocate an object with the supplied header fields and an attached
 * payload pointer (stored alongside the header — callers use
 * pal_obj_handle_payload() to retrieve).  Returns a DK_HANDLE (index
 * into the host's handle table) or DK_NULL_HANDLE on exhaustion.
 */
DK_HANDLE pal_obj_handle_alloc(uint32_t type, void *dtor, void *payload);

/*
 * Look up the payload associated with a handle.  Returns NULL if the
 * handle is invalid or closed.
 */
void *pal_obj_handle_payload(DK_HANDLE h);

/*
 * Look up the header for a handle, or NULL.
 */
DRAWBRIDGE_OBJECT_HEADER *pal_obj_handle_header(DK_HANDLE h);

/*
 * DK-PAL entry points (ms_abi).  These are the strong exports that
 * supersede the dk_pal.c definitions once dk_pal.c's versions are
 * weakened by the integrator — until then our copies are marked weak
 * (see pal_object.c) so the build stays clean.
 */
DK_API uint64_t DK_ObjectClose(DK_HANDLE h);
DK_API uint64_t DK_ObjectReference(DK_HANDLE h);

#ifdef __cplusplus
}
#endif

#endif /* PAL_OBJECT_H */
