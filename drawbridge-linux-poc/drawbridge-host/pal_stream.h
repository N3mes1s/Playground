/*
 * pal_stream.h — Component C5: Stream I/O (file)
 *
 * ELF source: analysis/sqlservr_FULL.c, `LinuxFile.cpp` section at
 *   lines 36533–39424 (primary LinuxFile::* members) and the
 *   `LinuxFile` string sites in the 88400–89300 region referenced
 *   by the component plan. The real POSIX primitives live at:
 *     FUN_00353d80  (pread)    — sqlservr_FULL.c:318931
 *     FUN_00353d90  (pwrite)   — sqlservr_FULL.c:318938
 *     FUN_00353db0  (fsync)    — sqlservr_FULL.c:318952
 *     FUN_003538e0  (ftruncate)— sqlservr_FULL.c:318720
 *
 * Owns all 21 DK_Stream* entry points the NTUM (sqlpal.dll) calls
 * through the PAL ABI. Strong symbols emitted here OVERRIDE the
 * legacy NAIVE versions in dk_pal.c (the Makefile weakens them via
 * objcopy so the link is unambiguous).
 *
 * Cross-module dependencies:
 *   - Handle pool: Agent A / component C8 (pal_object.c / pal_kobj.c).
 *     Until that lands, this file provides a local fallback pool
 *     with the same semantics as dk_pal.c's g_handles, exposed via
 *     the pal_stream_* shim so the public DK_Stream* entries stay
 *     valid during the Wave 1 merge.
 *   - Error translation: pal_result status codes (negative HRESULT).
 */

#ifndef PAL_STREAM_H
#define PAL_STREAM_H

#include <stdint.h>
#include "drawbridge_types.h"
#include "dk_pal.h"

/*
 * Internal stream-handle view. The fields mirror LinuxFile::m_*
 * members referenced in the decompiled constructor/destructor
 * (sqlservr_FULL.c around line 36533).
 */
typedef struct pal_stream_handle {
    int      fd;               /* Linux file descriptor */
    int      owns_fd;          /* 1 => close on DK_StreamClose */
    uint64_t open_flags;       /* O_RDONLY / O_RDWR / O_CREAT ... */
    uint64_t access_mask;      /* Windows-style access bits from DK_StreamOpen */
    uint64_t share_mode;       /* FILE_SHARE_* bits (currently informational) */
    uint64_t create_disp;      /* CREATE_NEW / OPEN_EXISTING / ... */
    char     path[256];        /* Resolved POSIX path, for diagnostics */
} pal_stream_handle_t;

/* Map a handle id to our stream record (NULL if wrong type). */
pal_stream_handle_t *pal_stream_from_handle(DK_HANDLE h);

/* Translate a Linux errno into a DK/NT-style status code. */
uint64_t pal_stream_errno_to_status(int err);

/* Open the host stdout/stderr as DK_HANDLEs (used by pal_console.c). */
DK_HANDLE pal_stream_wrap_fd(int fd, int owns_fd);

#endif /* PAL_STREAM_H */
