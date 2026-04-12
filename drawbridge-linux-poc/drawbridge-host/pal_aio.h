/*
 * pal_aio.h — Public interface of the async I/O completion subsystem (C14).
 *
 * Translated from analysis/sqlservr_FULL.c:
 *   FUN_001f1c50 @ line 52045              -> pal_io_create_completion_port_real
 *                                             (FileIoCompletionPort ctor path)
 *   FUN_001f1e20 @ line 52121              -> PalAioContext::arm  (io_setup arm)
 *   FUN_001f1fd0 @ line 52193              -> PalAioContext::construct
 *                                             (0x1c0-byte in-place ctor)
 *   FUN_00202100 @ line 67430              -> pal_aio_setup
 *                                             (raw "mov rax, 0xce; syscall")
 *   FUN_00252bf0 @ line 123349             -> AIO completion callback dispatch
 *
 * Provides strong definitions that override the weak / first-seen fallbacks
 * that live in pal_io.cpp and pal_stubs.cpp.  The Makefile places pal_aio.cpp
 * BEFORE dk_pal.cpp and pal_io.cpp so the linker's first-seen rule under
 * -Wl,--allow-multiple-definition picks these up.
 */

#ifndef PAL_AIO_H
#define PAL_AIO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Linux AIO opaque context id (matches io_setup(2) aio_context_t).
 * ELF stores this at [FileIoCompletionPort + 0x168].
 * ============================================================ */
typedef unsigned long pal_aio_context_t;

/* Default nr_events used by FUN_001f1e20 when arming io_setup. */
#define PAL_AIO_DEFAULT_NR_EVENTS  0x400u

/* Full size/alignment of the ELF FileIoCompletionPort object
 * (FUN_001f1c50 @ 52057: FUN_00353ee0(0x1c0, 0x40, PTR_nothrow_003675a8)). */
#define PAL_AIO_OBJECT_SIZE        0x1c0u
#define PAL_AIO_OBJECT_ALIGNMENT   0x40u

/* Field offset: m_KernelAioContext inside FileIoCompletionPort
 * (FUN_001f1e20 @ 52132 / 52137). */
#define PAL_AIO_OBJECT_CTX_OFFSET  0x168u

/* ============================================================
 * Public exports (all extern "C" — no ms_abi; called from C++ PAL
 * helpers, not from PE machine code).
 * ============================================================ */

/* FUN_001f1c50 — strong override that replaces the first-seen
 * pal_io_create_completion_port in pal_io.cpp.  Uses the real
 * PalAioContext ctor defined here.  `out_port_slot` is a
 * `long *` (FileIoCompletionPort **) — the caller's slot to publish
 * the newly-constructed object into.  Returns 0 on success, -1 on
 * OOM or io_setup failure (in which case the slot is left NULL). */
int  pal_io_create_completion_port_real(void *out_port_slot);

/* FUN_00202100 — raw io_setup syscall wrapper.  Returns 0 on success
 * and writes the aio_context_t through *ctx_out.  Returns -1 and
 * leaves *ctx_out unchanged on failure (errno preserved). */
int  pal_aio_setup(unsigned nr_events, unsigned long *ctx_out);

/* Submit an already-prepared iocb array to the supplied context.
 * Thin wrapper around SYS_io_submit.  Returns the number of iocbs
 * accepted (>=0) or -1 on error. */
long pal_aio_submit(pal_aio_context_t ctx, long nr, void **iocbpp);

/* Reap completions; blocks for at most `timeout_ns` nanoseconds.
 * Writes up to `max_events` io_event records into `events_out`.
 * Returns the number of events delivered (>=0) or -1 on error. */
long pal_aio_reap(pal_aio_context_t ctx, long min_events, long max_events,
                  void *events_out, long timeout_ns);

/* Tear down an aio context (io_destroy).  Safe to call on a 0 ctx. */
int  pal_aio_destroy(pal_aio_context_t ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAL_AIO_H */
