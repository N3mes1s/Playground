/*
 * pal_scheduler.h — Public interface of the fiber scheduler (C15).
 *
 * Translated from analysis/sqlservr_FULL.c:
 *   FUN_002890a0 @ lines 156863..156884   thread-subsystem init: calls
 *                                         FUN_00355d60(scheduler_config)
 *                                         and FUN_00279f90(aio_callback).
 *   FUN_00355d60 @ line  320481           scheduler config registration.
 *   FUN_00279f90 @ line  148741           AIO callback registration
 *                                         (spawns pthread via FUN_00353f90).
 *   FUN_00252bf0 @ line  123351           AIO completion callback proper.
 *   HEThreads.cpp                         lines 148200..158400: multi-worker
 *                                         dispatch, runqueue, preemption.
 *
 * Strong symbols owned by this TU (override the logged no-ops currently
 * compiled into pal_thread.cpp; the integrator removes those inline defs
 * once this file lands):
 *   pal_scheduler_register
 *   pal_aio_callback_register
 *   pal_aio_callback
 */

#ifndef PAL_SCHEDULER_H
#define PAL_SCHEDULER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scheduler config struct used at FUN_002890a0 @ 156874..156877.
 *   local_30 = 0xffff00000400  (mask_a)
 *   local_28 = 0               (mask_b)
 *   uStack_20 = 0              (mask_c)
 *   local_18 = 0xe10           (tick_period_us)
 */
typedef struct pal_scheduler_config_s {
    uint64_t mask_a;         /* +0x00, 0xffff00000400 */
    uint64_t mask_b;         /* +0x08, 0 */
    uint64_t mask_c;         /* +0x10, 0 */
    uint64_t tick_period_us; /* +0x18, 0xe10 (= 3600 us) */
} pal_scheduler_config_t;

typedef void (*pal_aio_callback_fn)(void *arg1, long arg2);

/* FUN_00355d60 — stash the 32-byte config for the scheduler worker. */
void pal_scheduler_register(const void *config);

/* FUN_00279f90 — register the AIO-completion callback and spawn the
 * dispatch worker.  The worker drains the reap queue and invokes `cb`
 * for every completed io_event. */
void pal_aio_callback_register(pal_aio_callback_fn cb);

/* FUN_00252bf0 — the AIO completion callback proper.  Invoked by the
 * dispatch worker (pal_aio_callback_register) for every reaped event. */
void pal_aio_callback(void *arg1, long arg2);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAL_SCHEDULER_H */
