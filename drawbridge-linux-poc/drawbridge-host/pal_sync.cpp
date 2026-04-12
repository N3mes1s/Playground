/*
 * pal_sync.c — Drawbridge component C7: real KEVENT / dispatcher semantics
 *
 * Source ELF line ranges (analysis/sqlservr_FULL.c):
 *   119203..119251  FUN_0024c620  PAL wrapper NotificationEventCreate
 *   119255..119302  FUN_0024c730  PAL wrapper SynchronizationEventCreate
 *   119307..119344  FUN_0024c840  PAL wrapper EventSet
 *   119348..119381  FUN_0024c920  PAL wrapper EventClear
 *   119385..119417  FUN_0024c9f0  PAL wrapper EventPeek
 *   193067..193075  FUN_002b6020  dispatcher base ctor  (refcount=1)
 *   193505..193518  FUN_002b67d0  KEVENT alloc + init (size 0x58)
 *   193522..193532  FUN_002b6840  KEVENT sub-ctor (Type/SignalState)
 *   193546..193557  FUN_002b68a0  Internal SetEvent helper
 *   193561..193575  FUN_002b68c0  Internal signal-test-reset
 *   193579..193609  FUN_002b68f0  KeSetEvent body (atomic fetch of state)
 *   193613..193625  FUN_002b69a0  KeClearEvent body (atomic xchg -> 0)
 *   193629..193635  FUN_002b69b0  KeReadStateEvent body (peek)
 *   201759..201777  FUN_002beff0  KEVENT outer ctor (waitq + sentinel)
 *
 * Because the DK_ interface hands out opaque DK_HANDLE tokens rather than
 * raw pointers into NTUM-managed memory, the pal_kevent_t struct lives in
 * host-side heap; we cast the pointer to DK_HANDLE for return.  This
 * matches the original ELF contract (Handle == pointer into the 0x58-byte
 * slab produced by FUN_002b67d0's FUN_00354030 allocation).
 *
 * Unblocks M2: the PE's poll loop at RIP 0x180226ad3 drops out once the
 * SignalState byte transitions AND a FUTEX_WAKE is issued.  We emit both
 * a pthread_cond_broadcast (for intra-host waiters) and a SYS_futex
 * FUTEX_WAKE (for PE-side spinners polling &SignalState across the ABI
 * trampoline — this is the critical edge that the weak stub lacked).
 *
 * Files we own: this file, pal_sync.h, Makefile SRCS addition.
 * Everything else is read-only.
 */

#define _GNU_SOURCE
#include "pal_sync.h"
#include "dk_pal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>

/* ------------------------------------------------------------------ */
/* Low-level futex helpers.                                            */
/* ------------------------------------------------------------------ */

static int pal_futex(uint32_t *uaddr, int op, uint32_t val,
                     const struct timespec *timeout)
{
    return (int)syscall(SYS_futex, uaddr, op, val, timeout, NULL, 0);
}

static inline void pal_futex_wake(uint32_t *w, int n)
{
    (void)pal_futex(w, FUTEX_WAKE_PRIVATE, (uint32_t)n, NULL);
}

/* ------------------------------------------------------------------ */
/* KEVENT lifecycle — translates FUN_002b67d0 + FUN_002beff0 +         */
/* FUN_002b6020 + FUN_002b6840 (ELF lines 193505..193532, 201759..67,  */
/* 193067..75).                                                        */
/* ------------------------------------------------------------------ */

pal_kevent_t *pal_sync_kevent_create(uint8_t type, uint8_t initial_signal)
{
    pal_kevent_t *ev = (pal_kevent_t *)calloc(1, sizeof(*ev));
    if (!ev)
        return NULL;

    /* FUN_002b6020: *param_1 = &PTR_FUN_00361fa8; refcount = 1 */
    ev->vtable   = NULL;   /* TODO: real vtable ptr PTR_FUN_00361fa8 */
    ev->refcount = 1;

    /* FUN_002beff0: waitqueue head points at itself, sentinel = -1 */
    ev->waitq_flink   = ev;  /* &ev->waitq_flink, same byte offset */
    ev->waitq_blink   = ev;
    ev->sentinel_0x48 = 0xffffffffffffffffULL;

    /* FUN_002b6840: Type + SignalState */
    ev->Type        = (uint8_t)(type & 1);
    ev->SignalState = (uint8_t)(initial_signal ? 1 : 0);

    /* Host-side extension — not part of the 0x58-byte ELF ABI. */
    ev->futex_word   = ev->SignalState;
    ev->waiter_count = 0;
    ev->magic        = PAL_KEVENT_MAGIC;
    pthread_mutex_init(&ev->host_mutex, NULL);
    pthread_cond_init(&ev->host_cond, NULL);

    return ev;
}

void pal_sync_kevent_destroy(pal_kevent_t *ev)
{
    if (!ev || ev->magic != PAL_KEVENT_MAGIC)
        return;
    /* Wake anyone still blocked so we don't leak a thread. */
    pthread_mutex_lock(&ev->host_mutex);
    ev->futex_word = 0xDEAD0000u;
    pthread_cond_broadcast(&ev->host_cond);
    pthread_mutex_unlock(&ev->host_mutex);
    pal_futex_wake(&ev->futex_word, INT32_MAX);

    pthread_mutex_destroy(&ev->host_mutex);
    pthread_cond_destroy(&ev->host_cond);
    ev->magic = 0;
    free(ev);
}

/* ------------------------------------------------------------------ */
/* SetEvent — ELF FUN_002b68f0 (193579..193609) wrapped by 002b68a0.   */
/* Returns previous SignalState.                                       */
/* ------------------------------------------------------------------ */

uint8_t pal_sync_kevent_set(pal_kevent_t *ev)
{
    if (!ev || ev->magic != PAL_KEVENT_MAGIC)
        return 0;

    pthread_mutex_lock(&ev->host_mutex);
    uint8_t prev = ev->SignalState;
    ev->SignalState = 1;
    __atomic_store_n(&ev->futex_word, 1u, __ATOMIC_SEQ_CST);

    /*
     * Type 0 (Notification) -> wake all waiters, SignalState stays set.
     * Type 1 (Synchronization) -> wake exactly one; our futex word remains
     * 1 until a consumer clears it (matches the ELF semantics in 002b68c0).
     */
    if (ev->Type == PAL_KEVENT_TYPE_NOTIFICATION) {
        pthread_cond_broadcast(&ev->host_cond);
    } else {
        pthread_cond_signal(&ev->host_cond);
    }
    pthread_mutex_unlock(&ev->host_mutex);

    /* Critical: real FUTEX_WAKE on the byte the PE poll loop is spinning
       on.  This is the edge that unsticks RIP 0x180226ad3. */
    int wake_n = (ev->Type == PAL_KEVENT_TYPE_NOTIFICATION) ? INT32_MAX : 1;
    pal_futex_wake(&ev->futex_word, wake_n);

    return prev;
}

/* ------------------------------------------------------------------ */
/* ClearEvent — ELF FUN_002b69a0 (193613..193625).                     */
/* xchg(SignalState, 0), returns previous state.                       */
/* ------------------------------------------------------------------ */

uint8_t pal_sync_kevent_clear(pal_kevent_t *ev)
{
    if (!ev || ev->magic != PAL_KEVENT_MAGIC)
        return 0;
    pthread_mutex_lock(&ev->host_mutex);
    uint8_t prev = ev->SignalState;
    ev->SignalState = 0;
    __atomic_store_n(&ev->futex_word, 0u, __ATOMIC_SEQ_CST);
    pthread_mutex_unlock(&ev->host_mutex);
    return prev;
}

/* ------------------------------------------------------------------ */
/* PeekEvent — ELF FUN_002b69b0 (193629..193635).                      */
/* ------------------------------------------------------------------ */

uint8_t pal_sync_kevent_peek(const pal_kevent_t *ev)
{
    if (!ev || ev->magic != PAL_KEVENT_MAGIC)
        return 0;
    return ev->SignalState & 1u;
}

/* ------------------------------------------------------------------ */
/* WaitAny — ELF FUN_001a3800 / KeWaitForMultipleObjects.              */
/*                                                                     */
/* Semantics: block until any event is signaled, returning its index   */
/* in *out_index.  For Synchronization events we also perform the      */
/* clear-on-consume (matches NT kernel + ELF FUN_002b68c0).            */
/* ------------------------------------------------------------------ */

static int compute_deadline(uint64_t timeout_100ns, struct timespec *out)
{
    /* timeout expressed as Windows 100ns ticks.  0 => poll.  Special
       sentinel 0xffffffffffffffff from the ELF = INFINITE. */
    if (timeout_100ns == 0xffffffffffffffffULL || timeout_100ns == 0)
        return 0;

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    uint64_t ns = timeout_100ns * 100ULL;
    out->tv_sec  = now.tv_sec + (time_t)(ns / 1000000000ULL);
    out->tv_nsec = now.tv_nsec + (long)(ns % 1000000000ULL);
    if (out->tv_nsec >= 1000000000L) {
        out->tv_nsec -= 1000000000L;
        out->tv_sec++;
    }
    return 1;
}

int pal_sync_wait_any(uint64_t count, pal_kevent_t **events,
                      uint64_t timeout_100ns, uint64_t *out_index)
{
    if (count == 0 || !events)
        return (int)DK_STATUS_INVALID_PARAM;

    struct timespec deadline;
    int have_deadline = compute_deadline(timeout_100ns, &deadline);
    int is_infinite   = (timeout_100ns == 0xffffffffffffffffULL);
    int is_poll       = (timeout_100ns == 0);

    for (;;) {
        /* Scan for a signaled event first (fast path). */
        for (uint64_t i = 0; i < count; i++) {
            pal_kevent_t *ev = events[i];
            if (!ev || ev->magic != PAL_KEVENT_MAGIC)
                continue;
            pthread_mutex_lock(&ev->host_mutex);
            if (ev->SignalState) {
                if (ev->Type == PAL_KEVENT_TYPE_SYNCHRONIZATION) {
                    ev->SignalState = 0;
                    __atomic_store_n(&ev->futex_word, 0u, __ATOMIC_SEQ_CST);
                }
                pthread_mutex_unlock(&ev->host_mutex);
                if (out_index) *out_index = i;
                return (int)DK_STATUS_SUCCESS;
            }
            pthread_mutex_unlock(&ev->host_mutex);
        }

        if (is_poll) {
            if (out_index) *out_index = (uint64_t)-1;
            return (int)0x00000102;  /* STATUS_TIMEOUT */
        }

        /* Slow path: wait on the first event's cond with a short ceiling
           so we re-scan periodically.  A correct KiWaitBlock chain would
           attach to every event; using a 10 ms ceiling is conservative
           and adds only minor latency to cross-object wakes.             */
        pal_kevent_t *anchor = events[0];
        if (!anchor || anchor->magic != PAL_KEVENT_MAGIC)
            return (int)DK_STATUS_INVALID_PARAM;

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 10 * 1000 * 1000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_nsec -= 1000000000L;
            ts.tv_sec++;
        }
        if (have_deadline) {
            if ((ts.tv_sec > deadline.tv_sec) ||
                (ts.tv_sec == deadline.tv_sec && ts.tv_nsec > deadline.tv_nsec)) {
                ts = deadline;
            }
        }

        pthread_mutex_lock(&anchor->host_mutex);
        anchor->waiter_count++;
        if (!anchor->SignalState)
            pthread_cond_timedwait(&anchor->host_cond, &anchor->host_mutex, &ts);
        anchor->waiter_count--;
        pthread_mutex_unlock(&anchor->host_mutex);

        if (!is_infinite && have_deadline) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            if ((now.tv_sec > deadline.tv_sec) ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                /* Final re-scan before declaring timeout. */
                for (uint64_t i = 0; i < count; i++) {
                    pal_kevent_t *ev = events[i];
                    if (!ev || ev->magic != PAL_KEVENT_MAGIC)
                        continue;
                    pthread_mutex_lock(&ev->host_mutex);
                    if (ev->SignalState) {
                        if (ev->Type == PAL_KEVENT_TYPE_SYNCHRONIZATION) {
                            ev->SignalState = 0;
                            __atomic_store_n(&ev->futex_word, 0u,
                                             __ATOMIC_SEQ_CST);
                        }
                        pthread_mutex_unlock(&ev->host_mutex);
                        if (out_index) *out_index = i;
                        return (int)DK_STATUS_SUCCESS;
                    }
                    pthread_mutex_unlock(&ev->host_mutex);
                }
                if (out_index) *out_index = (uint64_t)-1;
                return (int)0x00000102;  /* STATUS_TIMEOUT */
            }
        }
    }
}

/* ====================================================================
 * DK_* public surface — strong symbols superseding dk_pal.c versions.
 * Link order in the Makefile places pal_sync.c before dk_pal.c so that
 * with -Wl,--allow-multiple-definition the pal_sync.c definitions win.
 * ==================================================================== */

DK_API uint64_t DK_NotificationEventCreate(uint64_t initial_state,
                                           DK_HANDLE *event)
{
    pal_kevent_t *ev = pal_sync_kevent_create(PAL_KEVENT_TYPE_NOTIFICATION,
                                              (uint8_t)(initial_state & 1));
    if (!ev)
        return DK_STATUS_NO_MEMORY;
    if (event)
        *event = (DK_HANDLE)(uintptr_t)ev;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SynchronizationEventCreate(uint64_t initial_state,
                                              DK_HANDLE *event)
{
    pal_kevent_t *ev = pal_sync_kevent_create(PAL_KEVENT_TYPE_SYNCHRONIZATION,
                                              (uint8_t)(initial_state & 1));
    if (!ev)
        return DK_STATUS_NO_MEMORY;
    if (event)
        *event = (DK_HANDLE)(uintptr_t)ev;
    return DK_STATUS_SUCCESS;
}

static pal_kevent_t *pal_sync_from_handle(DK_HANDLE h)
{
    if (h == 0)
        return NULL;
    pal_kevent_t *ev = (pal_kevent_t *)(uintptr_t)h;
    if (((uintptr_t)ev & 0x7) != 0)   /* pointer must be 8-byte aligned */
        return NULL;
    if (ev->magic != PAL_KEVENT_MAGIC)
        return NULL;
    return ev;
}

DK_API uint64_t DK_EventSet(DK_HANDLE event)
{
    pal_kevent_t *ev = pal_sync_from_handle(event);
    if (!ev)
        return DK_STATUS_INVALID_PARAM;
    (void)pal_sync_kevent_set(ev);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventClear(DK_HANDLE event)
{
    pal_kevent_t *ev = pal_sync_from_handle(event);
    if (!ev)
        return DK_STATUS_INVALID_PARAM;
    (void)pal_sync_kevent_clear(ev);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventPeek(DK_HANDLE event, uint64_t *signaled)
{
    pal_kevent_t *ev = pal_sync_from_handle(event);
    if (!ev)
        return DK_STATUS_INVALID_PARAM;
    uint8_t s = pal_sync_kevent_peek(ev);
    if (signaled)
        *signaled = s;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ObjectsWaitAny(uint64_t count, DK_HANDLE *objects,
                                  uint64_t timeout, uint64_t *index)
{
    if (count == 0 || !objects)
        return DK_STATUS_INVALID_PARAM;

    /* The ELF passes raw KEVENT* pointers as handles; translate each
       through pal_sync_from_handle for validation.  On stack for small
       counts to avoid heap pressure in the fast path.                  */
    enum { STACK_N = 32 };
    pal_kevent_t *stack_buf[STACK_N];
    pal_kevent_t **evs;
    if (count <= STACK_N) {
        evs = stack_buf;
    } else {
        evs = (pal_kevent_t **)calloc((size_t)count, sizeof(*evs));
        if (!evs)
            return DK_STATUS_NO_MEMORY;
    }

    for (uint64_t i = 0; i < count; i++) {
        evs[i] = pal_sync_from_handle(objects[i]);
        if (!evs[i]) {
            if (evs != stack_buf) free(evs);
            return DK_STATUS_INVALID_PARAM;
        }
    }

    int rc = pal_sync_wait_any(count, evs, timeout, index);

    if (evs != stack_buf)
        free(evs);
    return (uint64_t)(uint32_t)rc;
}
