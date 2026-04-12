/*
 * pal_sync.h — Drawbridge component C7 (Sync / Event / Dispatcher)
 *
 * Source: analysis/sqlservr_FULL.c lines 119203..119417 (palcalls.cpp PAL
 *         wrappers) and 193067..193635 + 201759..201777 (internal KEVENT
 *         ctor / set / clear / peek).
 *
 * Public DK_* entry points are declared in dk_pal.h; this header exposes
 * the KEVENT layout and helpers owned by this component so that future
 * components (C6 thread, C3 ABI) can manipulate dispatcher objects without
 * going through the DK_ ABI thunks.
 *
 * KEVENT layout (observed from ELF FUN_002beff0 @ 0x2beff0 + FUN_002b6020
 * @ 0x2b6020 + FUN_002b6840 @ 0x2b6840).  The struct is 0x58 bytes; offsets
 * we've identified:
 *
 *   +0x00  void*   vtable                 (PTR_FUN_00361fe0 in ELF)
 *   +0x08  int32_t refcount               (initialized to 1 by FUN_002b6020)
 *   +0x0C  uint32_t pad
 *   +0x10  uint8[0x28] unk_0x10           // TODO: NTUM-internal wait mutex/cond
 *   +0x38  LIST_ENTRY waitQueue.Flink     // = &obj->waitQueue (self)
 *   +0x40  LIST_ENTRY waitQueue.Blink     // = &obj->waitQueue (self)
 *   +0x48  uint64_t sentinel              (initialized to 0xffffffffffffffff)
 *   +0x50  uint8   Type                   (0 = notification, 1 = synchronization)
 *   +0x51  uint8   SignalState            <-- futex word (4-byte aligned read)
 *   +0x52  uint8[6] pad
 *
 * Note: the task brief outlines the classic NT DISPATCHER_HEADER
 * (Type@+0x00, SignalState@+0x04, WaitListHead@+0x08).  The ELF's
 * sqlpal uses the alternate wrapper layout above — the PE-side
 * .data KEVENT at 0x1806679d0 is internal to the PE and is NOT
 * the object pointed to by DK_HANDLE.  This struct is what our
 * DK_*Event* calls operate on; the futex word we WAKE is
 * &SignalState promoted to a uint32 (bytes +0x51..+0x54).
 */

#ifndef PAL_SYNC_H
#define PAL_SYNC_H

#include <stdint.h>
#include <pthread.h>
#include "drawbridge_types.h"

#define PAL_KEVENT_TYPE_NOTIFICATION 0u
#define PAL_KEVENT_TYPE_SYNCHRONIZATION 1u

/* Full 0x58-byte object matching the ELF NTUM KEVENT wrapper. */
typedef struct pal_kevent {
    /* +0x00 */ void       *vtable;              /* PTR_FUN_00361fe0 */
    /* +0x08 */ int32_t     refcount;            /* ELF FUN_002b6020 sets 1 */
    /* +0x0C */ uint32_t    unk_0x0C;
    /* +0x10 */ uint8_t     unk_0x10[0x28];      /* TODO: NTUM wait mutex */
    /* +0x38 */ struct pal_kevent *waitq_flink;
    /* +0x40 */ struct pal_kevent *waitq_blink;
    /* +0x48 */ uint64_t    sentinel_0x48;       /* = 0xffffffffffffffff */
    /* +0x50 */ uint8_t     Type;                /* 0=notif, 1=sync */
    /* +0x51 */ uint8_t     SignalState;         /* <-- the futex byte */
    /* +0x52 */ uint8_t     pad_0x52[6];
    /*
     * Auxiliary Linux-host fields — live past the 0x58 boundary and are
     * not accessed by sqlpal code.  Used by our futex wake path.
     */
    uint32_t                futex_word;          /* 4-byte aligned mirror */
    pthread_mutex_t         host_mutex;
    pthread_cond_t          host_cond;
    uint32_t                waiter_count;
    uint32_t                magic;               /* 'KEVT' */
} pal_kevent_t;

#define PAL_KEVENT_MAGIC 0x4b455654u  /* 'KEVT' */

/*
 * Create / manipulate KEVENT (ELF equivalent FUN_002b67d0 +
 * FUN_002b68f0 / FUN_002b69a0 / FUN_002b69b0).
 */
pal_kevent_t *pal_sync_kevent_create(uint8_t type, uint8_t initial_signal);
void          pal_sync_kevent_destroy(pal_kevent_t *ev);

/* Returns previous SignalState (0/1).  Wakes waiters per Type. */
uint8_t       pal_sync_kevent_set(pal_kevent_t *ev);
/* Returns previous SignalState (0/1); clears it. */
uint8_t       pal_sync_kevent_clear(pal_kevent_t *ev);
/* Returns current SignalState (0/1) without side effects. */
uint8_t       pal_sync_kevent_peek(const pal_kevent_t *ev);

/* Block until any of the given events is signaled or the timeout elapses. */
int           pal_sync_wait_any(uint64_t count, pal_kevent_t **events,
                                uint64_t timeout_100ns, uint64_t *out_index);

#endif /* PAL_SYNC_H */
