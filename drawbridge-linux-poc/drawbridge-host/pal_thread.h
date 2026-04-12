/*
 * pal_thread.h — Public interface of the thread/fiber subsystem (C6).
 *
 * Translated from analysis/sqlservr_FULL.c:
 *   FUN_001fa9c0 @ line 61607                  → pal_alloc_teb
 *   FUN_00252c90 @ lines 123381-123462         → pal_set_thread_gs_base
 *   FUN_00252e60 @ lines 123466-123658         → pal_thread_create
 *   FUN_00253350 @ lines 123665-123755         → pal_thread_entry_thunk
 *   FUN_002890a0 @ lines 156863-156882         → pal_thread_subsystem_init
 *
 * Helpers referenced by the above (real implementations live in
 * pal_thread.c; weak fallbacks in pal_stubs.c until owner components
 * land real bodies):
 *   FUN_00280200 → pal_thread_validate_param / _ex
 *   FUN_001fa870 → pal_kthread_construct
 *   FUN_003541b0/c0 → pal_mutex_lock / pal_mutex_unlock
 *   FUN_0025a520/40 → pal_guest_dispatch_nt / _linux
 *   FUN_001fa5f0 → pal_thread_state_alloc
 *   FUN_002b6070/a0/d0/100/190 → pal_ts_acquire / arm / set_attached / release / release_alt
 *   FUN_001bbc30 → pal_instance_get_attr
 *   FUN_003553c0/d0/e0 → pal_pthread_attr_init / set_detach / destroy
 *   FUN_00353f90 → pal_pthread_create
 *   FUN_003553f0 → pal_thread_local_alloc
 *   FUN_00355400/10/20/30/40/50/60/70 → thread-state / teb_register / sigalt / signal_mask
 *   FUN_00354170 → pal_gettid
 *   FUN_0020d9e0 → pal_observer_notify
 *   FUN_00207280 → pal_pal_thread_starting
 *   FUN_001ae6e0 → pal_invoke_guest_entry
 *   FUN_00355d60 → pal_scheduler_register
 *   FUN_00279f90 → pal_aio_callback_register
 *   FUN_00252bf0 → pal_aio_callback
 */

#ifndef PAL_THREAD_H
#define PAL_THREAD_H

#include <stdint.h>
#include <stddef.h>

#include "drawbridge_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Core C6 public entrypoints
 * ============================================================ */

/* ELF FUN_001fa9c0 — allocates 64 KiB, zeros Nt_Tib header.
 * NOTE: if C13 (pal_teb.c) lands a stronger copy, its definition wins; our
 * pal_thread.c copy is therefore marked weak. */
ntum_teb_t *pal_alloc_teb(void);

/* ELF FUN_00252c90 — arch_prctl(ARCH_SET_GS, RegisterValues->GsBase). */
int  pal_set_thread_gs_base(void *register_values);

/* ELF FUN_00252e60 — create KTHREAD + spawn host pthread. */
ntum_kthread_t *pal_thread_create(void *entry, void *arg);

/* ELF FUN_00253350 — pthread start routine. */
void pal_thread_entry_thunk(ntum_kthread_t *kt);

/* ELF FUN_002890a0 — scheduler + AIO callback registration. */
void pal_thread_subsystem_init(void);

/* ============================================================
 * DK PAL exports (ms_abi) — strong in dk_pal.c, weak here so the
 * build stays clean during the parallel-agent landing window.  When
 * dk_pal.c's copies are deleted the pal_thread.c strong symbols
 * take over.
 * ============================================================ */

#ifndef DK_API
#define DK_API __attribute__((ms_abi))
#endif

DK_API uint64_t DK_ThreadCreate(void *start_routine, void *stack_ptr,
                                uint64_t flags, DK_HANDLE *thread);
DK_API void     DK_ThreadExit(uint64_t exit_code);
DK_API uint64_t DK_ThreadYieldExecution(void);
DK_API uint64_t DK_ThreadInterrupt(DK_HANDLE thread);
DK_API uint64_t DK_ThreadSetAffinity(DK_HANDLE thread, uint64_t group,
                                     uint64_t mask);

/* ============================================================
 * Subsystem helpers — real implementations in pal_thread.c.
 * Declared here so other components (e.g. pal_boot.c) that call
 * into us get prototype checking.
 * ============================================================ */

char     pal_thread_validate_param(void);
char     pal_thread_validate_param_ex(void *p);
void     pal_kthread_construct(void *kt);
int      pal_mutex_lock(void *m);
int      pal_mutex_unlock(void *m);
void     pal_guest_dispatch_nt(void);
void     pal_guest_dispatch_linux(void);
long     pal_thread_state_alloc(int kind);
void     pal_thread_destroy(void *kt);
void    *pal_ts_acquire(long ts);
void     pal_ts_arm(long ts);
void     pal_ts_set_attached(long ts);
void     pal_ts_release(long ts);
void     pal_ts_release_alt(long ts);
uint64_t pal_instance_get_attr(void *image_handle);
int      pal_pthread_attr_init(void *attr);
int      pal_pthread_attr_set_detach(void *attr, uint64_t detach_flag);
int      pal_pthread_attr_destroy(void *attr);
int      pal_pthread_create(void *tid_out, void *attr,
                            void *(*start)(void *), void *arg);

void     pal_pal_thread_starting(void *pal_instance_sink);
void    *pal_thread_local_alloc(void);
int      pal_thread_state_setup(void *tl, void *out_state);
int      pal_thread_state_stack(void *state, long *base_out, long *len_out);
int      pal_thread_state_finalize(void *state);
uint32_t pal_gettid(void);
int      pal_teb_register(void *teb_desc, int flag);
void     pal_sigalt_init(void *ctx);
void     pal_sigalt_set_signo(void *ctx, int sig);
int      pal_sigalt_install(int how, void *ctx, void *old);
void     pal_observer_notify(int flag, void *kthread, uint64_t sz);
int      pal_signal_mask_fork(void *ctx);
void     pal_signal_mask_release(void *tl);
void     pal_invoke_guest_entry(void *entry, void *stack,
                                void *tcb_slot, void *arg)
            __attribute__((noreturn));

void     pal_scheduler_register(const void *config);
void     pal_aio_callback_register(void (*cb)(void *, long));
void     pal_aio_callback(void *arg1, long arg2);

#ifdef __cplusplus
}
#endif

#endif /* PAL_THREAD_H */
