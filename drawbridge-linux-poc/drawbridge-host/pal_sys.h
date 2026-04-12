/*
 * pal_sys.h — Public interface for component C10
 * (Time / Random / SysInfo / ProcessId).
 *
 * Source functions in analysis/sqlservr_FULL.c:
 *   FUN_00202100 @ 67430 — syscall-wrapper family (maps to clock
 *                          gettime in the time-query branch exercised
 *                          by DK_SystemTimeQuery).
 *   FUN_003539f0 @ 314242 — getpid thunk (dispatches via FUN_003533e0).
 *   DK_* API defined by drawbridge_types.h / dk_pal.h.
 *
 * The four pal_sys_* functions below are the canonical translations.
 * They are defined as strong symbols in pal_sys.c.  The DK_* wrappers
 * in dk_pal.c are kept for compatibility (strong there); pal_sys.c
 * additionally provides weak DK_* aliases routed through pal_sys_*
 * so future plans that drop dk_pal.c from the build transparently
 * continue to work.
 */

#ifndef PAL_SYS_H
#define PAL_SYS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DK_SystemTimeQuery body — clock_gettime → FILETIME (100ns since 1601).
 *   clock_type == 0 → CLOCK_REALTIME (Windows KeQuerySystemTime)
 *   clock_type != 0 → CLOCK_MONOTONIC (interrupt-time-like).
 * Returns 0 on success.  Writes *out_filetime on success. */
int pal_sys_time_query(uint64_t clock_type, uint64_t *out_filetime);

/* DK_RandomBitsRead body — getrandom(2).  Returns 0 if length bytes
 * were produced, -1 on short read or error. */
int pal_sys_random_read(void *buffer, uint64_t length);

/* DK_SystemInfoQuery body — populates a SYSTEM_INFO-shaped buffer
 * using sysconf + /proc/meminfo.  Returns 0. */
int pal_sys_info_query(uint64_t info_class, void *buffer,
                       uint64_t buffer_size, uint64_t *out_result_size);

/* FUN_003539f0 — getpid(2). */
uint64_t pal_sys_process_get_id(void);

#ifdef __cplusplus
}
#endif

#endif /* PAL_SYS_H */
