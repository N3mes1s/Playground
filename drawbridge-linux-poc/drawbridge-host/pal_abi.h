/*
 * pal_abi.h — public interface for the C3 ABI Dispatcher component.
 *
 * Owned by Agent F (M6).  Publishes strong symbols that supersede the
 * naive versions that used to live in dk_pal.c:
 *
 *   DK_AbiDispatcher    — the wide 6-arg dispatcher installed at
 *                          g_pal_dispatch_table[+8] and reached from
 *                          the NTUM via the Win64 trampoline.
 *   DK_AbiGetFunction   — the narrow 2-arg lookup used by a few
 *                          NTUM callers that carry a raw ABI id.
 *
 * The internal registry translation (FUN_00269650, FUN_002696b0,
 * FUN_00284540/620/590/6d0) lives entirely inside pal_abi.c; only
 * the dispatcher entry-points are exported.
 */

#ifndef PAL_ABI_H
#define PAL_ABI_H

#include <stdint.h>
#include "drawbridge_types.h"

/* Strong symbol: supersedes dk_pal.c's old DK_AbiDispatcher. */
DK_API uint64_t DK_AbiDispatcher(uint64_t context, uint64_t call_type,
                                 uint64_t in_size, void *in_buf,
                                 uint64_t out_size, void *out_buf);

/* Strong symbol: supersedes dk_pal.c's old DK_AbiGetFunction. */
DK_API uint64_t DK_AbiGetFunction(uint64_t abi_id, void **func_ptr);

/* Internal helpers exposed for callers that need direct access to
 * the per-funcId resolver (pal_boot at dispatch-table construction,
 * diagnostics).  Returns NULL if the func_id has no owner. */
void *pal_abi_resolve_funcid(uint32_t func_id, uint32_t version,
                             int *is_real_impl);

/* 6-arg ABI dispatcher hook (keeps FUN_00269650 wrapper interface
 * around — used only by self-tests for the translated wrappers).   */
uint64_t pal_abi_dispatch(void *abi_table, uint32_t call_type,
                          uint64_t in_size, void *in_buf,
                          uint64_t out_size, void *out_buf);

/* FUN_00284620 — GetFunction_v2 body.  Public because the boot
 * orchestrator uses it directly to prime the first-cross handoff. */
void *pal_abi_get_function_v2(uint32_t function_id, uint32_t version);

#endif /* PAL_ABI_H */
