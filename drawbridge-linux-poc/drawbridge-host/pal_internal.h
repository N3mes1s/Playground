/*
 * pal_internal.h — Shared internal declarations for the translated
 * Drawbridge host components.
 *
 * Maps to the decompiled ELF host (analysis/sqlservr_FULL.c):
 *   pal_boot.c    — FUN_002053e0, FUN_00204680, FUN_0020ba60
 *   pal_thread.c  — FUN_001fa9c0, FUN_00252c90, FUN_00252e60,
 *                   FUN_00253350, FUN_002890a0
 *   pal_abi.c     — FUN_00269650, FUN_00284620
 *   pal_io.c      — FUN_001f1c50, FUN_00252b70
 *   pe_init_replicas.c — PE RVA 0x211650, 0x2bcf9c, 0x276b68
 *
 * The central types (ntum_kthread_t, ntum_teb_t, etc.) live in
 * drawbridge_types.h — only PAL-internal glue goes here.
 */

#ifndef PAL_INTERNAL_H
#define PAL_INTERNAL_H

#include <stdint.h>
#include "drawbridge_types.h"
#include "pal_thread.h"    /* C6: thread/fiber public API */
#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * pal_boot.c — to be filled in M2
 * ============================================================ */
/* Source: ELF FUN_00204680 @ analysis/sqlservr_FULL.c:69308 */
int  pal_boot_init(void);

/* Source: ELF FUN_002053e0 @ analysis/sqlservr_FULL.c:69864 */
void pal_init_abi_table(WINDOWS_LIBOS_PARAMETERS *params);

/* Source: ELF FUN_0020ba60 @ analysis/sqlservr_FULL.c:75933 */
void pal_init_libos_params(WINDOWS_LIBOS_PARAMETERS *params);

/* ============================================================
 * pal_thread.c — see pal_thread.h (included above)
 * ============================================================ */

/* ============================================================
 * pal_abi.c — to be filled in M4
 * ============================================================ */
/* Source: ELF FUN_00269650 @ analysis/sqlservr_FULL.c:137747 */
uint64_t pal_abi_dispatch(void *abi_table, uint32_t call_type,
                          uint64_t in_size, void *in_buf,
                          uint64_t out_size, void *out_buf);

/* Source: ELF FUN_00284620 — GetFunction_v2 implementation */
void *pal_abi_get_function_v2(uint32_t function_id, uint32_t version);

/* ============================================================
 * pal_io.c — to be filled in M4
 * ============================================================ */
/* Source: ELF FUN_00252b70 @ analysis/sqlservr_FULL.c:123314 */
int  pal_open_dev_null(void);

/* Source: ELF FUN_001f1c50 @ analysis/sqlservr_FULL.c:52045 */
int  pal_io_create_completion_port(void *out_port);

/* ============================================================
 * pe_init_replicas.c — to be filled in M5
 * ============================================================ */
/* Source: PE RVA 0x211650 — KUSER_SHARED_DATA allocator */
int  pe_replica_kuser_alloc(void);

/* Source: PE RVA 0x2bcf9c — kernel object type registry init */
int  pe_replica_type_registry_init(void);

/* Source: PE RVA 0x276b68 — thread/object initializer */
int  pe_replica_thread_object_init(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* PAL_INTERNAL_H */
