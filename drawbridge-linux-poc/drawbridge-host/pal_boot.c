/*
 * pal_boot.c — Translated PAL boot sequence from decompiled ELF host.
 *
 * Source functions (see analysis/sqlservr_FULL.c):
 *   FUN_002053e0 @ line 69864  → pal_init_abi_table
 *   FUN_00204680 @ line 69308  → pal_boot_init   (22-step PAL boot)
 *   FUN_0020ba60 @ line 75933  → pal_init_libos_params
 *
 * Milestone M1: scaffolding only. Code moves here in M2.
 * No behavior change vs. current bootstrap.
 */

#include <stdint.h>
#include "pal_internal.h"

/* TODO(M2): translate FUN_00204680 here.
 * Current implementation lives inline in ntum_bootstrap.c. */
