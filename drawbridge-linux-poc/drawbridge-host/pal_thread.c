/*
 * pal_thread.c — Translated thread creation & entry thunk.
 *
 * Source functions (see analysis/sqlservr_FULL.c):
 *   FUN_001fa9c0 @ line 61607   → pal_alloc_teb
 *   FUN_00252c90 @ line 123383  → pal_set_thread_gs_base (arch_prctl)
 *   FUN_00252e60 @ line 123466  → pal_thread_create      (alloc KTHREAD)
 *   FUN_00253350 @ line 123665  → pal_thread_entry_thunk (stack/TEB setup)
 *   FUN_002890a0 @ line 156863  → pal_thread_subsystem_init
 *
 * Milestone M1: scaffolding only. Code moves here in M3.
 */

#include <stdint.h>
#include "pal_internal.h"

/* TODO(M3): translate the ELF thread-creation chain here. */
