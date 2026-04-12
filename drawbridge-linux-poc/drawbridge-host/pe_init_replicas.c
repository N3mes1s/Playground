/*
 * pe_init_replicas.c — PE-internal init we must pre-execute.
 *
 * Source RVAs (see /tmp/sqlpal_full.txt):
 *   RVA 0x211650  → pe_replica_kuser_alloc
 *   RVA 0x2bcf9c  → pe_replica_type_registry_init
 *   RVA 0x276b68  → pe_replica_thread_object_init
 *
 * Milestone M1: scaffolding only. Code moves here in M5.
 * The current partial replicas (type registry, KUSER page) live in
 * ntum_bootstrap.c and main.c respectively.
 */

#include <stdint.h>
#include "pal_internal.h"

/* TODO(M5): translate the PE-internal init here. */
