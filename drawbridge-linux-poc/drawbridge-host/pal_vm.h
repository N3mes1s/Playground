/*
 * pal_vm.h — public interface for the C4 Virtual-Memory component.
 *
 * Owned by Agent F (M8).  Declares the strong symbols that supersede
 * the original definitions in dk_pal.c for the VM triplet
 * (allocate / free / protect).
 *
 * The bodies translate:
 *   FUN_0024b4f0  @ sqlservr_FULL.c:118424  -> DK_VirtualMemoryAllocate
 *   (FUN_0024b210 inlined wrapper around mmap)
 *   FUN_0024b3e0  @ sqlservr_FULL.c        -> mprotect tail-call helper
 *   FUN_00355380  @ sqlservr_FULL.c:318743 -> raw mmap syscall thunk
 *   FUN_001d9720  @ sqlservr_FULL.c:32651  -> Windows PAGE_* -> PROT_*
 */

#ifndef PAL_VM_H
#define PAL_VM_H

#include <stdint.h>
#include "drawbridge_types.h"

DK_API uint64_t DK_VirtualMemoryAllocate(void **address, uint64_t *size,
                                         uint64_t alloc_type,
                                         uint64_t protect);

DK_API uint64_t DK_VirtualMemoryFree(void *address, uint64_t size,
                                     uint64_t free_type);

DK_API uint64_t DK_VirtualMemoryProtect(void *address, uint64_t size,
                                        uint64_t new_protect,
                                        uint64_t *old_protect);

#endif /* PAL_VM_H */
