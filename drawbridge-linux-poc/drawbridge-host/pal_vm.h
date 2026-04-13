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

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * VM subsystem initializer — populates [0x180c00878] with a
 * VmModuleState so that the PE's consumer at RVA 0x24c3f6 doesn't
 * NULL-deref.
 *
 * Translations:
 *   pal_vm_init_module_state  <-  FUN_0037f700 (ELF 437482..437753)
 *   pal_vm_init_wrapper       <-  FUN_00378c00 (ELF 430096..430099)
 *   pal_vm_compute_head_list  <-  FUN_00379c14 (ELF 431235..431280)
 * ------------------------------------------------------------------ */
VmModuleState *pal_vm_init_module_state(void);
void           pal_vm_init_wrapper(void);
VmModuleState *pal_vm_compute_head_list(VmModuleState *self);

/* ------------------------------------------------------------------
 * Wave-49 — conservative reproduction of FUN_0x37cf68's side-effects:
 *
 *   1) allocate >= 0xE8-byte descriptor from the vms heap
 *   2) populate all 18 fields from FUN_0x37e1f0's table
 *   3) splice descriptor[+0x08] into vms+0x48 LIST_ENTRY, back-pointer
 *      at desc[+0x18] (FUN_0x37d23c)
 *   4) transition desc[+0x74] from 1 -> 2 (FUN_0x37e4c0)
 *
 * Deliberately SKIPS the AVL-tree insert (FUN_0x380708) and the global
 * memory-accounting update (FUN_0x208b0c) — see WAVE48_MASTER_flow.md
 * §Conservative approach.
 *
 * Returns the descriptor pointer, or NULL on error (e.g. vms is NULL).
 * ------------------------------------------------------------------ */
struct VmPeImageDescriptor *
pal_reserve_pe_image_range(VmModuleState *vms,
                           uint64_t pe_base,
                           uint64_t size,
                           uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif /* PAL_VM_H */
