/*
 * NTUM Bootstrap - Initialize and call the Drawbridge NTUM kernel
 *
 * Based on reverse engineering of sqlservr's boot sequence.
 * Sets up WINDOWS_LIBOS_PARAMETERS and calls sqlpal.dll entry.
 *
 * All structures and constants are defined in drawbridge_types.h.
 */

#ifndef NTUM_BOOTSTRAP_H
#define NTUM_BOOTSTRAP_H

#include "drawbridge_types.h"

/*
 * Initialize the bootstrap parameters.
 *
 * Fills WINDOWS_LIBOS_PARAMETERS based on the decompiled
 * FUN_0020ba60 initialization sequence:
 *   params->Size            = 0x90
 *   params->SubHeaderSize   = 0x38
 *   params->HostAbiTable    = pal_table
 *   params->ImageBase       = image_base
 *   params->ImageLength     = image_size
 *   params->BootEntryPoint  = image_base + entry_rva
 *
 * Also writes NTUM .data globals:
 *   [NTUM_BOOT_FLAG_ADDR]      = 1
 *   [NTUM_ABI_DISPATCHER_ADDR] = DK_AbiDispatcher
 *   [NTUM_PARAMS_ADDR]         = params
 *
 * @param params       Output: filled WINDOWS_LIBOS_PARAMETERS
 * @param image_base   Mapped base address of sqlpal.dll
 * @param image_size   Size of the mapped PE image
 * @param entry_rva    RVA of the DllMain/StartModule entry
 * @param pal_table    PAL function dispatch table
 */
void ntum_bootstrap_init(WINDOWS_LIBOS_PARAMETERS *params,
                          void *image_base, uint64_t image_size,
                          uint64_t entry_rva, void *pal_table);

/*
 * Launch the NTUM boot thread.
 *
 * Creates a new thread with a fresh stack at BOOT_STACK_ADDR,
 * switches to Windows x64 calling convention (ms_abi),
 * and jumps to the BootEntryPoint.
 *
 * The boot thread sets up:
 *   - Security cookie at NTUM_COOKIE_ADDR
 *   - TEB with self-pointer at TEB_SELF_OFFSET
 *   - GS base register via arch_prctl(ARCH_SET_GS)
 *   - Pre-faults all PE pages
 *
 * @param params   Filled WINDOWS_LIBOS_PARAMETERS
 * @return         0 on success, -1 on failure
 */
int ntum_bootstrap_launch(WINDOWS_LIBOS_PARAMETERS *params);

/*
 * The trampoline function that switches ABI and enters the NTUM.
 * Implemented in trampoline.S.
 *
 * Converts from Linux SysV ABI to Windows x64:
 *   - Moves args from rdi/rsi to rcx/rdx
 *   - Sets up fresh stack in LibOS space
 *   - Jumps to StartModule entry
 */
void ntum_trampoline(void *entry_point, void *stack_ptr,
                     void *param1, void *param2);

#endif /* NTUM_BOOTSTRAP_H */
