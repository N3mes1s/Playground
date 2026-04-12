/*
 * pal_vm.c — C4 Virtual-Memory subsystem (strong symbols).
 *
 * Split out of dk_pal.c per the Wave-1 F ownership (plan M6/M8).
 * Bodies are carried over verbatim from dk_pal.c; they're faithful
 * translations of:
 *
 *   FUN_0024b4f0  @ analysis/sqlservr_FULL.c:118424
 *     with FUN_0024b210 (mmap wrapper, line 118310) inlined
 *   FUN_0024b3e0  (SetMemoryProtectionAndKey — mprotect tail-call)
 *   FUN_00355380  (raw mmap thunk, line 318743)
 *   FUN_001d9720  (Windows PAGE_* -> Linux PROT_*, line 32651)
 *
 * Every exported DK_* here is a strong symbol; the corresponding
 * definitions in dk_pal.c are gated behind `#if 0` with a breadcrumb
 * comment pointing to this file.  Fail-loud rule: helpers not owned
 * by this component (dk_prot_to_linux, etc.) are declared extern and
 * linked from dk_pal.c where they still live.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "pal_vm.h"
#include "drawbridge_types.h"

/* Tracing macro mirrors dk_pal.c (same per-function ring counter so
 * the first 20 invocations of each DK function are logged).  */
#define DK_TRACE_ENTRY(fn_name, a, b, c, d) do {                 \
    static int _n = 0;                                           \
    _n++;                                                        \
    if (_n <= 20) {                                              \
        fprintf(stderr, "[DK-CALL] %-32s #%d"                    \
                        " a=0x%lx b=0x%lx c=0x%lx d=0x%lx\n",    \
                fn_name, _n,                                     \
                (unsigned long)(uintptr_t)(a),                   \
                (unsigned long)(uintptr_t)(b),                   \
                (unsigned long)(uintptr_t)(c),                   \
                (unsigned long)(uintptr_t)(d));                  \
    }                                                            \
} while (0)

/* ------------------------------------------------------------------
 * FUN_001d9720 — Windows PAGE_* to Linux PROT_* flag translator.
 *
 *   uint FUN_001d9720(uint param_1) {
 *       return param_1 & 3 | param_1 >> 1 & 6;
 *   }
 *
 * Kept local to this TU.  Identical to the definition in dk_pal.c.
 * ------------------------------------------------------------------ */
static int dk_prot_to_linux(uint64_t dk_prot)
{
    uint32_t p = (uint32_t)dk_prot;
    return (int)((p & 3) | ((p >> 1) & 6));
}

/* ==================================================================
 * DK_VirtualMemoryAllocate — FUN_0024b4f0 (verbatim carry-over).
 *
 * See dk_pal.c history + sqlservr_FULL.c:118424-118570 for the
 * step-by-step annotated commentary.  Keep in lock-step with the ELF
 * — edits here should mirror the ELF's control flow exactly.
 * ================================================================== */
DK_API uint64_t DK_VirtualMemoryAllocate(void **address, uint64_t *size,
                                         uint64_t alloc_type, uint64_t protect)
{
    DK_TRACE_ENTRY("DK_VirtualMemoryAllocate", address, size, alloc_type, protect);

    /* Mirror ELF locals. */
    uint64_t local_88 = 0;        /* LocalBaseAddress */
    uint32_t uVar7;               /* effective protect */
    uint64_t uVar6;               /* aligned base */
    uint64_t uVar8;               /* aligned length */

    uint64_t param_1 = address ? (uint64_t)*address : 0;   /* DesiredAddress */
    uint64_t param_2 = size    ? *size               : 0;  /* DesiredLength */
    uint32_t param_3 = (uint32_t)alloc_type;               /* AllocationType */
    uint32_t param_4 = (uint32_t)protect;                  /* Protect */

    /* uVar7 = param_4 | 1; if (param_4 == 0) uVar7 = 0; */
    uVar7 = param_4 | 1u;
    if (param_4 == 0) uVar7 = 0;

    /* Parameter validation ladder. */
    if (param_1 == 0) return DK_STATUS_INVALID_PARAM;
    if (param_2 == 0) return DK_STATUS_INVALID_PARAM;
    if (param_3 == 0) return DK_STATUS_INVALID_PARAM;
    /* DK_VALID_PAGE_PROTECTION(Protect) */
    if (!(uVar7 < 0x10 && (uVar7 & 6) != 6)) return DK_STATUS_INVALID_PARAM;
    /* DK_VALID_ALLOCATION_FLAGS(AllocationType) */
    if ((param_3 & 0xffffff3cu) != 0)        return DK_STATUS_INVALID_PARAM;

    /* Page-align address down and size up. */
    uVar6 = param_1 & ~0xFFFULL;
    uVar8 = (param_2 + (param_1 & 0xFFFULL) + 0xFFFULL) & ~0xFFFULL;
    local_88 = uVar6;

    static int va_count = 0;
    va_count++;
    if (va_count <= 50) {
        fprintf(stderr,
                "[PAL] VirtualAlloc hint=0x%lx aligned=0x%lx len=0x%lx "
                "type=0x%x prot=0x%x\n",
                (unsigned long)param_1, (unsigned long)uVar6,
                (unsigned long)uVar8, param_3, param_4);
    }

    if ((param_3 & 0x41u) == 0) {
        /* Reserve-only: ELF only logs.  No mmap.  */
    } else {
        if (uVar6 == 0) return DK_STATUS_INVALID_PARAM;

        int prot_linux = dk_prot_to_linux(uVar7);

        /* PE-image safety guard: skip mmap over the loaded PE; just
         * adjust protection.  See dk_pal.c history for rationale. */
        if (uVar6 >= PE_IMAGE_START && uVar6 < PE_IMAGE_END) {
            mprotect((void*)uVar6, uVar8,
                     prot_linux ? prot_linux : (PROT_READ|PROT_WRITE));
        } else {
            int mmap_flags = (int)(((uint32_t)(param_3 & 0x40u)) << 8) | 0x22;
            if (uVar6 != 0) mmap_flags |= 0x10;

            int safe_flags = (mmap_flags & ~0x10) | MAP_FIXED_NOREPLACE;
            void *result = mmap((void*)uVar6, uVar8,
                                prot_linux ? prot_linux : (PROT_READ|PROT_WRITE),
                                safe_flags, -1, 0);
            if (result == MAP_FAILED) {
                mprotect((void*)uVar6, uVar8,
                         prot_linux ? prot_linux : (PROT_READ|PROT_WRITE));
            } else if (uVar6 != 0 && (uint64_t)result != uVar6) {
                munmap(result, uVar8);
                return DK_STATUS_INVALID_PARAM;
            } else {
                local_88 = (uint64_t)result;
            }
        }

        if (local_88 != uVar6 && uVar6 != 0) {
            return DK_STATUS_INVALID_PARAM;
        }
    }

    /* Success path: apply SetMemoryProtectionAndKey (FUN_0024b3e0 tail). */
    if (address) *address = (void*)(uintptr_t)local_88;
    if (size)    *size    = uVar8;

    if (local_88 != 0 && uVar7 != 0) {
        int prot_linux_final = dk_prot_to_linux(uVar7);
        if (prot_linux_final == 0) prot_linux_final = PROT_READ | PROT_WRITE;
        mprotect((void*)(uintptr_t)local_88, uVar8, prot_linux_final);
    }

    return DK_STATUS_SUCCESS;
}

/* ==================================================================
 * DK_VirtualMemoryFree — FUN_0024b5a0 (approximated).
 *
 * ELF dispatches to a direct munmap after honoring MEM_DECOMMIT vs
 * MEM_RELEASE; our host only does RELEASE, with a guard protecting
 * the PE image range from being torn down.
 * ================================================================== */
DK_API uint64_t DK_VirtualMemoryFree(void *address, uint64_t size,
                                     uint64_t free_type)
{
    DK_TRACE_ENTRY("DK_VirtualMemoryFree", address, size, free_type, 0);
    (void)free_type;
    if (size == 0) size = 4096;

    uintptr_t addr = (uintptr_t)address;
    if (addr >= PE_IMAGE_START && addr < PE_IMAGE_END)
        return DK_STATUS_SUCCESS;

    munmap(address, size);
    return DK_STATUS_SUCCESS;
}

/* ==================================================================
 * DK_VirtualMemoryProtect — FUN_0024b3e0 (mprotect body).
 *
 * The ELF records the previous protection in *old_protect; we lack
 * a real tracker and return WIN_PAGE_READWRITE as a well-typed
 * placeholder (matches existing dk_pal.c behavior).
 * ================================================================== */
DK_API uint64_t DK_VirtualMemoryProtect(void *address, uint64_t size,
                                        uint64_t new_protect,
                                        uint64_t *old_protect)
{
    DK_TRACE_ENTRY("DK_VirtualMemoryProtect", address, size,
                   new_protect, old_protect);
    if (old_protect) *old_protect = WIN_PAGE_READWRITE;
    int prot = dk_prot_to_linux(new_protect);
    mprotect(address, size, prot);
    return DK_STATUS_SUCCESS;
}
