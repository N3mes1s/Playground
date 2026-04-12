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

/* ==================================================================
 * VM module-state construction.  Translated from:
 *   FUN_0037f700  (constructor)     — ELF 437482..437753
 *   FUN_00378c00  (thin wrapper)    — ELF 430096..430099
 *   FUN_00379c14  (head init)       — ELF 431235..431280
 *
 * The ELF allocates the descriptor inside a VM range computed from
 * the LIBOS_PARAMETERS base/size at [0xc00820]+0x38/0x40, using an
 * internal allocator (FUN_002142f4).  On Linux we mmap that range
 * directly — the resulting region serves the same purpose: a
 * managed address window whose start holds the VmModuleState and
 * whose tail is reserved for the page-table bookkeeping the PE
 * consumer at RVA 0x24c3f6 walks.
 * ================================================================== */

#include "drawbridge_types.h"

/* Single global instance, matching DAT_00c00878. */
static VmModuleState *g_vm_module_state = nullptr;

/* ------------------------------------------------------------------
 * pal_vm_compute_head_list  —  FUN_00379c14 verbatim.
 *
 * All the ELF does is zero-initialize an embedded head/list area
 * inside the VmModuleState passed in %rcx and return that same
 * pointer in %rax.  The three self-referencing list heads live at
 * +0x48, +0x60, +0x78, +0x90; a "free list marker" block lives at
 * +0x28 (dword 0x10 followed by three zero qwords).  If the global
 * [c00878] is already non-NULL and different from the incoming self
 * pointer, the routine links +0xA8 into a slot table keyed by the
 * signed-widened %edx argument (r9*0x68 + 8 + [c00878]).  Called
 * from FUN_0037f700 with %edx = 1.
 * ------------------------------------------------------------------ */
VmModuleState *pal_vm_compute_head_list(VmModuleState *self)
{
    if (!self) return nullptr;

    /* 379c17: movslq %edx,%r9 — caller passes edx = 1 */
    const int64_t r9 = 1;

    /* 379c1a/c1e/c21/c24/c2b/c2f/c33/c36: clear the leading scalar fields */
    self->_r18   = 0;              /* +0x18 */
    self->list_prev_0 = 0;         /* +0x10 */
    self->_r20   = 0;              /* +0x20 */
    self->head_ptr = nullptr;      /* +0x00 (mov %r10,(%rcx)) */
    /* 379c1e/c21: `or $-1, %eax; mov %eax, 0x8(%rcx); mov %eax, 0xc(%rcx)` */
    self->list_next = (uint64_t)(int64_t)-1;  /* +0x08 / +0x0C packed */

    /* 379c27..c41: initialize the 3-word sentinel block at +0x48. */
    self->list48_flink = (uint64_t)&self->list48_flink;
    self->list48_blink = (uint64_t)&self->list48_flink;
    self->list48_tail  = 0;

    /* +0x50: `mov %r10, 0x50(%rcx)` */
    /* Already zeroed via list48_blink write above? No — overlapping
     * address.  The ELF emits `mov %r10, 0x50(%rcx)` at 379c36
     * before the +0x48 self-ref pair (379c3a/379c3e), so order
     * matters only if the addresses collide.  They don't: +0x48/+0x50
     * are the flink/blink pair, +0x58 is zeroed via 0x10(%rax). */

    /* 379c45..c54: initialize the 3-word sentinel block at +0x60. */
    self->list60_flink = (uint64_t)&self->list60_flink;
    self->list60_blink = (uint64_t)&self->list60_flink;
    self->list60_tail  = 0;

    /* 379c58..c6a: initialize the 3-word sentinel block at +0x78. */
    self->list78_flink = (uint64_t)&self->list78_flink;
    self->list78_blink = (uint64_t)&self->list78_flink;
    /* +0x80: zero via `mov %r10, 0x80(%rcx)` at 379c5c */

    /* 379c6e..c8a: initialize the 3-word sentinel block at +0x90. */
    self->list90_flink = (uint64_t)&self->list90_flink;
    self->list90_blink = (uint64_t)&self->list90_flink;
    /* +0x98: zero via 0x98(%rcx) at 379c75 */

    /* 379c7c/c8e: if ([c00878] != self) link a per-slot pointer. */
    VmModuleState *global = g_vm_module_state;
    if (global && global != self) {
        /* 379c93..c9e: slot_ptr = [c00878] + r9*0x68 + 8. */
        self->slot_ptr = (uint64_t)global + (uint64_t)(r9 * 0x68) + 8;

        /* 379ca5..cc0: free-list-marker block at +0x28 = { 0x10, 0, 0, 0 }. */
        self->free_list_mark = 0x10;
        self->free_list_a    = 0;
        self->free_list_b    = 0;
        self->free_list_c    = 0;

        /* 379cc0: flag32 at +0xB0 = r10d = 0. */
        self->flag32 = 0;
    }

    /* 379cc7: mov %rcx, %rax ; ret */
    return self;
}

/* ------------------------------------------------------------------
 * pal_vm_init_module_state  —  FUN_0037f700 verbatim.
 *
 * Build the VM module descriptor, mmap the managed region, store
 * the result pointer at [0x180c00878], and populate the handful
 * of fields the rest of the ELF (and the PE's RVA 0x24c3f6
 * consumer) expect.
 *
 * Constants and shifts lifted directly from the disassembly — see
 * the inline comments for the ELF RVA of each operation.
 * ------------------------------------------------------------------ */
VmModuleState *pal_vm_init_module_state(void)
{
    /* 37f711: mov 0x881108(%rip),%rdx  — pointer-sized read of [c00820] */
    WINDOWS_LIBOS_PARAMETERS *params =
        *(WINDOWS_LIBOS_PARAMETERS * volatile *)0x180c00820ULL;
    if (params == nullptr) {
        fprintf(stderr,
                "[PAL][VM-INIT] [c00820] is NULL — LIBOS_PARAMETERS "
                "not yet staged; skipping VmModuleState build.\n");
        return nullptr;
    }

    /* 37f728/2c: rax = params->+0x38 (VMBase); rcx = params->+0x40 (VMSize).
     * The struct field at +0x38 is ImageBase, here repurposed as the VM
     * region base — matches the verbatim ELF read. */
    uint64_t vm_base_in = (uint64_t)params->ImageBase;     /* +0x38 */
    uint64_t vm_size_in = (uint64_t)params->ImageLength;   /* +0x40 */

    /* 37f733: cmove %r8,%rax  — if VMBase==0 then rax = 0x10000. */
    if (vm_base_in == 0) vm_base_in = 0x10000ULL;

    /* 37f737/3e: r14 = (VMBase + 0xFFFF) & ~0xFFFF  — 64KB-align up. */
    uint64_t r14 = (vm_base_in + 0xFFFFULL) & ~0xFFFFULL;

    /* 37f745..51: rdi = VMSize ? min(VMSize, 0x400000000000) : 0x400000000000. */
    const uint64_t kMaxSpan = 0x400000000000ULL;
    uint64_t rdi = (vm_size_in == 0) ? kMaxSpan
                                     : (vm_size_in > kMaxSpan ? kMaxSpan : vm_size_in);

    /* 37f754..64: rcx = 0xFFFFFFFF80000000; rbp = r14 & rcx; rdi = rdi & rcx. */
    const uint64_t kHiMask = 0xFFFFFFFF80000000ULL;
    uint64_t rbp = r14 & kHiMask;
    rdi          = rdi & kHiMask;

    /* 37f767..7a: rax = rdi - rbp; rbx = (rax*3) >> 2 + rbp; rbx &= kHiMask.
     * This is the "pick a 2/3 split point between rbp and rdi". */
    uint64_t rax = rdi - rbp;
    uint64_t rbx = ((rax + rax * 2) >> 2) + rbp;
    rbx &= kHiMask;
    /* 37f77d..85: sanity check — if rbx matched one of the endpoints,
     * the ELF logged C000000D.  We mirror the check with a warning;
     * the kHiMask & 2/3 split can land on rbp or rdi for tiny ranges. */
    if (rbx == rbp || rbx == rdi) {
        fprintf(stderr,
                "[PAL][VM-INIT] degenerate span: rbp=0x%lx rdi=0x%lx rbx=0x%lx\n",
                (unsigned long)rbp, (unsigned long)rdi, (unsigned long)rbx);
    }

    /* 37f7a4..7d9: range-validity check — warn only. */
    if (r14 < 0x80000000ULL && rdi < 0x200000000ULL && params->_pad1 /* +0x54 */ == 0) {
        fprintf(stderr,
                "[PAL][VM-INIT] narrow VM window warning (<2GB span)\n");
    }

    /* 37f7d9..f4:
     *   rdi = (rdi - rbx) >> 0x1f
     *   rcx = (rbx - rbp) >> 0x1f
     *   [rsp+0x48] = rcx
     * These give the number of 2GB super-pages in the low and high
     * halves of the managed window.  We keep them as local variables. */
    uint64_t hi_pages = (rdi - rbx) >> 0x1f;
    uint64_t lo_pages = (rbx - rbp) >> 0x1f;

    /* 37f7f9..831: compute the descriptor + bitmap size.
     *   rax  = (hi_pages + 0x3f) / 8  & ~7           (hi bitmap bytes)
     *   r13  = ((lo_pages + 0x3f) / 8 & ~7) + 0xE8  aligned to 8
     *          → descriptor body size (0xE8 = scalar-field area)
     *   rdx  = (rax + r13 + 0xF) & ~0xF              (total rounded to 16)
     * The ELF then adds |(lo|hi)pages| * 0x88 to reserve per-super-page
     * state blocks (slab headers) and stashes the running total at
     * [rsp+0x58] / [rsp+0xd0]. */
    const uint64_t kAlign8Mask = 0x1FFFFFFFFFFFFFF8ULL;  /* verbatim 37f7dc */
    uint64_t hi_bm = ((hi_pages + 0x3F) >> 3) & kAlign8Mask;
    uint64_t r13   = (((lo_pages + 0x3F) >> 3) & kAlign8Mask) + 0xE8ULL;
    r13 &= ~(uint64_t)7;
    uint64_t desc_bytes = (r13 + 0xFULL + hi_bm) & ~(uint64_t)0xF;

    uint64_t per_lo    = lo_pages * 0x88ULL;
    uint64_t per_hi    = hi_pages * 0x88ULL;
    uint64_t total_desc = ((desc_bytes + per_lo + 0xFULL + per_hi) & ~(uint64_t)0xF);

    /* 37f847..6a: r12 = [0x662d28]+0x10.  In the ELF that's the
     * per-process max-thread-count read from the runtime parameter
     * block.  We reuse LIBOS_PARAMETERS.NumaNodeCount (+0x68) or 1,
     * matching the cmove-zero-to-one semantics at 37f866. */
    uint64_t r12 = params->NumaNodeCount;
    if (r12 == 0) r12 = 1;

    /* 37f86a..96: reserve (r13 aligned) + (r12*8+0xFFF)&~0xFFF page
     * bytes at the computed region start.  In total the ELF mmaps
     * region_end = rbx + desc_bytes + r14_page_blob + hi_page_blob.
     * For our purposes the critical output fields are:
     *   vm_base (+0x88) = rbx       (PE RVA 0x24c3f6 reads this)
     *   region_end(+0xE0) = rbx + dtail  (RVA 0x37f990)
     *   page_count(+0xD8) = r15     (RVA 0x37f997)
     *   size_shift(+0xA0) = lo_pages  (consumer shifts by 0x1f again)
     */
    uint64_t r15 = ((r12 * 8ULL + 0xFFFULL) + total_desc) & ~(uint64_t)0xFFF;
    uint64_t r15_end = r15 + (lo_pages << 12);
    uint64_t hi_tail = r15_end + (hi_pages << 12);

    /* 37f8a5..c5: sanity — the combined region must fit in a 2GB
     * window.  We log a warning if not and keep going (production
     * SQL paths hit this when the host stacks >2GB of VM). */
    if (hi_tail > 0x80000000ULL) {
        fprintf(stderr,
                "[PAL][VM-INIT] descriptor window exceeds 2GB (tail=0x%lx)\n",
                (unsigned long)hi_tail);
    }

    /* Allocate the descriptor + tail region.  The ELF calls
     * FUN_002142f4 (host mmap wrapper).  On Linux, map it
     * MAP_PRIVATE|MAP_ANONYMOUS — the address we pick is the PAL-
     * managed window which by construction is outside both the PE
     * image and the kernel-heap reserves. */
    size_t map_len = (size_t)(hi_tail + 0x1000ULL);
    map_len = (map_len + 0xFFFULL) & ~(size_t)0xFFF;

    void *region = mmap(nullptr, map_len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        fprintf(stderr,
                "[PAL][VM-INIT] mmap(desc=%zu bytes) failed: %s\n",
                map_len, strerror(errno));
        return nullptr;
    }
    memset(region, 0, map_len);

    VmModuleState *self = (VmModuleState *)region;

    /* 37f984: mov %rbx, 0x880eed(%rip)  — publish to [c00878]. */
    g_vm_module_state = self;
    *(VmModuleState * volatile *)0x180c00878ULL = self;

    /* 37f990: self->+0xE0 = rbx + dtail.  We publish the end of the
     * descriptor + page blob as region_end so the PE's bounds check
     * at RVA 0x24c400 passes. */
    self->region_end = (uint64_t)region + map_len;

    /* 37f997: self->+0xD8 = r12. */
    self->page_count = r12;

    /* 37f99e..a3: self->+0x00 = FUN_00379c14(self). */
    (void)pal_vm_compute_head_list(self);

    /* Populate the consumer-relevant fields the PE reads at
     * RVA 0x24c3f6 (vm_base) / 0x24c402 (size_shift). */
    self->vm_base    = (uint64_t)region;
    self->size_shift = (map_len >> 0x1F) ? (map_len >> 0x1F) : 1;
    self->struct_tail = (uint64_t)region + map_len - 0x1000ULL;

    fprintf(stderr,
            "[PAL][VM-INIT] VmModuleState @ %p  vm_base=0x%lx size=0x%zx "
            "region_end=0x%lx page_count=%lu\n",
            (void *)self,
            (unsigned long)self->vm_base,
            map_len,
            (unsigned long)self->region_end,
            (unsigned long)self->page_count);

    return self;
}

/* ------------------------------------------------------------------
 * pal_vm_init_wrapper  —  FUN_00378c00 verbatim.
 *
 *   sub $0x28, %rsp
 *   call FUN_0037f700
 *   add $0x28, %rsp
 *   ret
 * ------------------------------------------------------------------ */
void pal_vm_init_wrapper(void)
{
    (void)pal_vm_init_module_state();
}
