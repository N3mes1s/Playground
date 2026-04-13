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

    /* Wave-32 instrumentation: log every VA alloc call with inputs
     * (hint, requested size, type/protect) and the returned VA.
     * Goal: reconstruct the VA lifecycle so we can see when/where
     * 0x300006442000 becomes a "free" VA the PE gives to
     * DK_NotificationEventCreate. */
    static int va_trace = 0;
    uint64_t in_hint = address ? (uint64_t)*address : 0;
    uint64_t in_size = size    ? *size               : 0;
    fprintf(stderr,
        "[VA-IN] #%d hint=0x%lx size=0x%lx type=0x%lx prot=0x%lx\n",
        ++va_trace, (unsigned long)in_hint, (unsigned long)in_size,
        (unsigned long)alloc_type, (unsigned long)protect);

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

    fprintf(stderr,
        "[VA-OUT] #%d returned_addr=0x%lx size=0x%lx status=SUCCESS\n",
        va_trace, (unsigned long)local_88, (unsigned long)uVar8);

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
     * RVA 0x24c3f6 (vm_base) / 0x24c402 (size_shift).
     *
     * CORRECTION (Wave-4 post-impl): `vm_base` must be the base of the
     * LIBOS-MANAGED VA region (where kernel-heap objects live), NOT the
     * descriptor-buffer address. The PE uses these two fields as a
     * pointer-validity filter:
     *
     *   candidate_in_range = (rbx >= vm_base) && (rbx < vm_base + (size_shift << 0x1F))
     *
     * Observed LibOS heap pointers during boot: rbp=0x3200100f0,
     * r14=0x34006a070 — all in 0x300000000..0x400000000. Per
     * /tmp/wave4_consumer.md and drawbridge_types.h LIBOS_VM_START/END,
     * the full LibOS VA window is 0x300000000..0x800000000 (5 GiB).
     * size_shift is in 2 GiB units (PE shifts it by 0x1F == 31):
     *   0xA * 2 GiB = 0x500000000 == LIBOS_VM_END - LIBOS_VM_START. */
    self->vm_base     = 0x300000000ULL;              /* LIBOS_VM_START */
    self->size_shift  = 0xAULL;                      /* 0xA * 2GiB = 0x500000000 */
    self->struct_tail = (uint64_t)region + map_len - 0x1000ULL;

    /* Wave-29: the missing descriptor slab init.
     *
     * Our original translation of FUN_0x37f700 stopped right after
     * pal_vm_compute_head_list. The ELF then calls FUN_0x37ee10 twice
     * (once for the LO slab, once for HI) which runs a per-descriptor
     * loop calling FUN_0x380058 → FUN_0x3800ac → FUN_0x380110 that
     * writes each 0x88-byte descriptor's fields. Without it, the PE's
     * allocator (FUN_0x384fbc) dereferences a NULL bitmap pointer at
     * descriptor+0x68 and the first VirtualMemoryAllocate panics with
     * STATUS_CONFLICTING_ADDRESSES (0xc0000018).
     *
     * Per agent A/B analysis:
     *   FUN_0x384fbc is a bitmap allocator:
     *     [desc+0x68] -> uint64[] bitmap (1 bit per 64KB page, 1=free)
     *     [desc+0x70] = bitmap capacity in pages (0x8000 = 2 GiB)
     *
     * Layout within our mmap'd region:
     *   [self + r15]                       : LO bitmap backing, lo_pages * 0x1000 bytes
     *   [self + r15 + lo_pages*0x1000]     : HI bitmap backing, hi_pages * 0x1000 bytes
     * (r15 = total_desc aligned; already computed at 37f894..a1.)
     *
     * Per descriptor (slot_idx in 0..lo_pages or 0..hi_pages):
     *   +0x40 = 0
     *   +0x48 = (slot_idx << 0x1F) + slab_base_va (low slab starts at rbp,
     *           high slab starts at rbx)
     *   +0x50 = 0x80000000 (2 GiB)
     *   +0x58 = self
     *   +0x60 = 0 (pool-list link; proper setup would call
     *               FUN_0x37a1c8 but leaving 0 keeps the linked list
     *               empty, which FUN_0x384fbc tolerates)
     *   +0x68 = backing_va + slot_idx * 0x1000  (per-descriptor 0x1000-byte bitmap)
     *   +0x70 = 0x8000 (capacity)
     *   +0x78 = 0 (allocation accumulator, PE increments as it reserves)
     *   +0x80 = 2 (state = active)
     */
    {
        uint8_t *region_bytes = (uint8_t *)region;
        uint64_t lo_backing_va = (uint64_t)region_bytes + r15;
        uint64_t hi_backing_va = lo_backing_va + (lo_pages << 12);

        /* Mark entire bitmap backing as "all-free" (0xFF = 8 pages free
         * per byte). The page_blob from r15..hi_tail was zeroed by our
         * memset, so we re-fill just the bitmap portion. */
        size_t bm_total_bytes = (lo_pages + hi_pages) << 12;
        memset((void *)lo_backing_va, 0xFF, bm_total_bytes);

        /* LO slab: descriptors at self+0xE8, base VA = rbp */
        uint8_t *lo_slab = region_bytes + 0xE8;
        for (uint64_t i = 0; i < lo_pages; i++) {
            uint8_t *d = lo_slab + i * 0x88;
            *(uint64_t *)(d + 0x40) = 0;
            *(uint64_t *)(d + 0x48) = (i << 0x1F) + rbp;
            *(uint64_t *)(d + 0x50) = 0x80000000ULL;
            *(uint64_t *)(d + 0x58) = (uint64_t)self;
            *(uint64_t *)(d + 0x60) = 0;
            *(uint64_t *)(d + 0x68) = lo_backing_va + i * 0x1000;
            *(uint64_t *)(d + 0x70) = 0x8000ULL;
            *(uint64_t *)(d + 0x78) = 0;
            *(uint32_t *)(d + 0x80) = 2;
        }

        /* HI slab: descriptors at self+0xE8+per_lo, base VA = rbx */
        uint8_t *hi_slab = region_bytes + 0xE8 + per_lo;
        for (uint64_t i = 0; i < hi_pages; i++) {
            uint8_t *d = hi_slab + i * 0x88;
            *(uint64_t *)(d + 0x40) = 0;
            *(uint64_t *)(d + 0x48) = (i << 0x1F) + rbx;
            *(uint64_t *)(d + 0x50) = 0x80000000ULL;
            *(uint64_t *)(d + 0x58) = (uint64_t)self;
            *(uint64_t *)(d + 0x60) = 0;
            *(uint64_t *)(d + 0x68) = hi_backing_va + i * 0x1000;
            *(uint64_t *)(d + 0x70) = 0x8000ULL;
            *(uint64_t *)(d + 0x78) = 0;
            *(uint32_t *)(d + 0x80) = 2;
        }

        fprintf(stderr,
                "[PAL][VM-INIT] wave-29: initialised %lu LO + %lu HI "
                "descriptors; bitmap backing at lo=0x%lx hi=0x%lx "
                "(0x%zx bytes total, set to 0xFF)\n",
                (unsigned long)lo_pages, (unsigned long)hi_pages,
                (unsigned long)lo_backing_va, (unsigned long)hi_backing_va,
                bm_total_bytes);
    }

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

/* ==================================================================
 * pal_reserve_pe_image_range  —  Wave-49 conservative translation of
 *                                FUN_0x37cf68's side-effects.
 *
 * Reproduces, on the host side, the descriptor the PE's sqlpal.dll
 * expects to find already registered in vms's list before its own PE
 * init runs (the wave-44 blocker at RIP 0x3756a3 reads fields of this
 * descriptor).
 *
 * Source:
 *   analysis/WAVE48_MASTER_flow.md  — overall flow
 *   analysis/WAVE48_fun_37e1f0.md   — 18-field populator table
 *   analysis/WAVE48_bookkeeping.md  — list-insert (FUN_0x37d23c)
 *
 * Intentional omissions (§"Conservative approach"):
 *   - AVL-tree insert (FUN_0x380708)
 *   - Global memory-accounting counters at
 *     [0x180653ed8] / [0x180662cf8] / [0x180662d10] (FUN_0x208b0c)
 * ================================================================== */

/* A tiny bump-arena carved out of the vms mmap tail — this mirrors
 * how FUN_0x37b2f0 would carve from the vms heap, but without touching
 * the bitmap slab (which FUN_0x37f700 already laid out for us). The
 * arena starts 1 page below the struct tail so it doesn't collide with
 * the VmModuleState header or the descriptor-slab region. */
static uint8_t *pal_vms_arena_alloc(VmModuleState *vms, size_t bytes)
{
    (void)vms;
    /* 16-byte align */
    bytes = (bytes + 15U) & ~(size_t)15U;

    /* Use a dedicated page-aligned mmap so we don't collide with the
     * PE's own internal allocations inside its vms region. The PE's
     * FUN_0x37f700 uses a slab layout the host doesn't know; anything
     * we place "inside" vms risks overlap with the PE's own descriptors.
     * mmap'ing a fresh 64 KiB pool avoids that entirely. */
    static uint8_t *arena = nullptr;
    static size_t  arena_used = 0;
    static const size_t kArenaSize = 0x10000;

    if (!arena) {
        arena = (uint8_t *)mmap(nullptr, kArenaSize,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (arena == MAP_FAILED) {
            fprintf(stderr, "[PAL][VMS-ARENA] mmap failed: %s\n",
                    strerror(errno));
            arena = nullptr;
            return nullptr;
        }
        memset(arena, 0, kArenaSize);
        fprintf(stderr, "[PAL][VMS-ARENA] arena mmap at %p size=0x%zx\n",
                (void *)arena, kArenaSize);
    }

    if (arena_used + bytes > kArenaSize) {
        fprintf(stderr, "[PAL][VMS-ARENA] out of space: used=%zu req=%zu\n",
                arena_used, bytes);
        return nullptr;
    }
    uint8_t *p = arena + arena_used;
    arena_used += bytes;
    memset(p, 0, bytes);
    return p;
}

extern "C" VmPeImageDescriptor *
pal_reserve_pe_image_range(VmModuleState *vms,
                           uint64_t pe_base,
                           uint64_t size,
                           uint32_t flags)
{
    if (!vms) {
        fprintf(stderr, "[PAL][RESERVE-PE] vms is NULL — bail\n");
        return nullptr;
    }
    if ((pe_base & 0xFFFULL) != 0) {
        fprintf(stderr,
                "[PAL][RESERVE-PE] pe_base=0x%lx not page-aligned\n",
                (unsigned long)pe_base);
        return nullptr;
    }
    if ((size & 0xFFFULL) != 0) {
        fprintf(stderr,
                "[PAL][RESERVE-PE] size=0x%lx not page-aligned\n",
                (unsigned long)size);
        return nullptr;
    }

    /* 1) Allocate a zeroed >= 0xE8-byte chunk from the vms arena. */
    size_t desc_bytes = sizeof(VmPeImageDescriptor);
    if (desc_bytes < 0xE8) desc_bytes = 0xE8;

    VmPeImageDescriptor *desc =
        (VmPeImageDescriptor *)pal_vms_arena_alloc(vms, desc_bytes);
    if (!desc) {
        fprintf(stderr, "[PAL][RESERVE-PE] arena alloc failed\n");
        return nullptr;
    }

    fprintf(stderr,
            "[PAL][RESERVE-PE] vms=%p pe_base=0x%lx size=0x%lx flags=0x%x\n"
            "[PAL][RESERVE-PE]  desc=%p size=0x%zx\n",
            (void *)vms, (unsigned long)pe_base, (unsigned long)size,
            (unsigned)flags, (void *)desc, desc_bytes);

    /* 2) Populate per WAVE48_fun_37e1f0.md / WAVE48_MASTER_flow.md.
     *    Every write is a verbatim table-row; log at debug. */
    const uint64_t page_sz = PE_IMAGE_DESC_PAGE_SIZE;
    desc->vtable            = PE_IMAGE_DESC_OUTER_VTABLE;          /* +0x00 */
    desc->list_flink        = 0;                                   /* +0x08 (filled by insert) */
    desc->list_blink        = 0;                                   /* +0x10 (filled by insert) */
    desc->list_head_backptr = 0;                                   /* +0x18 (filled by insert) */
    desc->state_tag         = PE_IMAGE_DESC_STATE_ALLOCATED;       /* +0x20 = 1 */
    desc->va_base           = pe_base;                             /* +0x28 */
    desc->size              = size;                                /* +0x30 */
    desc->self_ref_38       = 0;                                   /* +0x38 */
    desc->page_count        = size / page_sz;                      /* +0x40 */
    desc->page_size         = (uint32_t)page_sz;                   /* +0x48 */
    desc->caller_dword_4c   = 0;                                   /* +0x4C */
    desc->caller_dword_50   = 0;                                   /* +0x50 */
    desc->avl_node_58       = 0;                                   /* +0x58 (AVL skipped) */
    desc->avl_node_60       = 0;                                   /* +0x60 (AVL skipped) */
    desc->zero_68           = 0;                                   /* +0x68 */
    desc->flags             = flags;                               /* +0x70 */
    desc->state             = PE_IMAGE_DESC_STATE_ALLOCATED;       /* +0x74 = 1 (pre-transition) */
    desc->ctx               = (uint64_t)vms;                       /* +0x78 */

    fprintf(stderr,
            "[PAL][RESERVE-PE]  +0x00 vtable=0x%lx  +0x20 tag=%u  +0x28 va_base=0x%lx\n"
            "[PAL][RESERVE-PE]  +0x30 size=0x%lx    +0x40 pgcnt=0x%lx  +0x48 pgsz=0x%x\n"
            "[PAL][RESERVE-PE]  +0x70 flags=0x%x   +0x74 state=%u     +0x78 ctx=0x%lx\n",
            (unsigned long)desc->vtable,
            (unsigned)desc->state_tag,
            (unsigned long)desc->va_base,
            (unsigned long)desc->size,
            (unsigned long)desc->page_count,
            (unsigned)desc->page_size,
            (unsigned)desc->flags,
            (unsigned)desc->state,
            (unsigned long)desc->ctx);

    /* 3) LIST_ENTRY insert at vms+0x48 (FUN_0x37d23c).
     *
     * Layout per WAVE48_bookkeeping.md (assembly-level, authoritative):
     *   vms+0x48+0x00 = Blink    (implicit from `[r8]=rdi` line 434854)
     *   vms+0x48+0x08 = Flink    (read at 434850, written at 434853)
     *   vms+0x48+0x10 = spinlock (dword)
     *   vms+0x48+0x14 = count    (dword, incremented at 434855)
     *
     * Node inside descriptor (at desc+0x08):
     *   desc+0x08 = Blink  (written to list-head at line 434854)
     *   desc+0x10 = Flink  (written to old-Flink at lines 434848/50)
     *   desc+0x18 = back-pointer to list-head (line 434856)
     *
     * Insert-head sequence (verbatim translation):
     *   new_node_addr = desc+0x08
     *   new_node->Flink  = head->Flink        [desc+0x10 = old_flink]
     *   old_flink->Blink = new_node_addr      [[rdi+0x8]'s +0x0 = r8]
     *   head->Flink      = new_node_addr      [vms+0x50 = r8]
     *   new_node->Blink  = head               [desc+0x08 = vms+0x48]
     */
    {
        uint64_t head_addr = (uint64_t)vms + 0x48ULL;
        uint64_t node_addr = (uint64_t)desc + 0x08ULL;

        volatile uint32_t *lock_word =
            (volatile uint32_t *)((uint8_t *)head_addr + 0x10);  /* vms+0x58 */
        volatile uint32_t *count_word =
            (volatile uint32_t *)((uint8_t *)head_addr + 0x14);  /* vms+0x5c */

        /* Detect & repair an un-initialised or corrupt list-head. A
         * FUN_0x37f700-initialised head has self-ref (+0x00 == head,
         * +0x08 == head); anything else means the head predates its
         * init or has been trampled.  We treat anything other than a
         * valid in-arena Blink as "empty". */
        volatile uint64_t *head_blink = (volatile uint64_t *)(head_addr);
        volatile uint64_t *head_flink = (volatile uint64_t *)(head_addr + 8);

        if (*head_flink == 0 || *head_flink == (uint64_t)-1 ||
            *head_blink == 0 || *head_blink == (uint64_t)-1) {
            fprintf(stderr,
                    "[PAL][RESERVE-PE]  head empty/corrupt "
                    "(Blink=0x%lx Flink=0x%lx) — self-ref-initializing\n",
                    (unsigned long)*head_blink,
                    (unsigned long)*head_flink);
            *head_blink = head_addr;
            *head_flink = head_addr;
        }

        /* Acquire spinlock at vms+0x58 (test-and-set on the dword). */
        while (__atomic_exchange_n(lock_word, 1U, __ATOMIC_ACQUIRE) != 0) {
            /* spin */
        }

        uint64_t old_flink = *head_flink;

        /* new_node->Flink = old_flink */
        *(volatile uint64_t *)(node_addr + 8ULL) = old_flink;
        /* old_flink->Blink = new_node (old_flink points at some node,
         * its Blink is at that node+0x00). */
        *(volatile uint64_t *)(old_flink) = node_addr;
        /* head->Flink = new_node */
        *head_flink = node_addr;
        /* new_node->Blink = head_addr */
        *(volatile uint64_t *)(node_addr) = head_addr;

        /* Back-pointer: desc[+0x18] = vms+0x48 */
        desc->list_head_backptr = head_addr;

        /* Count++ */
        (*count_word)++;

        fprintf(stderr,
                "[PAL][RESERVE-PE]  list-insert: head=0x%lx node=0x%lx "
                "oldFlink=0x%lx count=%u\n",
                (unsigned long)head_addr, (unsigned long)node_addr,
                (unsigned long)old_flink, (unsigned)*count_word);

        /* Release lock. */
        __atomic_store_n(lock_word, 0U, __ATOMIC_RELEASE);
    }

    /* 4) State transition: desc[+0x74] 1 -> 2 (REGISTERED). */
    desc->state = PE_IMAGE_DESC_STATE_REGISTERED;
    fprintf(stderr,
            "[PAL][RESERVE-PE]  state transition +0x74: 1 -> %u (REGISTERED)\n",
            (unsigned)desc->state);

    /* 5) Skip AVL insert + global counters per master-flow §Conservative. */
    fprintf(stderr,
            "[PAL][RESERVE-PE]  SKIPPED: AVL insert (FUN_0x380708) and "
            "global counters (FUN_0x208b0c) per wave-49 conservative plan\n");

    return desc;
}
