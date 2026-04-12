/*
 * pe_init_replicas.c — translations of PE-internal init functions
 * we observe running inside sqlpal.dll. These are NOT ELF-host
 * functions; they are kernel-mode code inside the NTUM PE. We
 * replicate them so our host can pre-execute the setup (or at
 * least document what the PE expects).
 *
 * Sources (see /tmp/sqlpal_full.txt PE disassembly, PE base 0x180000000):
 *   RVA 0x211650 → pe_replica_kuser_alloc
 *       Allocates KUSER_SHARED_DATA at 0x7ffe0000 via VirtualAllocate.
 *   RVA 0x2bcf9c → pe_replica_type_registry_init
 *       Populates kernel type registry at static addr 0x1806472c0,
 *       points [0x180648c00] at it, initializes 64 type entries of
 *       0x58 bytes each at 0x180648c48..0x180650248.
 *   RVA 0x276b68 → pe_replica_thread_object_init
 *       Initializes a per-thread kernel object; the validation at
 *       [sched+0xbc0]==1 (RVA 0x276ca0) and the vtable dispatch
 *       via [sched+0xa98] (RVA 0x276e0e) are what drove the
 *       sequence_id and processor_info fields in ntum_sched_block_t.
 *
 * These functions are declared in pal_internal.h. They are not
 * called from our boot orchestrator yet — calling them requires
 * the PE's vtable at static .data 0x4078e8 to be populated, which
 * in turn requires the ELF host's earlier init to have run. For
 * now these exist as DOCUMENTATION OF EXPECTED PE BEHAVIOR.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "pal_internal.h"

/* ------------------------------------------------------------
 * PE static-data constants (observed in /tmp/sqlpal_full.txt).
 * ------------------------------------------------------------ */

/* PE .data absolute addresses. */
#define PE_KUSER_SHARED_DATA_VA   0x7ffe0000ULL   /* KUSER_SHARED_DATA */
#define PE_TYPE_REGISTRY_VA       0x1806472c0ULL  /* static registry header */
#define PE_TYPE_REGISTRY_GLOBAL   0x180648c00ULL  /* holds &type_registry */
#define PE_TYPE_REGISTRY_GLOBAL2  0x1806475d0ULL  /* alt global */
#define PE_TYPE_ENTRIES_BASE      0x180648c48ULL  /* 64 entries @ 0x58 each */
#define PE_TYPE_ENTRIES_COUNT     64
#define PE_TYPE_ENTRY_STRIDE      0x58
#define PE_TYPE_ENTRIES_SIZE      (PE_TYPE_ENTRIES_COUNT * PE_TYPE_ENTRY_STRIDE)  /* 0x1600 */

/* PE .rdata vtable used by FUN_0x276b68 object init loop. */
#define PE_DEFAULT_VTABLE_ADDR    0x18040e380ULL  /* qword at [obj+slot] */

/* PE guard_dispatch trampoline address (0xa00008 in .00cfg → jmp *rax). */
#define PE_GUARD_DISPATCH_ADDR    0x180a00008ULL

/* Observed .data status flag set by FUN_0x2bcf9c. */
#define PE_TYPE_INIT_STATUS_ADDR  0x180608bfcULL  /* = 2 when init complete */

/* ------------------------------------------------------------
 * pe_thread_object — layout consumed by FUN_0x276b68.
 *
 * Observed at PE RVAs 0x276b68 - 0x277060 via disassembly. Offsets
 * are derived from the PE's explicit byte accesses — unknown fields
 * are named `unk_0xNNN` per the "no invention" rule.
 *
 * Total size: at least 0xdf0 (upper bound observed at
 * 0xac0 + 3*8 = 0xad8 array, plus 0xcf8 or-in write).
 * ------------------------------------------------------------ */

/* pe_thread_object: only key field offsets are asserted; the full
 * layout is sparse (many 8-byte slots from offset 0x48 to 0xAB8 are
 * populated in a vtable-init loop, and there are gaps between 0xB00
 * and 0xCD8 we haven't dissected yet). We use offsetof-from-base
 * helpers instead of a dense struct. */

struct pe_thread_object_header {
    void       *sched_block;        /* 0x000 */
    void       *unk_0x008;          /* 0x008 */
    uint64_t    init_timestamp;     /* 0x010 */
    uint8_t     unk_0x018[0x10];    /* 0x018 */
    uint32_t    unk_0x028_state;    /* 0x028 */
    uint32_t    unk_0x02c;          /* 0x02c */
    uint32_t    unk_0x030_value;    /* 0x030 */
    uint8_t     unk_0x034_flag;     /* 0x034 */
    uint8_t     unk_0x035;          /* 0x035 */
    uint16_t    unk_0x036;          /* 0x036 */
    uint32_t    cpu_slot_count;     /* 0x038 */
};

_Static_assert(offsetof(struct pe_thread_object_header, init_timestamp) == 0x10,
               "header: init_timestamp at +0x10");
_Static_assert(offsetof(struct pe_thread_object_header, unk_0x028_state) == 0x28,
               "header: +0x28");
_Static_assert(offsetof(struct pe_thread_object_header, cpu_slot_count) == 0x38,
               "header: cpu_slot_count at +0x38");

/* Named byte offsets for sparse fields beyond the header. */
#define PE_THREAD_OBJ_VTABLE_SLOT_BASE  0x48
#define PE_THREAD_OBJ_VTABLE_STRIDE     0x20
#define PE_THREAD_OBJ_VTABLE_COUNT      0x43   /* 67 slots */
#define PE_THREAD_OBJ_CPU_RESULTS_BASE  0xAC0  /* uint64[4] array indexed by cpu_slot_count */
#define PE_THREAD_OBJ_CPU_CDC           0xCDC  /* uint32 = -1 then inc */
#define PE_THREAD_OBJ_CPU_CE0           0xCE0
#define PE_THREAD_OBJ_CPU_CE4           0xCE4
#define PE_THREAD_OBJ_CPU_CE8           0xCE8
#define PE_THREAD_OBJ_CPU_CEC           0xCEC
#define PE_THREAD_OBJ_FLAGS_CF8         0xCF8  /* uint64 |= -1 */

/* ------------------------------------------------------------
 * Extern stubs — supplied by ELF translations or pal_stubs.c.
 * ------------------------------------------------------------ */

/* FUN_0x244cd0: resolves `gs:0x30 → TEB[0x1838] → KTHREAD[0x70] + 0xF0`,
 * returns 0 when any link is NULL. Callers subtract 0xf0 to get the
 * raw sched_block pointer. */
extern void *pe_get_current_thread_sched_info(void);

/* FUN_0x218494: PE-internal assertion / debug-break. The decompile
 * chains this after `call 0x3a0880` (int 0x2c fastfail). We route
 * all fastfail paths through abort() in the host context. */
extern void pe_panic_assert(uint32_t error_code, void *detail) __attribute__((noreturn));

/* ------------------------------------------------------------
 * Helpers mirroring PE idioms.
 * ------------------------------------------------------------ */

/* Reads KUSER_SHARED_DATA InterruptTime (qword at [0x7ffe0008]).
 * Matches PE RVA 0x276bd5. */
static inline uint64_t pe_kuser_interrupt_time(void)
{
    return *(volatile uint64_t *)(PE_KUSER_SHARED_DATA_VA + 0x08);
}

/* Invokes the indirect CFG call through [0x180a00008]. In the host
 * we compile these as direct function-pointer calls — the CFG check
 * on Linux is always "pass-through jmp *rax". */
static inline uint64_t pe_guard_dispatch_callr(uint64_t (*fn)(void *self),
                                               void *self)
{
    return fn ? fn(self) : 0;
}

/* ------------------------------------------------------------
 * pe_replica_kuser_alloc — PE RVA 0x211650
 *
 * In the real PE this calls its VirtualAllocate wrapper
 * (FUN_0x378c10) with base=0x7ffe0000, size=0x1000, commit|reserve.
 * On Linux we rely on setup_libos_memory() in main.c to mmap the
 * page ahead of time, so this function only validates presence
 * and zero-initializes the TickCountMultiplier field.
 * ------------------------------------------------------------ */
int pe_replica_kuser_alloc(void)
{
    /* TODO: translate FUN_0x378c10 (PE VirtualAllocate wrapper)
     *       once we have pal_image.c. For now we trust the host
     *       pre-map at KUSER_SHARED_DATA_ADDR done in main.c. */
    volatile uint32_t *multiplier =
        (volatile uint32_t *)(PE_KUSER_SHARED_DATA_VA + 0x04);
    if (*multiplier == 0)
        *multiplier = 0x0fa00000u;  /* default Windows tick multiplier */
    return 0;
}

/* ------------------------------------------------------------
 * pe_replica_type_registry_init — PE RVA 0x2bcf9c
 *
 * ELF-equivalent control flow:
 *   [0x180608bfc] = 2                     ; init status = INITIALIZED
 *   pool_obj = FUN_0x2c2a00(...) → [0x6456e8]
 *   allocator = FUN_0x2c2a00(...) → [0x645b78]
 *   [0x180648c00] = &type_registry        ; 0x1806472c0
 *   loop 64x:
 *     entry = &type_entries[i * 0x58]
 *     FUN_0x31a348(allocator, type_registry, entry-8, entry+0x18,
 *                  entry, entry+0x1a)
 *   FUN_0x2b5fbc(allocator, &[0x648c00], 1)
 *   [0x180648c08] = 1
 * ------------------------------------------------------------ */
int pe_replica_type_registry_init(void)
{
    /* 1. Publish type-registry pointer and init-status flag.
     *    This matches what ntum_bootstrap.c:ntum_bootstrap_init
     *    already does at the typed-struct level. We re-do the raw
     *    writes here for parity with the PE's own code. */
    ntum_type_registry_t *registry = (ntum_type_registry_t *)PE_TYPE_REGISTRY_VA;
    *(volatile uint64_t *)PE_TYPE_REGISTRY_GLOBAL  = (uint64_t)registry;
    *(volatile uint64_t *)PE_TYPE_REGISTRY_GLOBAL2 = (uint64_t)registry;
    *(volatile uint32_t *)PE_TYPE_INIT_STATUS_ADDR = 2u;

    /* 2. Zero the 64-entry type table at 0x180648c48. The real PE
     *    calls FUN_0x31a348 to register each type; we lack that
     *    translation but zero-init is sufficient for the type
     *    registry lookup NOT to crash (the table is then treated
     *    as "no types registered"). */
    memset((void *)PE_TYPE_ENTRIES_BASE, 0, PE_TYPE_ENTRIES_SIZE);

    /* 3. Set the "type registry ready" guard byte at 0x180648c08. */
    *(volatile uint8_t *)0x180648c08ULL = 1;

    /* TODO: translate FUN_0x31a348 per-entry registration and
     *       FUN_0x2b5fbc finalizer. */
    return 0;
}

/* ------------------------------------------------------------
 * pe_replica_thread_object_init — PE RVA 0x276b68
 *
 * ELF/PE signature (Windows x64 ABI):
 *   (rcx = object, rdx = param2, r8d = flags_word,
 *    r9d = value, [rsp+0x88] = stack_flag1,
 *    [rsp+0x90] = param2_extra, [rsp+0x98] = stack_flag2)
 *
 * Steps (exact):
 *   1. Loop 0x43 times: at [object + 0x48 + i*0x20]
 *      write vtable ptr (0x18040e380) and self-link.
 *   2. object->flags_cf8 |= -1
 *   3. object->init_timestamp = [0x7ffe0008]  (KUSER InterruptTime)
 *   4. rax = get_current_thread_sched_info()  (= sched + 0xf0 or 0)
 *   5. sched = rax - 0xf0  (or 0 if rax == 0)
 *   6. object->sched_block = sched
 *   7. object->cpu_count_* (0xcdc, 0xce0, 0xce4, 0xce8) = -1
 *   8. object->unk_0x028_state = ebx & 0xffffff3f
 *   9. object->unk_0x02c = sign-extended byte [sched + 0x322]
 *  10. Validate sched->sequence_id (0xbc0) == 1 else int 0x2c
 *  11. Validate sched->unk_0x2d6 (word) == 0 else int 0x2c
 *  12. vtable dispatch: fn = sched->processor_info->vtable[0x30]
 *      result = fn(sched->processor_info)
 *      object->cpu_vtable_results[object->cpu_slot_count++] = result
 *      (called 2-4 times depending on stack flags)
 *  13. Validate cpu_slot_count <= 3 else int 0x2c
 *  14. Return.
 *
 * We implement the zero-arg stub form (the caller supplies the object)
 * and forward to pe_get_current_thread_sched_info() — which the host's
 * ntum_bootstrap.c has already set up. This translation is NOT yet
 * called; it exists for documentation and future wiring.
 * ------------------------------------------------------------ */
int pe_replica_thread_object_init(void)
{
    /* The real FUN_0x276b68 needs an object pointer and param2 from
     * the caller. Since our pal_internal.h signature is zero-arg, we
     * treat this as documentation-only: wire-up happens in M6 when
     * the host's boot orchestrator allocates the object and calls
     * this function with the right rcx/rdx. For now just return
     * success so the symbol resolves. */
    return 0;
}
