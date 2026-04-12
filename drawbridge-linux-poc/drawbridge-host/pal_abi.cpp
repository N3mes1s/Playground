/*
 * pal_abi.c — ABI dispatcher + GetFunction_v2 / GetVersion_v2
 *             (translated from the decompiled ELF host).
 *
 * Source functions (see analysis/sqlservr_FULL.c):
 *   FUN_00269650 @ line 137747  → pal_abi_lookup_function
 *                                 (core func_id -> funcptr lookup)
 *   FUN_002696b0 @ line 137777  → pal_abi_lookup_version
 *                                 (core func_id -> max-version lookup)
 *   FUN_00284540 @ line 152669  → pal_abi_get_function_v2_wrapper
 *   FUN_00284620 @ line 152731  → pal_abi_get_function_v2
 *   FUN_00284590 @ line 152692  → pal_abi_get_version_v2_wrapper
 *   FUN_002846d0 @ line 152771  → pal_abi_get_version_v2
 *
 * Milestone M4: translated but not yet wired in. The currently-live
 * ABI dispatcher is the hand-written DK_AbiDispatcher in dk_pal.c.
 *
 * Rules followed (per CLAUDE.md + M4 scope):
 *   - No invention; unknown fields get unk_* names with TODO.
 *   - Exact control flow preserved from the decompiled code.
 *   - Cross-subsystem helpers (assert/error/FS-canary) are declared
 *     as extern stubs; no implementation committed here.
 *   - DAT_00369f40 becomes g_abi_function_registry (static).
 */

#include <stdint.h>
#include <stddef.h>
#include "pal_internal.h"

extern "C" {

/* ============================================================
 * ABI registry layout (derived from FUN_00269650 / FUN_002696b0).
 *
 * The registry is an array of 0x13 ( = 19) "version" entries, each
 * 0x3a0 bytes wide. Index is (funcId >> 0x18) - 1.
 *
 *   entry layout (0x3a0 bytes):
 *     +0x000 : int64_t group_base      // lowest (funcId>>0xc & 0xfff)
 *     +0x020 : group[0]  (0x20 bytes)
 *     +0x040 : group[1]
 *     ...    : up to 0x1c ( = 28) groups
 *
 *   group layout (0x20 bytes):
 *     +0x00 : int64_t subfn_base      // lowest (funcId & 0xfff)
 *             (up to 3 sub-functions after the base)
 *     +0x08 : void *slot[0]           // funcptr for base+0
 *     +0x10 : void *slot[1]           // funcptr for base+1
 *     +0x18 : void *slot[2]           // funcptr for base+2
 *
 * These sizes/indices are all pulled verbatim from the decompilation;
 * we do NOT have a typed struct for this yet (TODO: add once we
 * translate the registry builder in a later milestone).
 * ============================================================ */

#define PAL_ABI_VERSION_COUNT   0x13u   /* 19 version tables */
#define PAL_ABI_VERSION_STRIDE  0x3a0u  /* bytes per version */
#define PAL_ABI_GROUP_COUNT     0x1cu   /* 28 groups / version */
#define PAL_ABI_GROUP_STRIDE    0x20u   /* bytes per group */
#define PAL_ABI_SUBFN_COUNT     3u      /* slots per group (base+0..+2) */

#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000002u

/* ------------------------------------------------------------
 * Globals.
 *
 * DAT_00369f40 is the primary ABI function registry; it is
 * populated at NTUM startup by code we haven't translated yet.
 * DAT_0035d000 is a secondary (read-only?) table consulted by
 * GetVersion_v2 — TODO: reverse its initializer.
 * ------------------------------------------------------------ */
static uint8_t g_abi_function_registry[PAL_ABI_VERSION_COUNT *
                                       PAL_ABI_VERSION_STRIDE];
/* TODO(M?): translate the initializer for DAT_00369f40. */

static uint8_t g_abi_version_table_secondary[PAL_ABI_VERSION_COUNT *
                                             PAL_ABI_VERSION_STRIDE];
/* TODO(M?): translate the initializer for DAT_0035d000. */

/* ------------------------------------------------------------
 * Extern stubs for cross-subsystem helpers used by the
 * translated wrappers. These live in other translation units
 * we haven't pulled in yet — declare them here so this file
 * compiles standalone.
 *
 *   FUN_00353860 → __errno_location()-like: returns &errno-ish.
 *   FUN_001c1100 → assertion handler (noreturn).
 *   FUN_00353500 → stack-canary failure (noreturn).
 *   FUN_0028e070 → pal_result ctor (success).
 *   FUN_0028e0d0 → pal_result set-error.
 *   FUN_0028e130 → pal_result dtor.
 *   FUN_0028e1f0 → pal_result is-error check.
 *   FUN_0028e560 → pal_result combine (lhs |= rhs).
 * ------------------------------------------------------------ */
/* Integrator fix (C++ pivot): these live in pal_stubs.cpp which is now
 * wrapped in extern "C"; match here so mangling agrees across TUs. */
extern "C" {
extern int   *pal_abi_errno_location(void);                 /* FUN_00353860 */
extern void   pal_abi_assert_fail(const char *msg, int err) /* FUN_001c1100 */
                  __attribute__((noreturn));
extern void   pal_abi_stack_chk_fail(void)                  /* FUN_00353500 */
                  __attribute__((noreturn));
extern void   pal_result_init(void *result);                /* FUN_0028e070 */
extern void   pal_result_set(void *result, uint32_t status,
                             const char *file, int line);  /* FUN_0028e0d0 */
extern void   pal_result_fini(void *result);               /* FUN_0028e130 */
extern char   pal_result_is_error(void *result);           /* FUN_0028e1f0 */
extern void   pal_result_combine(void *dst, void *src);    /* FUN_0028e560 */
}

/* Size of the opaque pal_result structure (see "Error Handling
 * Pattern" note in CLAUDE.md — file ptr, status, line, extended).
 * The decompile uses a 24-byte stack slot; keep that.  */
#define PAL_RESULT_SIZE 24

/* fs:0x28 stack canary (glibc ABI). */
static inline uint64_t pal_abi_read_stack_guard(void)
{
    uint64_t v;
    __asm__ __volatile__("mov %%fs:0x28, %0" : "=r"(v));
    return v;
}

/* ============================================================
 * FUN_00269650 — core lookup.
 *
 * Translated verbatim. Given the registry base, a 32-bit func_id
 * packed as:
 *   bits [31:24] = version (1..0x13)
 *   bits [23:12] = group
 *   bits [11:0]  = subfunction
 * writes the resolved function pointer to *out_fn and returns 0,
 * or STATUS_OBJECT_NAME_NOT_FOUND on any out-of-range index.
 * ============================================================ */
static uint32_t pal_abi_lookup_function(void *registry_base,
                                        uint32_t func_id,
                                        void **out_fn)
{
    /* Always zero-init out_fn on ALL paths. Callers consuming the
     * returned pointer while ignoring the status (documented pattern
     * in several PE paths) must NEVER see stale memory or the NTSTATUS
     * value itself leaked through out_fn. Ref RCA3/RCA5 audits. */
    if (out_fn) *out_fn = NULL;

    uint8_t *base = (uint8_t *)registry_base;

    uint32_t version_idx = (func_id >> 0x18) - 1u;
    if (version_idx >= PAL_ABI_VERSION_COUNT) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    uint8_t *ver_entry = base + (uint64_t)version_idx * PAL_ABI_VERSION_STRIDE;

    uint64_t group_base = *(int64_t *)(ver_entry + 0x00);
    uint64_t group_idx  = (uint64_t)((func_id >> 0xc) & 0xfffu) - group_base;
    if (group_idx >= PAL_ABI_GROUP_COUNT) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    uint8_t *group = ver_entry + 0x20 + group_idx * PAL_ABI_GROUP_STRIDE;
    uint64_t subfn_base = *(int64_t *)(group + 0x00);
    uint64_t subfn_idx  = (uint64_t)(func_id & 0xfffu) - subfn_base;
    if (subfn_idx >= PAL_ABI_SUBFN_COUNT) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    *out_fn = *(void **)(group + 0x08 + subfn_idx * 8);
    return 0;
}

/* ============================================================
 * FUN_002696b0 — core max-supported-version lookup.
 *
 * Walks the same registry shape, but returns the highest version
 * index (as a count, not an index) that is populated for a given
 * (version, group) pair, capped at the caller's requested value.
 * Control flow preserved exactly from the decompilation.
 * ============================================================ */
static uint32_t pal_abi_lookup_version(void *registry_base,
                                       uint32_t func_id,
                                       uint32_t max_version,
                                       uint64_t *out_count)
{
    uint8_t *base = (uint8_t *)registry_base;

    uint32_t version_idx = (func_id >> 0x18) - 1u;
    if (version_idx >= PAL_ABI_VERSION_COUNT) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    uint64_t ver_off = (uint64_t)version_idx * PAL_ABI_VERSION_STRIDE;
    uint64_t group_idx =
        (uint64_t)((func_id >> 0xc) & 0xfffu) -
        *(int64_t *)(base + ver_off);
    if (group_idx > 0x1bu) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    uint8_t *ver_entry = base + ver_off;

    /* +0x20 : subfn_base for this group. */
    uint64_t subfn_base =
        *(uint64_t *)(ver_entry + group_idx * PAL_ABI_GROUP_STRIDE + 0x20);
    uint64_t cap = (uint64_t)max_version;
    if (cap < subfn_base) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    /* +0x28 : slot0 ptr. If non-NULL, running total starts at subfn_base. */
    uint64_t slot0 = *(uint64_t *)(ver_entry + group_idx * PAL_ABI_GROUP_STRIDE + 0x28);
    uint64_t running = subfn_base;
    if (slot0 != 0) {
        running = subfn_base;   /* matches decompile: `if (s0) running=subfn_base;` */
    }

    uint64_t highest;
    int64_t  slot2;
    if (*(int64_t *)(ver_entry + group_idx * PAL_ABI_GROUP_STRIDE + 0x30) == 0) {
        /* slot1 missing → skip the +1 step. */
        slot2   = *(int64_t *)(ver_entry + group_idx * PAL_ABI_GROUP_STRIDE + 0x38);
        highest = running;
    } else {
        highest = subfn_base + 1;
        if (cap < highest) {
            goto done;
        }
        slot2 = *(int64_t *)(ver_entry + group_idx * PAL_ABI_GROUP_STRIDE + 0x38);
    }

    running = highest;
    if (slot2 != 0) {
        uint64_t try_two = subfn_base + 2;
        if (cap >= try_two) {
            running = try_two;
        }
    }

done:
    *out_count = running;
    if (running == 0) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    return 0;
}

/* ============================================================
 * FUN_00284620 — Abi_GetFunction_v2 implementation.
 *
 * Delegates to the core lookup against the primary registry,
 * wraps the status in a pal_result, propagates it, and returns
 * the final status to the caller.
 * ============================================================ */
void *pal_abi_get_function_v2(uint32_t function_id, uint32_t version)
{
    uint64_t canary = pal_abi_read_stack_guard();
    (void)canary;   /* matches ELF's `local_20 = fs:0x28` prologue. */
    (void)version;  /* FUN_00284620 has no "version" arg — but our
                     * public signature in pal_internal.h does. We
                     * preserve the ELF's single func_id-based lookup
                     * and ignore the extra input here. TODO: unify. */

    void *fn = NULL;
    uint32_t status = pal_abi_lookup_function(&g_abi_function_registry,
                                              function_id, &fn);

    /* Fallback: g_abi_function_registry is not yet populated (the
     * ELF's DAT_00369f40 static initializer is untranslated, see
     * TODO @ pal_abi.cpp:74). Route the lookup through the
     * hand-written DK_AbiGetFunction table in dk_pal.cpp so the
     * PE doesn't consume STATUS_OBJECT_NAME_NOT_FOUND as a
     * pointer (ref /tmp/deadlock_rca.md, RCA5 audit). */
    if (status != 0 || fn == NULL) {
        /* already inside extern "C" block so plain extern decl is fine */
        extern uint64_t DK_AbiGetFunction(uint64_t abi_id, void **func_ptr);
        if (DK_AbiGetFunction((uint64_t)function_id, &fn) == 0 && fn) {
            status = 0;
        }
    }

    uint8_t result[PAL_RESULT_SIZE];
    pal_result_set(result, status, "abis/Abi_GetFunction_v2.cpp", 0x18);
    pal_result_fini(result);

    if (pal_abi_read_stack_guard() != canary) {
        pal_abi_stack_chk_fail();
    }

    /* ELF returns the 32-bit status (local_30). For our callers
     * expecting void*, return fn on success, NULL on failure. */
    return (status == 0) ? fn : NULL;
}

/* ============================================================
 * FUN_00284540 — GetFunction_v2 wrapper.
 *
 * Validates InSize == 4 (one uint32 func_id) and OutSize == 8
 * (room for a void*), then calls through.
 * ============================================================ */
static void pal_abi_get_function_v2_wrapper(uint64_t in_size,
                                            const uint32_t *in_buf,
                                            uint64_t out_size,
                                            void **out_buf)
{
    if (in_size != 4) {
        int *e = pal_abi_errno_location();
        pal_abi_assert_fail("InSize == sizeof(Abi_GetFunction_v2_In)", *e);
    }
    if (out_size != 8) {
        int *e = pal_abi_errno_location();
        pal_abi_assert_fail("OutSize == sizeof(Abi_GetFunction_v2_Out)", *e);
    }

    /* out_buf[0] is the slot pointer (double-deref convention, see
     * CLAUDE.md "GetFunction_v2 Output Protocol"). The ELF code just
     * passes *param_4 as a uint64_t to FUN_00284620 — here we mirror
     * that by passing the slot pointer through directly. */
    void *fn = pal_abi_get_function_v2(in_buf[0], 0);
    *(void **)(*out_buf) = fn;
}

/* ============================================================
 * FUN_002846d0 — Abi_GetVersion_v2 implementation.
 *
 * Queries both the primary and secondary registries for the
 * highest supported sub-function, takes the max of the two,
 * and writes it to *out_version. Sets an error status if zero.
 * ============================================================ */
static uint32_t pal_abi_get_version_v2(uint32_t function_id,
                                       uint32_t max_version,
                                       uint32_t *out_version)
{
    uint64_t canary = pal_abi_read_stack_guard();
    (void)canary;

    uint8_t aggregate[PAL_RESULT_SIZE];
    pal_result_init(aggregate);

    uint64_t primary_max   = 0;
    uint64_t secondary_max = 0;

    uint8_t tmp[PAL_RESULT_SIZE];
    uint32_t st;

    /* Primary registry. */
    st = pal_abi_lookup_version(&g_abi_function_registry,
                                function_id, max_version, &primary_max);
    pal_result_set(tmp, st, "abis/Abi_GetVersion_v2.cpp", 0x21);
    pal_result_combine(aggregate, tmp);
    pal_result_fini(tmp);
    if (pal_result_is_error(aggregate)) {
        primary_max = 0;
    }

    /* Secondary registry. */
    st = pal_abi_lookup_version(&g_abi_version_table_secondary,
                                function_id, max_version, &secondary_max);
    /* NOTE: decompile calls FUN_0028e0d0 with only 3 args here;
     * the line number wasn't captured. TODO: recover from binary. */
    pal_result_set(tmp, st, "abis/Abi_GetVersion_v2.cpp", 0);
    pal_result_combine(aggregate, tmp);
    pal_result_fini(tmp);
    if (pal_result_is_error(aggregate)) {
        secondary_max = 0;
    }

    uint64_t winner = (secondary_max < primary_max) ? primary_max
                                                    : secondary_max;
    *out_version = (uint32_t)winner;

    if (winner == 0) {
        pal_result_set(tmp, STATUS_OBJECT_NAME_NOT_FOUND,
                       "abis/Abi_GetVersion_v2.cpp", 0x3d);
    } else {
        pal_result_init(tmp);
    }
    pal_result_combine(aggregate, tmp);
    pal_result_fini(tmp);
    pal_result_fini(aggregate);

    if (pal_abi_read_stack_guard() != canary) {
        pal_abi_stack_chk_fail();
    }

    return (winner == 0) ? STATUS_OBJECT_NAME_NOT_FOUND : 0;
}

/* ============================================================
 * FUN_00284590 — GetVersion_v2 wrapper.
 *
 * Validates InSize == 8 (two uint32s: func_id, max_version) and
 * OutSize == 8 (one uint64 out slot — decompile shows the wrapper
 * writes via param_4[0], which is a uint32_t*).
 * ============================================================ */
static void pal_abi_get_version_v2_wrapper(uint64_t in_size,
                                           const uint32_t *in_buf,
                                           uint64_t out_size,
                                           uint32_t **out_buf)
{
    if (in_size != 8) {
        int *e = pal_abi_errno_location();
        pal_abi_assert_fail("InSize == sizeof(Abi_GetVersion_v2_In)", *e);
    }
    if (out_size != 8) {
        int *e = pal_abi_errno_location();
        pal_abi_assert_fail("OutSize == sizeof(Abi_GetVersion_v2_Out)", *e);
    }

    (void)pal_abi_get_version_v2(in_buf[0], in_buf[1], *out_buf);
}

/* ============================================================
 * pal_abi_dispatch — FUN_00269650 entry-point shim.
 *
 * The decompiled FUN_00269650 is the raw 3-arg lookup used
 * directly by FUN_00284620. The public signature declared in
 * pal_internal.h matches the DK_AbiDispatcher-style 6-arg form
 * (table, call_type, in_size, in_buf, out_size, out_buf). We
 * route it to the appropriate wrapper based on call_type so this
 * file stays compilable and exports something usable later.
 *
 * TODO(M?): once we know how the NTUM actually reaches these
 * wrappers (likely via the registry itself, not a switch), drop
 * this shim.
 * ============================================================ */
uint64_t pal_abi_dispatch(void *abi_table, uint32_t call_type,
                          uint64_t in_size, void *in_buf,
                          uint64_t out_size, void *out_buf)
{
    (void)abi_table;

    switch (call_type) {
    case 0x7002000u:   /* Abi_GetFunction_v2 */
        pal_abi_get_function_v2_wrapper(in_size,
                                        (const uint32_t *)in_buf,
                                        out_size,
                                        (void **)out_buf);
        return 0;
    case 0x7001000u:   /* Abi_GetVersion_v2 */
        pal_abi_get_version_v2_wrapper(in_size,
                                       (const uint32_t *)in_buf,
                                       out_size,
                                       (uint32_t **)out_buf);
        return 0;
    default:
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
}

/* Compile-time sanity on the registry geometry.
 *   version stride = 0x20 header + 28 * 0x20 groups = 0x3a0
 *   group   stride = 0x08 base   +  3 * 0x08 slots  = 0x20
 */
static_assert(PAL_ABI_VERSION_STRIDE ==
               0x20 + PAL_ABI_GROUP_COUNT * PAL_ABI_GROUP_STRIDE,
               "version stride should cover header + 28 groups");
static_assert(PAL_ABI_GROUP_STRIDE == 8 + PAL_ABI_SUBFN_COUNT * 8,
               "group stride is base + 3 slot ptrs");

} // extern "C"
