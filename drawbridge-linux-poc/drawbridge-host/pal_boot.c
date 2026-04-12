/*
 * pal_boot.c - Translated PAL boot sequence from decompiled ELF host.
 *
 * Source functions (see analysis/sqlservr_FULL.c):
 *   FUN_002053e0 @ line 69864       -> pal_init_abi_table
 *   FUN_00204680 @ line 69308       -> pal_boot_init         (22-step PAL boot)
 *   FUN_0020ba60 @ lines 75933-76034 -> pal_init_libos_params
 *
 * Milestone M2a: translate FUN_002053e0 and FUN_0020ba60.
 * pal_boot_init is still TODO (handled by another agent in M2b).
 */

#include <stdint.h>
#include <stddef.h>
#include "pal_internal.h"

/* ============================================================
 * File-scope globals referenced by the decompiled boot code.
 *
 * DAT_00369ec8 -> g_host_abi_table_template   (ELF .rodata)
 * DAT_003b2138 -> g_runtime_callback_state_template (ELF .data)
 * DAT_0036f598 -> g_pal_instance (file-scope static, ELF .bss)
 * DAT_00369f30 -> g_libos_init_tag (passed to FUN_0020bcf0;
 *                 TODO: identify - looks like a string/tag constant)
 * ============================================================ */
extern uint8_t g_host_abi_table_template[];         /* DAT_00369ec8 */
extern uint8_t g_runtime_callback_state_template[]; /* DAT_003b2138 */
static uint8_t g_pal_instance[0x1000];              /* DAT_0036f598 - TODO size */
extern uint8_t g_libos_init_tag[];                  /* DAT_00369f30 - TODO */

/* ============================================================
 * Cross-subsystem externs (translated elsewhere / still stubs).
 *
 * These live in other PAL subsystems; we declare minimal signatures
 * matching the decompiled call sites.  TODO: move to pal_internal.h
 * once their owning subsystems are translated.
 * ============================================================ */

/* FUN_0020bcf0 @ analysis/sqlservr_FULL.c:76067 - AbiDispatch sub-struct init.
 * TODO(M2/M4): translate; owner TBD (pal_abi?). */
extern void pal_abi_dispatch_init(void *abi_dispatch_slot,
                                  void *image_handle,
                                  void *init_tag);

/* FUN_0029fd00 - queries {version_id, flags} from the AbiDispatch sub-struct.
 * TODO: translate (likely pal_abi). */
extern void pal_abi_query_version(void *abi_dispatch_slot,
                                  uint64_t *out_version,
                                  uint32_t *out_flags);

/* FUN_00297c90 / FUN_00297c80 / FUN_00297ca0 / FUN_00296db0 / FUN_00296dd0 -
 * image-metadata accessors on the sqlpal.dll image handle.
 * TODO: translate (likely pe_init_replicas or a new pal_image module). */
extern uint64_t pal_image_get_field_c90(void *image_handle);
extern uint64_t pal_image_get_field_c80(void *image_handle);
extern uint64_t pal_image_get_field_ca0(void *image_handle);
extern uint64_t pal_image_get_field_db0(void *image_handle);
extern uint32_t pal_image_get_field_dd0(void *image_handle);

/* FUN_002bdee0 / FUN_002bdfc0 - bool/addr helpers over an image-metadata
 * descriptor returned by the accessors above.  TODO: translate. */
extern char     pal_image_meta_is_split(uint64_t meta);
extern uint64_t pal_image_meta_resolve(uint64_t meta);

/* FUN_0029e430 / FUN_0029e2c0 / FUN_0029df10 / FUN_0029df00 -
 * operate on the inner "parameter-buffer" object at (params + 0x240).
 * TODO: translate (pal_parambuf?). */
extern int      pal_parambuf_reserve(void *pbuf, void *hdr, uint64_t size);
extern uint64_t pal_parambuf_append (void *pbuf, uint64_t value);
extern uint32_t pal_parambuf_cursor (void *pbuf);
extern void    *pal_parambuf_tail   (void *pbuf);

/* FUN_0020d9c0 - one-byte capability probe (returns HasEnclave flag). */
extern uint8_t  pal_probe_has_enclave(void);

/* FUN_00353790 / FUN_00354360 / FUN_003537b0 - libstdc++ exception glue.
 * FUN_00353500 - __stack_chk_fail.  FUN_00353860 - errno*.
 * FUN_001c1100 - assertion failure.  Translated as abort() hooks for now. */
extern void    *pal_cxa_allocate_exception(uint64_t size);
extern void     pal_runtime_error_ctor(void *ex, const char *what);
extern void     pal_cxa_throw(void *ex, void *tinfo, void *dtor);
extern void     pal_stack_chk_fail(void) __attribute__((noreturn));
extern int     *pal_errno_location(void);
extern void     pal_assert_fail(const char *expr, int err) __attribute__((noreturn));
extern void    *g_std_runtime_error_typeinfo;       /* std::runtime_error::typeinfo */
extern void    *g_std_runtime_error_dtor_ptr;       /* PTR__runtime_error_00367550 */

/* ============================================================
 * Extended LIBOS-params layout beyond drawbridge_types.h.
 *
 * FUN_0020ba60 touches fields *past* the 0x190-byte
 * WINDOWS_LIBOS_PARAMETERS defined in drawbridge_types.h:
 *
 *   params[0x12]   @ +0x090  - AbiDispatch sub-struct (already sized 0xE0)
 *   params[0x48]   @ +0x240  - inner parameter-buffer object (pal_parambuf)
 *   params[0x4b]   @ +0x258  - init-once guard byte
 *
 * TODO(integrator): extend WINDOWS_LIBOS_PARAMETERS in drawbridge_types.h
 * with explicit fields:
 *     uint8_t  ParameterBufObject[0x18];  // +0x240
 *     uint8_t  InitGuard;                 // +0x258
 * and likely grow the total size accordingly (currently declared 0x190).
 * For now we reach these via typed byte offsets on the params pointer.
 * ============================================================ */
#define PAL_LIBOS_PARAMBUF_OBJ_OFFSET  0x240
#define PAL_LIBOS_INIT_GUARD_OFFSET    0x258

static inline void *pal_libos_parambuf_obj(WINDOWS_LIBOS_PARAMETERS *p) {
    return (uint8_t *)p + PAL_LIBOS_PARAMBUF_OBJ_OFFSET;
}
static inline uint8_t *pal_libos_init_guard(WINDOWS_LIBOS_PARAMETERS *p) {
    return (uint8_t *)p + PAL_LIBOS_INIT_GUARD_OFFSET;
}

/* ============================================================
 * pal_init_abi_table  (FUN_002053e0 @ 0x2053e0, line 69864)
 *
 * Original decompilation:
 *   void FUN_002053e0(long param_1) {
 *     FUN_0020ba60(param_1 + 400,
 *                  *(undefined8*)(param_1 + 0x138),
 *                  *(undefined8*)(param_1 + 0x180),
 *                  *(undefined8*)(param_1 + 0x188),
 *                  &DAT_00369ec8, &DAT_003b2138, 0x18);
 *   }
 *
 * `param_1` is the outer PAL-instance context (DAT_0036f598-style), of which
 * the embedded WINDOWS_LIBOS_PARAMETERS starts 400 (=0x190) bytes in.  The
 * three fields at +0x138 / +0x180 / +0x188 of the outer context carry the
 * sqlpal.dll image handle, image base, and image size respectively.
 *
 * TODO(integrator): the outer context structure isn't typed yet - add a
 * "pal_instance_t" typedef in drawbridge_types.h so we don't have to reach
 * in with byte offsets here.
 * ============================================================ */

/* Byte offsets inside the outer PAL instance context.  TODO: typedef. */
#define PAL_INSTANCE_LIBOS_PARAMS_OFFSET  400     /* 0x190 */
#define PAL_INSTANCE_IMAGE_HANDLE_OFFSET  0x138
#define PAL_INSTANCE_IMAGE_BASE_OFFSET    0x180
#define PAL_INSTANCE_IMAGE_LENGTH_OFFSET  0x188

/* Forward decl - definition below. */
static void pal_init_libos_params_ex(WINDOWS_LIBOS_PARAMETERS *params,
                                     void *image_handle,
                                     void *image_base,
                                     void *image_length,
                                     void *host_abi_table,
                                     void *runtime_cbstate,
                                     void *stack_reservation);

void pal_init_abi_table(WINDOWS_LIBOS_PARAMETERS *params_ignored)
{
    /* The public signature takes the LIBOS params pointer directly, but the
     * ELF decompilation receives the outer PAL-instance pointer and derives
     * everything from it.  Walk back to the outer context so we can pull
     * the image metadata exactly like FUN_002053e0 does. */
    (void)params_ignored;

    uint8_t *instance = g_pal_instance;
    WINDOWS_LIBOS_PARAMETERS *params =
        (WINDOWS_LIBOS_PARAMETERS *)(instance + PAL_INSTANCE_LIBOS_PARAMS_OFFSET);

    void    *image_handle = *(void    **)(instance + PAL_INSTANCE_IMAGE_HANDLE_OFFSET);
    void    *image_base   = *(void    **)(instance + PAL_INSTANCE_IMAGE_BASE_OFFSET);
    uint64_t image_length = *(uint64_t *)(instance + PAL_INSTANCE_IMAGE_LENGTH_OFFSET);

    pal_init_libos_params_ex(params,
                             image_handle,
                             image_base,
                             (void *)image_length,
                             g_host_abi_table_template,
                             g_runtime_callback_state_template,
                             (void *)0x18);
}

/* ============================================================
 * pal_init_libos_params  (FUN_0020ba60 @ 0x20ba60, lines 75933-76034)
 *
 * "Guest OS initialization class" - fills in the WINDOWS_LIBOS_PARAMETERS
 * header (Size, SubHeaderSize, HostAbiTable, RuntimeCallbackState,
 * StackReservation, ImageBase, ImageLength) plus the AbiDispatch
 * sub-struct at +0x090 and the inner parameter-buffer object at +0x240.
 *
 * Guarded by an init-once byte at +0x258: double-init throws
 * std::runtime_error("The Guest OS initialization class cannot be loaded twice.").
 *
 * Control flow is preserved exactly - including the fall-through from the
 * happy path into the "throw" block after the return check, matching the
 * decompiled cfg.
 * ============================================================ */

/* Extended signature exposed for pal_init_abi_table above.
 * The public pal_init_libos_params(params) one-arg wrapper is kept
 * for pal_internal.h compatibility and simply errors-out for now. */
static void pal_init_libos_params_ex(WINDOWS_LIBOS_PARAMETERS *params,
                                     void *image_handle,     /* param_2 */
                                     void *image_base,       /* param_3 */
                                     void *image_length,     /* param_4 */
                                     void *host_abi_table,   /* param_5 */
                                     void *runtime_cbstate,  /* param_6 */
                                     void *stack_reservation /* param_7 */)
{
    uint8_t *init_guard = pal_libos_init_guard(params);

    if (*init_guard == 0) {
        *init_guard = 1;

        /* Header: Size / SubHeaderSize / host pointers / image metadata. */
        params->Size              = 0x90;
        params->SubHeaderSize     = 0x38;
        params->HostAbiTable      = host_abi_table;
        params->RuntimeCallbackState = runtime_cbstate;
        params->StackReservation  = stack_reservation;
        params->ImageBase         = image_base;
        params->ImageLength       = (uint64_t)image_length;

        /* AbiDispatch sub-struct init (FUN_0020bcf0). */
        pal_abi_dispatch_init(&params->AbiDispatch[0],
                              image_handle,
                              g_libos_init_tag);

        /* Query version/flags out of the AbiDispatch sub-struct. */
        uint64_t local_version = 0;
        uint32_t local_flags   = 0;
        pal_abi_query_version(&params->AbiDispatch[0],
                              &local_version, &local_flags);

        uint64_t version_value = local_version;

        /* Decide whether the image wants a "split" parameter-buffer entry. */
        uint64_t meta_c90 = pal_image_get_field_c90(image_handle);
        char     is_split = pal_image_meta_is_split(meta_c90);

        uint32_t final_flags;

        if (is_split == 0) {
            /* Simple path: ParameterBuffer <- version_value directly. */
            params->ParameterBuffer = (void *)version_value;
            final_flags = local_flags;
        } else {
            /* Split path: build a 0x20-byte entry inside the inner
             * parameter-buffer object (+0x240) and point ParameterBuffer
             * at the freshly allocated tail. */
            void *pbuf = pal_libos_parambuf_obj(params);

            struct {
                uint32_t size_lo;
                uint32_t cursor;
                uint64_t version;   /* mirrors uStack_60 */
                uint64_t flags64;   /* mirrors local_58 */
                uint64_t resolved;  /* mirrors uStack_50 */
            } entry = { 0, 0, 0, 0, 0 };

            int rc = pal_parambuf_reserve(pbuf, &entry, 0x20);
            if (rc != 0) {
                /* LAB_0020bc5d - "offset == 0" assertion. */
                int *err = pal_errno_location();
                pal_assert_fail("offset == 0", err ? *err : 0);
                /* pal_assert_fail is noreturn */
            }

            entry.size_lo = 0x20;
            entry.version = version_value;
            entry.flags64 = (uint64_t)local_flags;

            uint64_t meta_c80     = pal_image_get_field_c80(image_handle);
            uint64_t meta_c80_abs = pal_image_meta_resolve(meta_c80);
            entry.resolved        = pal_parambuf_append(pbuf, meta_c80_abs);

            uint32_t cursor = pal_parambuf_cursor(pbuf);
            entry.cursor    = cursor;

            uint32_t *tail = (uint32_t *)pal_parambuf_tail(pbuf);
            tail[0] = entry.size_lo;
            tail[1] = entry.cursor;
            tail[2] = (uint32_t)(entry.version & 0xFFFFFFFFu);
            tail[3] = (uint32_t)(entry.version >> 32);
            *(uint64_t *)(tail + 4) = entry.flags64;
            *(uint64_t *)(tail + 6) = entry.resolved;

            params->ParameterBuffer = tail;
            final_flags = cursor;
        }

        params->ParameterBufferSize = (uint64_t)final_flags;

        /* Resolve image-metadata byte/short fields and stamp them in. */
        uint64_t meta_ca0     = pal_image_get_field_ca0(image_handle);
        uint64_t meta_ca0_abs = pal_image_meta_resolve(meta_ca0);
        uint64_t tail_base    = (uint64_t)pal_parambuf_tail(pal_libos_parambuf_obj(params));

        /* HostExtensionEntryPoint <- (low32 of resolved meta) + tail_base.
         * In the ELF this writes param_1[6] which matches +0x30. */
        params->HostExtensionEntryPoint =
            (void *)((meta_ca0_abs & 0xFFFFFFFFull) + tail_base);

        uint16_t version_short = (uint16_t)(meta_ca0_abs >> 32);
        params->MajorVersion = version_short;
        params->MinorVersion = version_short;   /* +0x2a mirrors +0x28 */

        params->HasEnclave = pal_probe_has_enclave();

        params->ProcessorInfo = (void *)pal_image_get_field_db0(image_handle);
        params->NumaNodeCount = pal_image_get_field_dd0(image_handle);

        /* Stack-guard check (__stack_chk_fail on mismatch).  Translated as
         * a return on the happy path; real stack canary handling is on the
         * compiler for our build. */
        return;
    }

    /* Double-init: throw std::runtime_error. */
    void *ex = pal_cxa_allocate_exception(0x10);
    pal_runtime_error_ctor(ex,
        "The Guest OS initialization class cannot be loaded twice.");
    pal_cxa_throw(ex,
                  &g_std_runtime_error_typeinfo,
                  &g_std_runtime_error_dtor_ptr);
    /* pal_cxa_throw is effectively noreturn, but keep the body structurally
     * identical to the decompilation. */
}

/* One-arg shim kept to satisfy the pal_internal.h signature.  The real
 * entry point is pal_init_abi_table (FUN_002053e0) which calls the _ex
 * variant with the correct image metadata. */
void pal_init_libos_params(WINDOWS_LIBOS_PARAMETERS *params)
{
    pal_init_libos_params_ex(params,
                             /* image_handle    */ NULL,
                             /* image_base      */ params ? params->ImageBase : NULL,
                             /* image_length    */ params ? (void *)params->ImageLength : NULL,
                             /* host_abi_table  */ g_host_abi_table_template,
                             /* runtime_cbstate */ g_runtime_callback_state_template,
                             /* stack_reserv    */ (void *)0x18);
}

/* ============================================================
 * pal_boot_init (FUN_00204680 @ line 69308)
 *
 * TODO(M2b): translate the 22-step PAL boot sequence.  Another agent is
 * splitting this work concurrently - leave as an empty stub for now.
 * ============================================================ */
int pal_boot_init(void)
{
    /* TODO(M2b) */
    return 0;
}

/* ============================================================
 * Weak placeholder definitions for every cross-subsystem symbol
 * referenced above.  They exist only so pal_boot.c links cleanly
 * before the owning subsystems are translated - the eventual real
 * definitions (in pal_abi.c / pe_init_replicas.c / pal_stubs.c /
 * the ELF data sections) supersede these at link time.
 *
 * Every one of these carries a TODO and is intentionally inert.
 * ============================================================ */

#define PAL_WEAK __attribute__((weak))

/* Data symbols.  TODO: provide real ELF-sourced templates. */
PAL_WEAK uint8_t g_host_abi_table_template[0x40];          /* DAT_00369ec8 */
PAL_WEAK uint8_t g_runtime_callback_state_template[0x100]; /* DAT_003b2138 */
PAL_WEAK uint8_t g_libos_init_tag[0x10];                   /* DAT_00369f30 */
PAL_WEAK void   *g_std_runtime_error_typeinfo = NULL;
PAL_WEAK void   *g_std_runtime_error_dtor_ptr = NULL;

/* Function stubs - all no-ops returning zero.  TODO: translate. */
PAL_WEAK void pal_abi_dispatch_init(void *a, void *b, void *c)
{ (void)a; (void)b; (void)c; }

PAL_WEAK void pal_abi_query_version(void *a, uint64_t *v, uint32_t *f)
{ (void)a; if (v) *v = 0; if (f) *f = 0; }

PAL_WEAK uint64_t pal_image_get_field_c90(void *h) { (void)h; return 0; }
PAL_WEAK uint64_t pal_image_get_field_c80(void *h) { (void)h; return 0; }
PAL_WEAK uint64_t pal_image_get_field_ca0(void *h) { (void)h; return 0; }
PAL_WEAK uint64_t pal_image_get_field_db0(void *h) { (void)h; return 0; }
PAL_WEAK uint32_t pal_image_get_field_dd0(void *h) { (void)h; return 0; }

PAL_WEAK char     pal_image_meta_is_split(uint64_t m) { (void)m; return 0; }
PAL_WEAK uint64_t pal_image_meta_resolve (uint64_t m) { return m; }

PAL_WEAK int      pal_parambuf_reserve(void *p, void *h, uint64_t s)
{ (void)p; (void)h; (void)s; return 0; }
PAL_WEAK uint64_t pal_parambuf_append (void *p, uint64_t v)
{ (void)p; return v; }
PAL_WEAK uint32_t pal_parambuf_cursor (void *p) { (void)p; return 0; }
PAL_WEAK void    *pal_parambuf_tail   (void *p) { return p; }

PAL_WEAK uint8_t  pal_probe_has_enclave(void) { return 0; }

PAL_WEAK void    *pal_cxa_allocate_exception(uint64_t s) { (void)s; return NULL; }
PAL_WEAK void     pal_runtime_error_ctor(void *e, const char *w)
{ (void)e; (void)w; }
PAL_WEAK void     pal_cxa_throw(void *e, void *t, void *d)
{ (void)e; (void)t; (void)d; }

PAL_WEAK void     pal_stack_chk_fail(void) { __builtin_trap(); }
PAL_WEAK int     *pal_errno_location(void) { static int e; return &e; }
PAL_WEAK void     pal_assert_fail(const char *ex, int er)
{ (void)ex; (void)er; __builtin_trap(); }
