/*
 * pal_stubs.c — Temporary weak stubs for cross-subsystem helpers
 *               referenced by the freshly-translated pal_*.c files.
 *
 * These correspond to ELF decompiled helpers that haven't been
 * translated yet:
 *   FUN_00353860 → pal_abi_errno_location     (__errno_location)
 *   FUN_001c1100 → pal_abi_assert_fail         (__assert_fail)
 *   FUN_00353500 → pal_abi_stack_chk_fail      (__stack_chk_fail)
 *   FUN_0028e070 → pal_result_init             (pal_result ctor)
 *   FUN_0028e130 → pal_result_fini             (pal_result dtor)
 *   FUN_0028e1f0 → pal_result_is_error         (check)
 *   FUN_0028e560 → pal_result_combine          (lhs |= rhs)
 *   FUN_0028e0d0 → pal_result_set              (set error)
 *   FUN_00353ee0 → pal_aligned_nothrow_alloc   (operator new aligned nothrow)
 *   PTR_nothrow_003675a8 → pal_std_nothrow_tag
 *   FUN_001f1fd0 → io_completion_port_construct
 *
 * All are marked `weak` so the eventual real translations in
 * pal_abi.c / pal_thread.c / dedicated pal_result.c supersede
 * these at link time.
 *
 * TODO: replace these as later milestones land the real ELF
 *       translations.
 */

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PAL_WEAK __attribute__((weak))

/* ------------ errno / assert / stack-chk -------------------- */

PAL_WEAK int *pal_abi_errno_location(void)
{
    return &errno;
}

PAL_WEAK void pal_abi_assert_fail(const char *msg, int err) __attribute__((noreturn));
PAL_WEAK void pal_abi_assert_fail(const char *msg, int err)
{
    fprintf(stderr, "[PAL-ASSERT] %s (errno=%d)\n", msg ? msg : "?", err);
    abort();
}

PAL_WEAK void pal_abi_stack_chk_fail(void) __attribute__((noreturn));
PAL_WEAK void pal_abi_stack_chk_fail(void)
{
    fprintf(stderr, "[PAL-STACK-CHK] canary mismatch\n");
    abort();
}

PAL_WEAK void pal_panic_assert(const char *expr, int linux_errno) __attribute__((noreturn));
PAL_WEAK void pal_panic_assert(const char *expr, int linux_errno)
{
    fprintf(stderr, "[PAL-PANIC] %s (errno=%d)\n", expr ? expr : "?", linux_errno);
    abort();
}

/* ------------ pal_result (see CLAUDE.md error pattern) ------
 * struct pal_result {
 *     char    *source_file;  // +0x00
 *     int32_t  status;       // +0x08 (HRESULT)
 *     uint16_t line;         // +0x0C
 *     int32_t  extended;     // +0x10
 * };
 * 24 bytes total.
 */

struct pal_result_layout {
    char    *source_file;
    int32_t  status;
    uint16_t line;
    uint16_t _pad;
    int32_t  extended;
    uint32_t _pad2;
};

PAL_WEAK void pal_result_init(void *result)
{
    if (result) memset(result, 0, sizeof(struct pal_result_layout));
}

PAL_WEAK void pal_result_fini(void *result)
{
    (void)result;
    /* No-op: real ELF frees source_file if owned; stub deliberately
     * leaks because the allocator side isn't translated yet. */
}

PAL_WEAK char pal_result_is_error(void *result)
{
    if (!result) return 0;
    return ((struct pal_result_layout*)result)->status < 0;
}

PAL_WEAK char pal_result_succeeded(void *result)
{
    if (!result) return 1;
    return ((struct pal_result_layout*)result)->status >= 0;
}

PAL_WEAK void pal_result_combine(void *dst, void *src)
{
    if (!dst || !src) return;
    struct pal_result_layout *d = dst;
    struct pal_result_layout *s = src;
    if (d->status >= 0 && s->status < 0) *d = *s;
}

PAL_WEAK void pal_result_copy(void *dst, void *src)
{
    if (!dst || !src) return;
    *(struct pal_result_layout*)dst = *(struct pal_result_layout*)src;
}

PAL_WEAK void pal_result_release(void *result)
{
    (void)result;
}

PAL_WEAK void pal_result_set(void *result, uint32_t status,
                             const char *file, int line)
{
    if (!result) return;
    struct pal_result_layout *r = result;
    r->source_file = (char*)file;
    r->status      = (int32_t)status;
    r->line        = (uint16_t)line;
    r->extended    = 0;
}

/* ------------ aligned allocator ---------------------------- */

PAL_WEAK void *pal_aligned_nothrow_alloc(size_t size, size_t align,
                                         const void *nothrow_tag)
{
    (void)nothrow_tag;
    if (align < sizeof(void*)) align = sizeof(void*);
    void *p = NULL;
    if (posix_memalign(&p, align, size) != 0) return NULL;
    return p;
}

PAL_WEAK const void *const pal_std_nothrow_tag = (const void*)0;

/* ------------ FileIoCompletionPort constructor stub -------- */

PAL_WEAK void io_completion_port_construct(void *self)
{
    if (self) memset(self, 0, 0x1c0);
}

/* ------------ pal_boot.c extern stubs ---------------------- *
 * These are referenced by the translated pal_init_libos_params
 * (FUN_0020ba60) and pal_init_abi_table (FUN_002053e0). They
 * will be superseded by translations in later milestones.
 */

/* DAT_00369ec8 — host ABI table template (16 bytes header + sentinel) */
PAL_WEAK uint8_t g_host_abi_table_template[256];

/* DAT_003b2138 — runtime callback state (256 bytes) */
PAL_WEAK uint8_t g_runtime_callback_state_template[256];

/* DAT_00369f30 — init tag constant */
PAL_WEAK uint8_t g_libos_init_tag[64];

/* Std runtime_error vtable/dtor placeholders — throwing runtime errors
 * is a noreturn path we route through abort() in the stub. */
PAL_WEAK void *g_std_runtime_error_typeinfo = NULL;
PAL_WEAK void *g_std_runtime_error_dtor_ptr = NULL;

/* Stubs that get called from pal_boot.c only on error paths. */

PAL_WEAK void pal_abi_dispatch_init(void *abi_dispatch_slot,
                                    void *image_handle,
                                    void *init_tag)
{
    (void)abi_dispatch_slot; (void)image_handle; (void)init_tag;
    /* TODO(M?): translate FUN_0020bcf0. */
}

PAL_WEAK void pal_abi_query_version(void *abi_dispatch_slot,
                                    uint64_t *out_version,
                                    uint32_t *out_flags)
{
    (void)abi_dispatch_slot;
    if (out_version) *out_version = 0;
    if (out_flags)   *out_flags   = 0;
}

/* Image-metadata accessors — TODO translate as pal_image.c. */
PAL_WEAK uint64_t pal_image_get_field_c90(void *h){ (void)h; return 0; }
PAL_WEAK uint64_t pal_image_get_field_c80(void *h){ (void)h; return 0; }
PAL_WEAK uint64_t pal_image_get_field_ca0(void *h){ (void)h; return 0; }
PAL_WEAK uint64_t pal_image_get_field_db0(void *h){ (void)h; return 0; }
PAL_WEAK uint32_t pal_image_get_field_dd0(void *h){ (void)h; return 0; }
PAL_WEAK char     pal_image_meta_is_split(uint64_t m){ (void)m; return 0; }
PAL_WEAK uint64_t pal_image_meta_resolve(uint64_t m){ return m; }

/* Parameter-buffer inner object — pal_parambuf.c TODO. */
PAL_WEAK int      pal_parambuf_reserve(void *p, void *h, uint64_t s){ (void)p;(void)h;(void)s; return 0; }
PAL_WEAK uint64_t pal_parambuf_append (void *p, uint64_t v){ (void)p; return v; }
PAL_WEAK uint32_t pal_parambuf_cursor (void *p){ (void)p; return 0; }
PAL_WEAK void    *pal_parambuf_tail   (void *p){ (void)p; return NULL; }

/* Enclave capability probe — FUN_0020d9c0 — stub returns 0 (no enclave). */
PAL_WEAK uint8_t  pal_probe_has_enclave(void){ return 0; }

/* C++ exception / assert plumbing used by the translated boot functions
 * on the error paths. Route all terminal paths through abort().
 */
PAL_WEAK void *pal_cxa_allocate_exception(uint64_t size)
{
    void *p = calloc(1, size ? size : 64);
    return p;
}

PAL_WEAK void pal_runtime_error_ctor(void *ex, const char *what)
{
    (void)ex;
    fprintf(stderr, "[PAL-RUNTIME-ERROR-CTOR] %s\n", what ? what : "?");
}

PAL_WEAK void pal_cxa_throw(void *ex, void *tinfo, void *dtor) __attribute__((noreturn));
PAL_WEAK void pal_cxa_throw(void *ex, void *tinfo, void *dtor)
{
    (void)ex; (void)tinfo; (void)dtor;
    fprintf(stderr, "[PAL-CXA-THROW] terminating\n");
    abort();
}

PAL_WEAK void pal_stack_chk_fail(void) __attribute__((noreturn));
PAL_WEAK void pal_stack_chk_fail(void)
{
    fprintf(stderr, "[PAL-STACK-CHK] canary failed\n");
    abort();
}

PAL_WEAK int *pal_errno_location(void)
{
    return &errno;
}

PAL_WEAK void pal_assert_fail(const char *expr, int err) __attribute__((noreturn));
PAL_WEAK void pal_assert_fail(const char *expr, int err)
{
    fprintf(stderr, "[PAL-ASSERT] %s (errno=%d)\n", expr ? expr : "?", err);
    abort();
}
