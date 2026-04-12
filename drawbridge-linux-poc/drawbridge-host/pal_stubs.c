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
