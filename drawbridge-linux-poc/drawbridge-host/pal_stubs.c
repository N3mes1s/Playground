/*
 * pal_stubs.c — Fail-loud placeholders and genuine minor helpers
 *
 * Per the full-component rewrite plan
 * (/root/.claude/plans/hashed-sparking-lake.md):
 *   "No weak stubs — any untranslated function is abort() with the
 *    component/func_id so gaps are visible."
 *
 * This file therefore splits into three classes of symbol:
 *
 *   1. UNIMPLEMENTED  — body is `PAL_UNIMPLEMENTED("pal_xxx")` which
 *      logs and aborts.  As each Wave-1/Wave-2 agent lands its real
 *      translation, that strong symbol wins over the fallback here.
 *
 *   2. GENUINE        — helpers whose "stub" was already a real
 *      implementation (pal_result_* memset/compare, pal_aligned_
 *      nothrow_alloc wrapping posix_memalign, pal_cxa_throw routing
 *      to abort, pal_gettid → SYS_gettid).  Kept weak so later
 *      component-owned versions can still override if they need to.
 *
 *   3. DATA           — globals (g_pal_instance, g_host_abi_table_
 *      template, etc.) that occupy memory; no behavior to fail-loud
 *      on.  Kept as zeroed storage.
 *
 * Every symbol in class 1 annotates its ELF FUN_* and the component
 * (C1..C21) that owns it per the approved plan so the eventual
 * translation target is obvious.
 */

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>

#define PAL_WEAK __attribute__((weak))

/* ==================================================================
 * Fail-loud primitive (class 1)
 * ================================================================== */

static void pal_unimplemented_impl(const char *who) __attribute__((noreturn));
static void pal_unimplemented_impl(const char *who)
{
    fprintf(stderr, "[PAL-UNIMPLEMENTED] %s called before a real "
                    "translation exists — see plan component mapping.\n",
                    who ? who : "?");
    fflush(stderr);
    abort();
}

#define PAL_UNIMPLEMENTED(name) pal_unimplemented_impl(name)

/* ==================================================================
 * Class 2: genuine helpers that already match ELF semantics.
 * Kept weak so component translations can still replace them.
 * ================================================================== */

/* errno / assert plumbing --------------------------------------- */

PAL_WEAK int *pal_abi_errno_location(void) { return &errno; }
PAL_WEAK int *pal_errno_location(void)     { return &errno; }

PAL_WEAK void pal_abi_assert_fail(const char *msg, int err) __attribute__((noreturn));
PAL_WEAK void pal_abi_assert_fail(const char *msg, int err)
{
    fprintf(stderr, "[PAL-ASSERT] %s (errno=%d)\n", msg ? msg : "?", err);
    abort();
}

PAL_WEAK void pal_assert_fail(const char *expr, int err) __attribute__((noreturn));
PAL_WEAK void pal_assert_fail(const char *expr, int err)
{
    fprintf(stderr, "[PAL-ASSERT] %s (errno=%d)\n", expr ? expr : "?", err);
    abort();
}

PAL_WEAK void pal_abi_stack_chk_fail(void) __attribute__((noreturn));
PAL_WEAK void pal_abi_stack_chk_fail(void)
{
    fprintf(stderr, "[PAL-STACK-CHK] canary mismatch\n");
    abort();
}

PAL_WEAK void pal_stack_chk_fail(void) __attribute__((noreturn));
PAL_WEAK void pal_stack_chk_fail(void)
{
    fprintf(stderr, "[PAL-STACK-CHK] canary failed\n");
    abort();
}

PAL_WEAK void pal_panic_assert(const char *expr, int linux_errno) __attribute__((noreturn));
PAL_WEAK void pal_panic_assert(const char *expr, int linux_errno)
{
    fprintf(stderr, "[PAL-PANIC] %s (errno=%d)\n", expr ? expr : "?", linux_errno);
    abort();
}

PAL_WEAK void pal_abort(void) __attribute__((noreturn));
PAL_WEAK void pal_abort(void) { abort(); }

/* pal_result helpers (CLAUDE.md documented struct: 24 B) -------- */

struct pal_result_layout {
    char    *source_file;   /* +0x00 */
    int32_t  status;        /* +0x08 */
    uint16_t line;          /* +0x0C */
    uint16_t _pad;
    int32_t  extended;      /* +0x10 */
    uint32_t _pad2;
};

PAL_WEAK void pal_result_init(void *r)
{ if (r) memset(r, 0, sizeof(struct pal_result_layout)); }

PAL_WEAK void pal_result_fini(void *r) { (void)r; }

PAL_WEAK char pal_result_is_error(void *r)
{ return r ? (((struct pal_result_layout*)r)->status < 0) : (char)0; }

PAL_WEAK char pal_result_succeeded(void *r)
{ return r ? (((struct pal_result_layout*)r)->status >= 0) : (char)1; }

PAL_WEAK void pal_result_combine(void *dst, void *src)
{
    if (!dst || !src) return;
    struct pal_result_layout *d = dst, *s = src;
    if (d->status >= 0 && s->status < 0) *d = *s;
}

PAL_WEAK void pal_result_copy(void *dst, void *src)
{
    if (!dst || !src) return;
    *(struct pal_result_layout*)dst = *(struct pal_result_layout*)src;
}

PAL_WEAK void pal_result_release(void *r) { (void)r; }

PAL_WEAK void pal_result_set(void *r, uint32_t status,
                             const char *file, int line)
{
    if (!r) return;
    struct pal_result_layout *x = r;
    x->source_file = (char*)file;
    x->status      = (int32_t)status;
    x->line        = (uint16_t)line;
    x->extended    = 0;
}

/* aligned allocator (posix_memalign wrapper — legit) ------------ */

PAL_WEAK void *pal_aligned_nothrow_alloc(size_t size, size_t align,
                                         const void *nothrow_tag)
{
    (void)nothrow_tag;
    if (align < sizeof(void*)) align = sizeof(void*);
    void *p = NULL;
    if (posix_memalign(&p, align, size) != 0) return NULL;
    return p;
}

PAL_WEAK void *pal_nothrow_alloc(size_t size, const void *nothrow_tag)
{ (void)nothrow_tag; return calloc(1, size); }

/* C++ runtime — abort() path is correct (no exception handling) - */

PAL_WEAK void *pal_cxa_allocate_exception(uint64_t size)
{ return calloc(1, size ? size : 64); }

PAL_WEAK void pal_runtime_error_ctor(void *ex, const char *what)
{ (void)ex; fprintf(stderr, "[PAL-RUNTIME-ERROR] %s\n", what ? what : "?"); }

PAL_WEAK void pal_cxa_throw(void *ex, void *tinfo, void *dtor) __attribute__((noreturn));
PAL_WEAK void pal_cxa_throw(void *ex, void *tinfo, void *dtor)
{ (void)ex; (void)tinfo; (void)dtor;
  fprintf(stderr, "[PAL-CXA-THROW] terminating\n"); abort(); }

/* tid + thread helpers (thin syscall/libc wrappers) ------------- */

PAL_WEAK uint32_t pal_gettid(void) { return (uint32_t)syscall(SYS_gettid); }

PAL_WEAK int pal_pthread_create(void *tid_out, void *attr,
                                void *(*start)(void *), void *arg)
{ (void)attr; return pthread_create((pthread_t*)tid_out, NULL, start, arg); }

/* ==================================================================
 * Class 3: DATA globals — must exist somewhere, behavior not
 * applicable.  Real values get populated by the owning components.
 * ================================================================== */

PAL_WEAK uint8_t g_host_abi_table_template[256];         /* DAT_00369ec8 */
PAL_WEAK uint8_t g_runtime_callback_state_template[256]; /* DAT_003b2138 */
PAL_WEAK uint8_t g_libos_init_tag[64];                   /* DAT_00369f30 */
PAL_WEAK uint8_t g_pal_instance[0x1000];                 /* DAT_0036f598 */
PAL_WEAK void   *g_std_runtime_error_typeinfo = NULL;
PAL_WEAK void   *g_std_runtime_error_dtor_ptr = NULL;
PAL_WEAK const void *const pal_std_nothrow_tag = (const void*)0;

/* ==================================================================
 * Class 1: fail-loud placeholders.  Each has its ELF FUN_* and the
 * component (C1..C21) that owns it per the plan.  When the owner
 * lands its real translation, that strong symbol supersedes these.
 * ================================================================== */

/* ---- C2  Boot Orchestrator ---- FUN_0020bcf0 */
PAL_WEAK void pal_abi_dispatch_init(void *a, void *b, void *c)
{ (void)a; (void)b; (void)c; PAL_UNIMPLEMENTED("pal_abi_dispatch_init"); }

/* ---- C3  ABI Dispatcher ---- FUN_0029fd00 */
PAL_WEAK void pal_abi_query_version(void *a, uint64_t *v, uint32_t *f)
{ (void)a; (void)v; (void)f; PAL_UNIMPLEMENTED("pal_abi_query_version"); }

/* ---- C1  PE Loader / image-metadata accessors ---- FUN_00297c90/c80/ca0/db0/dd0 */
PAL_WEAK uint64_t pal_image_get_field_c90(void *h)
{ (void)h; PAL_UNIMPLEMENTED("pal_image_get_field_c90"); }
PAL_WEAK uint64_t pal_image_get_field_c80(void *h)
{ (void)h; PAL_UNIMPLEMENTED("pal_image_get_field_c80"); }
PAL_WEAK uint64_t pal_image_get_field_ca0(void *h)
{ (void)h; PAL_UNIMPLEMENTED("pal_image_get_field_ca0"); }
PAL_WEAK uint64_t pal_image_get_field_db0(void *h)
{ (void)h; PAL_UNIMPLEMENTED("pal_image_get_field_db0"); }
PAL_WEAK uint32_t pal_image_get_field_dd0(void *h)
{ (void)h; PAL_UNIMPLEMENTED("pal_image_get_field_dd0"); }
PAL_WEAK char     pal_image_meta_is_split(uint64_t m)
{ (void)m; PAL_UNIMPLEMENTED("pal_image_meta_is_split"); }
PAL_WEAK uint64_t pal_image_meta_resolve(uint64_t m)
{ (void)m; PAL_UNIMPLEMENTED("pal_image_meta_resolve"); }

/* ---- C2  Boot param-buffer helpers ---- FUN_0029e430/e2c0/df10/df00 */
PAL_WEAK int      pal_parambuf_reserve(void *p, void *h, uint64_t s)
{ (void)p; (void)h; (void)s; PAL_UNIMPLEMENTED("pal_parambuf_reserve"); }
PAL_WEAK uint64_t pal_parambuf_append(void *p, uint64_t v)
{ (void)p; (void)v; PAL_UNIMPLEMENTED("pal_parambuf_append"); }
PAL_WEAK uint32_t pal_parambuf_cursor(void *p)
{ (void)p; PAL_UNIMPLEMENTED("pal_parambuf_cursor"); }
PAL_WEAK void    *pal_parambuf_tail(void *p)
{ (void)p; PAL_UNIMPLEMENTED("pal_parambuf_tail"); }

/* ---- C2  Enclave probe ---- FUN_0020d9c0 */
PAL_WEAK uint8_t  pal_probe_has_enclave(void)
{ PAL_UNIMPLEMENTED("pal_probe_has_enclave"); }

/* ---- C2  22-step boot helpers ---- FUN_00354250..FUN_00204da0 */
PAL_WEAK void pal_runtime_params_init(void)         { PAL_UNIMPLEMENTED("pal_runtime_params_init"); }
PAL_WEAK void pal_runtime_params_commit(void)       { PAL_UNIMPLEMENTED("pal_runtime_params_commit"); }
PAL_WEAK void pal_logging_init(uint8_t d)           { (void)d; PAL_UNIMPLEMENTED("pal_logging_init"); }
PAL_WEAK void pal_debugger_setup(void)              { PAL_UNIMPLEMENTED("pal_debugger_setup"); }
PAL_WEAK char pal_threading_needed(void *i)         { (void)i; PAL_UNIMPLEMENTED("pal_threading_needed"); }
PAL_WEAK int  pal_logger_thread_create(void)        { PAL_UNIMPLEMENTED("pal_logger_thread_create"); }
PAL_WEAK void pal_dynlink_init(void)                { PAL_UNIMPLEMENTED("pal_dynlink_init"); }
PAL_WEAK int  pal_module_loader_init(void)          { PAL_UNIMPLEMENTED("pal_module_loader_init"); }
PAL_WEAK void pal_library_init(void)                { PAL_UNIMPLEMENTED("pal_library_init"); }
PAL_WEAK int  pal_setrlimit(int w, int s, int h)    { (void)w;(void)s;(void)h; PAL_UNIMPLEMENTED("pal_setrlimit"); }
PAL_WEAK int  pal_fd_limit_get(int r, void *o)      { (void)r;(void)o; PAL_UNIMPLEMENTED("pal_fd_limit_get"); }
PAL_WEAK int  pal_fd_limit_set(int r, const void *i){ (void)r;(void)i; PAL_UNIMPLEMENTED("pal_fd_limit_set"); }
PAL_WEAK void pal_post_boot_init_1(void *c)         { (void)c; PAL_UNIMPLEMENTED("pal_post_boot_init_1"); }
PAL_WEAK void pal_post_boot_init_2(void)            { PAL_UNIMPLEMENTED("pal_post_boot_init_2"); }
PAL_WEAK void pal_post_boot_init_3(void)            { PAL_UNIMPLEMENTED("pal_post_boot_init_3"); }
PAL_WEAK void pal_io_finalize(void)                 { PAL_UNIMPLEMENTED("pal_io_finalize"); }
PAL_WEAK void pal_kernel_version_log(void)          { PAL_UNIMPLEMENTED("pal_kernel_version_log"); }

/* ---- C6  Thread-subsystem helpers ---- FUN_00207280/FUN_00355400..470/FUN_00354170 */
PAL_WEAK char  pal_thread_validate_param(void)       { PAL_UNIMPLEMENTED("pal_thread_validate_param"); }
PAL_WEAK char  pal_thread_validate_param_ex(void *p) { (void)p; PAL_UNIMPLEMENTED("pal_thread_validate_param_ex"); }
PAL_WEAK void  pal_kthread_construct(void *kt)       { (void)kt; PAL_UNIMPLEMENTED("pal_kthread_construct"); }
PAL_WEAK int   pal_mutex_lock(void *m)               { (void)m; PAL_UNIMPLEMENTED("pal_mutex_lock"); }
PAL_WEAK int   pal_mutex_unlock(void *m)             { (void)m; PAL_UNIMPLEMENTED("pal_mutex_unlock"); }
PAL_WEAK void  pal_guest_dispatch_nt(void)           { PAL_UNIMPLEMENTED("pal_guest_dispatch_nt"); }
PAL_WEAK void  pal_guest_dispatch_linux(void)        { PAL_UNIMPLEMENTED("pal_guest_dispatch_linux"); }
PAL_WEAK long  pal_thread_state_alloc(int k)         { (void)k; PAL_UNIMPLEMENTED("pal_thread_state_alloc"); }
PAL_WEAK void  pal_thread_destroy(void *kt)          { (void)kt; PAL_UNIMPLEMENTED("pal_thread_destroy"); }
PAL_WEAK void *pal_ts_acquire(long ts)               { (void)ts; PAL_UNIMPLEMENTED("pal_ts_acquire"); }
PAL_WEAK void  pal_ts_arm(long ts)                   { (void)ts; PAL_UNIMPLEMENTED("pal_ts_arm"); }
PAL_WEAK void  pal_ts_set_attached(long ts)          { (void)ts; PAL_UNIMPLEMENTED("pal_ts_set_attached"); }
PAL_WEAK void  pal_ts_release(long ts)               { (void)ts; PAL_UNIMPLEMENTED("pal_ts_release"); }
PAL_WEAK void  pal_ts_release_alt(long ts)           { (void)ts; PAL_UNIMPLEMENTED("pal_ts_release_alt"); }
PAL_WEAK uint64_t pal_instance_get_attr(void *h)     { (void)h; PAL_UNIMPLEMENTED("pal_instance_get_attr"); }
PAL_WEAK int   pal_pthread_attr_init(void *a)        { (void)a; PAL_UNIMPLEMENTED("pal_pthread_attr_init"); }
PAL_WEAK int   pal_pthread_attr_set_detach(void *a, uint64_t f)
                                                    { (void)a; (void)f; PAL_UNIMPLEMENTED("pal_pthread_attr_set_detach"); }
PAL_WEAK int   pal_pthread_attr_destroy(void *a)     { (void)a; PAL_UNIMPLEMENTED("pal_pthread_attr_destroy"); }
PAL_WEAK void  pal_result_set_from_errno(void *r, const char *f, uint16_t l, int e)
                                                    { (void)r;(void)f;(void)l;(void)e; PAL_UNIMPLEMENTED("pal_result_set_from_errno"); }
PAL_WEAK char  pal_result_is_error_full(void *r)     { (void)r; PAL_UNIMPLEMENTED("pal_result_is_error_full"); }

PAL_WEAK void  pal_pal_thread_starting(void *x)      { (void)x; PAL_UNIMPLEMENTED("pal_pal_thread_starting"); }
PAL_WEAK void *pal_thread_local_alloc(void)          { PAL_UNIMPLEMENTED("pal_thread_local_alloc"); }
PAL_WEAK int   pal_thread_state_setup(void *tl, void *out)
                                                    { (void)tl;(void)out; PAL_UNIMPLEMENTED("pal_thread_state_setup"); }
PAL_WEAK int   pal_thread_state_stack(void *s, long *b, long *l)
                                                    { (void)s;(void)b;(void)l; PAL_UNIMPLEMENTED("pal_thread_state_stack"); }
PAL_WEAK int   pal_thread_state_finalize(void *s)    { (void)s; PAL_UNIMPLEMENTED("pal_thread_state_finalize"); }
PAL_WEAK int   pal_teb_register(void *d, int f)      { (void)d;(void)f; PAL_UNIMPLEMENTED("pal_teb_register"); }
PAL_WEAK void  pal_sigalt_init(void *c)              { (void)c; PAL_UNIMPLEMENTED("pal_sigalt_init"); }
PAL_WEAK void  pal_sigalt_set_signo(void *c, int s)  { (void)c;(void)s; PAL_UNIMPLEMENTED("pal_sigalt_set_signo"); }
PAL_WEAK int   pal_sigalt_install(int h, void *c, void *o)
                                                    { (void)h;(void)c;(void)o; PAL_UNIMPLEMENTED("pal_sigalt_install"); }
PAL_WEAK void  pal_observer_notify(int f, void *k, uint64_t s)
                                                    { (void)f;(void)k;(void)s; PAL_UNIMPLEMENTED("pal_observer_notify"); }
PAL_WEAK int   pal_signal_mask_fork(void *c)         { (void)c; PAL_UNIMPLEMENTED("pal_signal_mask_fork"); }
PAL_WEAK void  pal_signal_mask_release(void *t)      { (void)t; PAL_UNIMPLEMENTED("pal_signal_mask_release"); }
PAL_WEAK void  pal_invoke_guest_entry(void *entry, void *stack,
                                       void *tcb_slot, void *arg) __attribute__((noreturn));
PAL_WEAK void  pal_invoke_guest_entry(void *entry, void *stack,
                                       void *tcb_slot, void *arg)
{ (void)entry; (void)stack; (void)tcb_slot; (void)arg;
  PAL_UNIMPLEMENTED("pal_invoke_guest_entry"); }

/* ---- C15  Fiber Scheduler ---- FUN_00355d60/FUN_00279f90/FUN_00252bf0 */
PAL_WEAK void pal_scheduler_register(const void *c)   { (void)c; PAL_UNIMPLEMENTED("pal_scheduler_register"); }
PAL_WEAK void pal_aio_callback_register(void (*cb)(void*, long))
                                                    { (void)cb; PAL_UNIMPLEMENTED("pal_aio_callback_register"); }
PAL_WEAK void pal_aio_callback(void *a, long b)       { (void)a; (void)b; PAL_UNIMPLEMENTED("pal_aio_callback"); }

/* ---- C14  Async I/O ---- FUN_001f1fd0 (FileIoCompletionPort ctor) */
PAL_WEAK void io_completion_port_construct(void *self)
{ (void)self; PAL_UNIMPLEMENTED("io_completion_port_construct"); }
