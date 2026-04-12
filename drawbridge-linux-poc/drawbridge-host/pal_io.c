/*
 * pal_io.c - Host-side I/O subsystem bring-up (M4).
 *
 * Translated from the decompiled ELF host (analysis/sqlservr_FULL.c):
 *
 *   FUN_00252b70 @ line 123314  -> pal_open_dev_null
 *       Opens "/dev/null" O_WRONLY and stashes the fd in the global
 *       DAT_00369ea8 (aka g_NullFileDesc).  Panics on failure.
 *
 *   FUN_001f1c50 @ line 52045   -> pal_io_create_completion_port
 *       Allocates a 0x1c0-byte FileIoCompletionPort object, runs its
 *       C++ constructor (FUN_001f1fd0), then invokes the io_setup
 *       wrapper (FUN_00202100 -> syscall 0xce) with nr_events=0x400.
 *
 *   FUN_001f1fd0 @ line 52193   -> io_completion_port_construct
 *       The in-place constructor for the 0x1c0-byte object.  Declared
 *       as an extern stub here; full translation belongs to a later
 *       milestone.
 *
 *   FUN_00202100 @ line 67430   -> pal_io_setup_wrapper
 *       Two-line stub: tail-calls FUN_00354180(0xce, nr_events, ctx).
 *       That wrapper performs the raw "mov rax, 0xce; syscall"
 *       sequence for Linux AIO io_setup (syscall 206).
 *
 * M4: this TU is not yet wired into the boot path; it exists so the
 * translation is captured and compiles cleanly.  Today's crash is still
 * DK #234 / RIP 0x1803a0880; nothing here should change that.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "pal_internal.h"

/* ============================================================
 * Globals
 * ============================================================
 * DAT_00369ea8 in the ELF - referred to as "g_NullFileDesc" by the
 * assertion string in FUN_00252b70.  Initialized to -1 so the
 * "DAT >= 0" assertion semantics are preserved before open() runs.
 */
static int g_dev_null_fd = -1;

/* ============================================================
 * Linux AIO context handle.
 *
 * io_setup(2) writes an aio_context_t (opaque unsigned long) through
 * its out-pointer.  The ELF's FileIoCompletionPort stores this at
 * [object + 0x168] (see FUN_001f1e20 @ line 52132).
 * ============================================================ */
typedef unsigned long pal_aio_context_t;

/* Default nr_events passed to io_setup by FUN_001f1e20. */
#define PAL_IO_SETUP_NR_EVENTS  0x400u

/* Size/alignment of the FileIoCompletionPort object as allocated at
 * line 52057: FUN_00353ee0(0x1c0, 0x40, PTR_nothrow_003675a8).
 * The allocator signature is (size, alignment, nothrow_tag).
 */
#define PAL_IO_COMPLETION_PORT_SIZE        0x1c0u
#define PAL_IO_COMPLETION_PORT_ALIGNMENT   0x40u

/* Offset of m_KernelAioContext within the FileIoCompletionPort object
 * (see FUN_001f1e20 @ line 52132/52137).  Recorded for future use;
 * not dereferenced here because the constructor translation is still
 * pending.
 */
#define PAL_IO_COMPLETION_PORT_AIOCTX_OFF  0x168u

/* ============================================================
 * Extern stubs for cross-subsystem calls that are not yet translated.
 *
 * These preserve exact ELF semantics.  TODO: replace with real
 * translations as later milestones land.
 * ============================================================ */

/* FUN_00353ee0: aligned, no-throw operator new.  Returns NULL on OOM.
 * TODO(M?): translate to aligned_alloc()/posix_memalign() wrapper.
 */
extern void *pal_aligned_nothrow_alloc(size_t size, size_t align,
                                       const void *nothrow_tag);

/* PTR_nothrow_003675a8: address of the std::nothrow_t sentinel.
 * Only its address is observed; the value is never dereferenced.
 */
extern const void *const pal_std_nothrow_tag;

/* FUN_001f1fd0: in-place constructor for the 0x1c0-byte
 * FileIoCompletionPort object.  Touches globals DAT_0036f598,
 * DAT_0036f0c8 and various helpers (FUN_001f5120, FUN_0029a4e0,
 * FUN_002c2000, operator_new, FUN_001f5250).
 * TODO(M?): translate FileIoCompletionPort ctor.
 */
extern void io_completion_port_construct(void *self);

/* FUN_0028e070 / FUN_0028e530 / FUN_0028e560 / FUN_0028e130 /
 * FUN_0028e0d0: the pal_result (HRESULT+file+line+extended) helpers
 * from the NTUM error-handling pattern.  Signatures per CLAUDE.md.
 * TODO(pal_abi.c): share these once pal_abi lands its translation.
 */
extern void  pal_result_init(void *result);
extern char  pal_result_succeeded(void *result);
extern void  pal_result_copy(void *dst, void *src);
extern void  pal_result_release(void *result);
extern void  pal_result_set(void *result, int32_t status,
                            const char *file, uint16_t line);

/* FUN_001c1100: __assert_fail-style no-return panic used throughout
 * the ELF.  Prints "<expr> at <file>" and aborts.
 */
extern void pal_panic_assert(const char *expr, int linux_errno)
    __attribute__((noreturn));

/* FUN_00353860: returns pointer to errno (__errno_location equivalent).
 * TODO: inline as &errno once we are sure of TLS semantics.
 */
static inline int *pal_errno_location(void)
{
    return &errno;
}

/* ============================================================
 * pal_open_dev_null - FUN_00252b70 @ analysis/sqlservr_FULL.c:123314
 *
 * ELF body (simplified):
 *     DAT_00369ea8 = FUN_003536b0("/dev/null", 1);
 *     if (DAT_00369ea8 >= 0) return;
 *     FUN_001c1100("g_NullFileDesc >= 0", *FUN_00353860());
 *
 * FUN_003536b0 is a thin wrapper around the libc open() entry
 * (FUN_003533e0).  Flag "1" is O_WRONLY.
 * ============================================================ */
int pal_open_dev_null(void)
{
    g_dev_null_fd = open("/dev/null", O_WRONLY);
    if (g_dev_null_fd >= 0) {
        return g_dev_null_fd;
    }

    /* Matches the ELF assert; never returns. */
    pal_panic_assert("g_NullFileDesc >= 0", *pal_errno_location());
    return -1; /* unreachable */
}

/* ============================================================
 * pal_io_setup_wrapper - FUN_00202100 @ line 67430
 *
 * ELF body: `FUN_00354180(0xce, param_1, param_2);`
 * which is `mov rax, 0xce; syscall` - the raw Linux io_setup.
 *
 * Signature in the ELF returns void but the return value (syscall
 * result in rax) is inspected by the caller (FUN_001f1e20 checks
 * `lVar5 == -1`).  We reflect that: callers compare against -1.
 * ============================================================ */
static long pal_io_setup_wrapper(uint32_t nr_events,
                                 pal_aio_context_t *ctx_idp)
{
    /* Linux io_setup is syscall 206 (0xce).  Glibc does not expose
     * it as a wrapper, so we call it raw - exactly like FUN_00354180.
     */
    long rc = syscall(SYS_io_setup, (unsigned long)nr_events, ctx_idp);
    if (rc < 0) {
        /* syscall() sets errno and returns -1; the ELF raw wrapper
         * returns the negative errno directly, but every caller only
         * checks for -1, so the observable behavior matches.
         */
        return -1;
    }
    return rc;
}

/* ============================================================
 * pal_io_create_completion_port - FUN_001f1c50 @ line 52045
 *
 * True ELF signature:
 *     (pal_result *result, byte flags, long *out_port_slot)
 *
 * pal_internal.h currently exposes only the out-slot as `void *`.
 * We translate the full control flow internally and accept the
 * simplified public signature.  The optional flags byte and the
 * pal_result object are handled via the helper stubs above.
 *
 * Control flow (exact):
 *   1. pal_result_init(result)
 *   2. obj = pal_aligned_nothrow_alloc(0x1c0, 0x40, &nothrow);
 *   3. if (obj) io_completion_port_construct(obj);
 *   4. assert(&obj_local != out_port_slot, "self-assignment");
 *   5. if (*out_port_slot != 0) pal_result_release(*out_port_slot);
 *   6. *out_port_slot = obj;
 *   7. if (obj == 0) -> set E_OUTOFMEMORY (0xc0000017),
 *                       FileIoCompletionPort.cpp:0x85, propagate.
 *   8. if (pal_result_succeeded(result)) {
 *          assert(*out_port_slot != 0);
 *          FUN_001f1e20(result, obj);   // runs io_setup
 *      }
 *   9. if ((succeeded & flags) == 1) FUN_001f1b40(result, obj);
 *
 * Steps 8/9 are the branches that invoke the io_setup wrapper via
 * FUN_001f1e20.  We preserve the structure and mark the deeper
 * kernel-context init as TODO.
 * ============================================================ */

/* FUN_001f1e20: arms io_setup on a freshly-constructed object.
 * Translated here in-line because this is the fd-bearing call.
 */
static void io_completion_port_arm_aio(void *result_obj, void *port_obj)
{
    /* The ELF asserts [port + 0x168] == NULL before calling. */
    pal_aio_context_t *ctx_slot =
        (pal_aio_context_t *)((char *)port_obj
                              + PAL_IO_COMPLETION_PORT_AIOCTX_OFF);

    if (*ctx_slot != 0) {
        pal_panic_assert("m_KernelAioContext == nullptr", 0);
    }

    long rc = pal_io_setup_wrapper(PAL_IO_SETUP_NR_EVENTS, ctx_slot);

    int saved_errno = 0;
    if (rc == -1) {
        saved_errno = *pal_errno_location();
    }

    /* FUN_0028e0f0(result, "FileIoCompletionPort.cpp", 0xe9, errno)
     * TODO(pal_abi.c): wire the pal_result "set from errno" helper.
     */
    (void)result_obj;
    (void)saved_errno;

    if (!pal_result_succeeded(result_obj)) {
        /* Logging branch - io_setup failed.  TODO: hook into the
         * host's tracing once pal_abi exposes it.
         */
        return;
    }

    if (*ctx_slot == 0) {
        pal_panic_assert("m_KernelAioContext != nullptr", 0);
    }
}

/* FUN_001f1b40: the "success-with-flag" finisher.  Not needed at
 * M4 - the public entry point below ignores the optional flag.
 */
static void io_completion_port_finalize(void *result_obj, void *port_obj)
{
    /* TODO(M?): translate FUN_001f1b40. */
    (void)result_obj;
    (void)port_obj;
}

int pal_io_create_completion_port(void *out_port)
{
    /* Synthetic local pal_result object (64 bytes is comfortably
     * larger than the 24-byte struct defined in CLAUDE.md).
     */
    uint64_t result_storage[8] = { 0 };
    void *result = result_storage;

    long *out_slot = (long *)out_port;
    if (out_slot == NULL) {
        return -1;
    }

    pal_result_init(result);

    /* Step 2: allocate the 0x1c0-byte FileIoCompletionPort object. */
    void *obj = pal_aligned_nothrow_alloc(PAL_IO_COMPLETION_PORT_SIZE,
                                          PAL_IO_COMPLETION_PORT_ALIGNMENT,
                                          pal_std_nothrow_tag);

    /* Step 3: run the C++ constructor on successful alloc. */
    if (obj != NULL) {
        io_completion_port_construct(obj);
    }

    /* Step 4: self-assignment guard (local != slot).  Our synthesized
     * local cannot alias out_slot in practice, but preserve the check.
     */
    if ((void *)&obj == (void *)out_slot) {
        pal_panic_assert("We should be performing self assignment", 0);
    }

    /* Step 5: release any previous port sitting in the slot. */
    if (*out_slot != 0) {
        pal_result_release((void *)*out_slot);
    }

    /* Step 6: publish the (possibly NULL) object. */
    *out_slot = (long)obj;

    /* Step 7: OOM path. */
    if (obj == NULL) {
        pal_result_set(result, (int32_t)0xc0000017,
                       "FileIoCompletionPort.cpp", 0x85);
        /* ELF then copies into param_1 and releases the local; the
         * consolidated result object here serves both roles.
         */
        return -1;
    }

    /* Step 8: arm io_setup on success. */
    if (pal_result_succeeded(result)) {
        if (*out_slot == 0) {
            pal_panic_assert("m_object != nullptr", 0);
        }
        io_completion_port_arm_aio(result, obj);
    }

    /* Step 9: optional finalizer when succeeded & flag bit are set.
     * The simplified public signature has no flag byte, so this
     * branch is intentionally skipped.  TODO: extend the header
     * signature to match the ELF if/when a caller needs it.
     */
    (void)io_completion_port_finalize;

    return pal_result_succeeded(result) ? 0 : -1;
}

/* ============================================================
 * Static asserts
 * ============================================================ */
_Static_assert(PAL_IO_COMPLETION_PORT_AIOCTX_OFF
                   < PAL_IO_COMPLETION_PORT_SIZE,
               "m_KernelAioContext must sit inside the object");
_Static_assert(sizeof(pal_aio_context_t) == sizeof(unsigned long),
               "aio_context_t is an opaque unsigned long per io_setup(2)");

/* ============================================================
 * Weak default definitions for the extern stubs.
 *
 * These keep the TU link-clean while the rest of the host is still
 * being translated.  When the real translations land in their own
 * TUs, those strong symbols will override these weak ones.
 * ============================================================ */

__attribute__((weak))
void *pal_aligned_nothrow_alloc(size_t size, size_t align,
                                const void *nothrow_tag)
{
    (void)nothrow_tag;
    void *p = NULL;
    if (posix_memalign(&p, align < sizeof(void *) ? sizeof(void *) : align,
                       size) != 0) {
        return NULL;
    }
    return p;
}

__attribute__((weak))
const void *const pal_std_nothrow_tag = (const void *)0;

__attribute__((weak))
void io_completion_port_construct(void *self)
{
    /* TODO: translate FUN_001f1fd0.  For now, zero the object so
     * the AIO context slot reads as 0 (matches fresh allocation).
     */
    if (self != NULL) {
        for (size_t i = 0; i < PAL_IO_COMPLETION_PORT_SIZE; i++) {
            ((volatile unsigned char *)self)[i] = 0;
        }
    }
}

__attribute__((weak)) void pal_result_init(void *r)    { (void)r; }
__attribute__((weak)) char pal_result_succeeded(void *r) { (void)r; return 1; }
__attribute__((weak)) void pal_result_copy(void *d, void *s)
    { (void)d; (void)s; }
__attribute__((weak)) void pal_result_release(void *r) { (void)r; }
__attribute__((weak)) void pal_result_set(void *r, int32_t s,
                                          const char *f, uint16_t l)
    { (void)r; (void)s; (void)f; (void)l; }

__attribute__((weak, noreturn))
void pal_panic_assert(const char *expr, int linux_errno)
{
    (void)expr;
    (void)linux_errno;
    __builtin_trap();
}
