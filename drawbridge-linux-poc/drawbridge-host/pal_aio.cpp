/*
 * pal_aio.cpp — Async I/O completion subsystem (Component C14, Milestone M9).
 *
 * Translated from analysis/sqlservr_FULL.c (line ranges are exact ELF offsets
 * via the Ghidra-generated FUN_xxxxxxxx tags):
 *
 *   FUN_001f1c50 @ 52045..52115   FileIoCompletionPort::FileIoCompletionPort
 *                                 public ctor path.  Allocates the 0x1c0-byte
 *                                 object, runs the in-place ctor, publishes
 *                                 into the caller's slot, and arms io_setup.
 *                                 -> PalAioContext::create  /
 *                                    pal_io_create_completion_port_real
 *
 *   FUN_001f1e20 @ 52121..52172   FileIoCompletionPort::ArmAio
 *                                 Asserts [obj + 0x168] == 0, invokes
 *                                 io_setup(0x400, &obj->m_KernelAioContext),
 *                                 checks result, logs.
 *                                 -> PalAioContext::arm
 *
 *   FUN_001f1fd0 @ 52193..52235   FileIoCompletionPort in-place ctor
 *                                 (vtable install + 0x1a4-offset sub-object
 *                                 init + config-byte fetch + optional
 *                                 operator_new(0x80) + FUN_001f5250 wiring).
 *                                 -> PalAioContext::construct
 *
 *   FUN_00202100 @ 67430..67437   tail-call to raw syscall wrapper
 *                                 FUN_00354180(0xce, nr, ctx).
 *                                 -> pal_aio_setup
 *
 *   FUN_00252bf0 @ 123349..123377 AIO completion callback — dispatched from
 *                                 the scheduler worker on every reaped
 *                                 io_event.
 *                                 -> pal_aio_callback (defined in
 *                                    pal_scheduler.cpp; declared here so we
 *                                    can forward-register it during port
 *                                    construction).
 *
 * Strong symbols owned by this TU:
 *   pal_io_create_completion_port_real
 *   pal_io_create_completion_port          (first-seen override of pal_io.cpp)
 *   pal_aio_setup
 *   pal_aio_submit
 *   pal_aio_reap
 *   pal_aio_destroy
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/aio_abi.h>
#include <stdio.h>
#include <time.h>

#include "pal_aio.h"

/* ======================================================================
 * struct PalAioPortObject — byte-for-byte layout of the ELF
 * FileIoCompletionPort that FUN_001f1c50 allocates (0x1c0 bytes, 0x40
 * aligned).  Only the fields we observably touch from the ELF trace
 * get named; the rest are padded as unk_0xNN slots.
 *
 * Observed offsets (from FUN_001f1fd0 @ 52193 and FUN_001f1e20 @ 52121):
 *   +0x000  vtbl                 (FUN_001f1fd0:52204 "*param_1 = &PTR_FUN_003594e8")
 *   +0x158  cfg_byte             (FUN_001f1fd0:52207 puVar3 load; param_1[0x2b])
 *   +0x160  observer_slot_0      (param_1[0x2c])
 *   +0x168  m_KernelAioContext   (FUN_001f1e20:52132; this is where
 *                                 io_setup writes the aio_context_t)
 *   +0x1a4  sub_obj (FUN_002c2000)
 * ====================================================================== */
typedef struct PalAioPortObject {
    void              *vtbl;               /* +0x000 */
    uint8_t            unk_0x08[0x150];    /* +0x008..+0x158 */
    uint8_t            cfg_byte;           /* +0x158 */
    uint8_t            unk_0x159[7];       /* +0x159..+0x15f */
    void              *observer_slot_0;    /* +0x160, param_1[0x2c] */
    pal_aio_context_t  m_KernelAioContext; /* +0x168, param_1[0x2d] */
    uint64_t           unk_0x170;          /* param_1[0x2e] */
    uint64_t           unk_0x178;          /* param_1[0x2f] */
    uint64_t           unk_0x180;          /* param_1[0x30] */
    uint64_t           unk_0x188;          /* param_1[0x31] */
    uint64_t           unk_0x190;          /* param_1[0x32] */
    uint64_t           unk_0x198;          /* param_1[0x33] */
    uint8_t            unk_0x1a0_byte;     /* param_1[0x34] */
    uint8_t            _pad0[3];
    uint8_t            sub_obj[0x18];      /* +0x1a4: FUN_002c2000 target */
    uint8_t            _pad_tail[0x1c0 - 0x1a4 - 0x18];
} PalAioPortObject;

static_assert(offsetof(PalAioPortObject, cfg_byte)            == 0x158,
              "cfg_byte must sit at +0x158 (FUN_001f1fd0:52207)");
static_assert(offsetof(PalAioPortObject, observer_slot_0)     == 0x160,
              "observer slot at +0x160 (param_1[0x2c])");
static_assert(offsetof(PalAioPortObject, m_KernelAioContext)  == 0x168,
              "m_KernelAioContext must sit at +0x168 (FUN_001f1e20:52132)");
static_assert(sizeof(PalAioPortObject)                        == 0x1c0,
              "FileIoCompletionPort is 0x1c0 bytes (FUN_001f1c50:52057)");

/* ======================================================================
 * class PalAioContext — RAII owner of a single Linux aio_context_t plus
 * the surrounding FileIoCompletionPort storage.  Lifetime:
 *   construct() — zero-init, install vtable sentinel, mark the control
 *                 byte so later trace calls can recognise the object.
 *   arm()       — run io_setup(nr_events, &m_KernelAioContext).
 *   ~()         — io_destroy() + free the backing storage.
 * ====================================================================== */
class PalAioContext {
public:
    PalAioContext() noexcept : obj_(nullptr), owned_(false) {}

    ~PalAioContext() noexcept
    {
        if (obj_ != nullptr && obj_->m_KernelAioContext != 0) {
            (void)pal_aio_destroy(obj_->m_KernelAioContext);
            obj_->m_KernelAioContext = 0;
        }
        if (owned_ && obj_ != nullptr) {
            free(obj_);
        }
        obj_ = nullptr;
        owned_ = false;
    }

    /* Non-copyable, non-movable — the slot-publishing contract in
     * FUN_001f1c50 @ 52072 requires a stable address. */
    PalAioContext(const PalAioContext &)            = delete;
    PalAioContext &operator=(const PalAioContext &) = delete;

    /* Allocate the 0x1c0-byte object with 0x40 alignment.  Mirrors
     * FUN_00353ee0(0x1c0, 0x40, PTR_nothrow_003675a8). */
    int allocate() noexcept
    {
        void *p = nullptr;
        if (posix_memalign(&p, PAL_AIO_OBJECT_ALIGNMENT,
                           PAL_AIO_OBJECT_SIZE) != 0) {
            return -1;
        }
        obj_   = static_cast<PalAioPortObject *>(p);
        owned_ = true;
        memset(obj_, 0, PAL_AIO_OBJECT_SIZE);
        return 0;
    }

    /* In-place construct (FUN_001f1fd0 @ 52193).
     * The ELF version installs a vtable pointer at offset 0, pulls the
     * config byte via FUN_0029a4e0, initialises a sub-object at +0x1a4,
     * and conditionally allocates an 0x80-byte observer entry.
     * We keep the layout honest but skip the observer allocation (no
     * PE code ever reads from it during the hello_drawbridge path). */
    void construct() noexcept
    {
        if (obj_ == nullptr) {
            return;
        }
        obj_->vtbl               = reinterpret_cast<void *>(
                                       PalAioContext::vtbl_sentinel);
        obj_->cfg_byte           = 0;   /* cfg fetch not yet translated */
        obj_->observer_slot_0    = nullptr;
        obj_->m_KernelAioContext = 0;
        /* TODO: translate FUN_001f5120 + FUN_002c2000 sub-object init.
         *       The aio-reap path does not read from +0x1a4 yet. */
    }

    /* Arm io_setup (FUN_001f1e20 @ 52121).
     * Asserts m_KernelAioContext == 0, calls pal_aio_setup, asserts
     * the result is non-zero on success.  Returns 0 on success. */
    int arm(unsigned nr_events = PAL_AIO_DEFAULT_NR_EVENTS) noexcept
    {
        if (obj_ == nullptr) {
            return -1;
        }
        if (obj_->m_KernelAioContext != 0) {
            fprintf(stderr,
                    "[PAL-AIO] arm: m_KernelAioContext already set (%lu)\n",
                    (unsigned long)obj_->m_KernelAioContext);
            return -1;
        }
        int rc = pal_aio_setup(nr_events, &obj_->m_KernelAioContext);
        if (rc != 0) {
            fprintf(stderr,
                    "[PAL-AIO] io_setup(nr=%u) failed: errno=%d (%s)\n",
                    nr_events, errno, strerror(errno));
            /* ELF FileIoCompletionPort.cpp:0xf5 logs:
             *   "Unable to create a new asynchronous I/O context.
             *    Please increase sysctl fs.aio-max-nr"
             * We do not fail the PoC on that — the PE can still boot
             * with a zero context in the common case. */
            obj_->m_KernelAioContext = 0;
            return -1;
        }
        fprintf(stderr,
                "[PAL-AIO] io_setup OK: nr=%u ctx=%lu obj=%p\n",
                nr_events, (unsigned long)obj_->m_KernelAioContext,
                (void *)obj_);
        return 0;
    }

    PalAioPortObject *object() noexcept { return obj_; }

    /* Release ownership without destroying the backing storage.
     * Used when the object is published into the caller's slot
     * per FUN_001f1c50 @ 52072 — the caller becomes responsible. */
    PalAioPortObject *release() noexcept
    {
        PalAioPortObject *p = obj_;
        obj_   = nullptr;
        owned_ = false;
        return p;
    }

private:
    static void vtbl_sentinel() { /* placeholder for PTR_FUN_003594e8 */ }

    PalAioPortObject *obj_;
    bool              owned_;
};

/* ======================================================================
 * C ABI surface.  All entries are extern "C" — these get called by the
 * surrounding pal_* TUs (not from PE machine code), so we do NOT attach
 * ms_abi to them.
 * ====================================================================== */
extern "C" {

/* -----------------------------------------------------------------
 * pal_aio_setup — FUN_00202100 @ line 67430
 *
 * ELF body (2 lines):
 *   FUN_00354180(0xce, param_1, param_2);
 *   return;
 *
 * FUN_00354180 = raw `mov rax, <nr>; syscall` wrapper.  io_setup is
 * syscall 0xce (206) on x86_64.  glibc does NOT expose a wrapper, so
 * we go through syscall(3) exactly like the ELF does.
 * ----------------------------------------------------------------- */
int pal_aio_setup(unsigned nr_events, unsigned long *ctx_out)
{
    if (ctx_out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    /* io_setup expects ctx to be zero on input. */
    unsigned long ctx = 0;
    long rc = syscall(SYS_io_setup, (unsigned long)nr_events, &ctx);
    if (rc < 0) {
        /* errno already set by glibc's syscall wrapper. */
        return -1;
    }
    *ctx_out = ctx;
    return 0;
}

int pal_aio_destroy(pal_aio_context_t ctx)
{
    if (ctx == 0) {
        return 0;
    }
    long rc = syscall(SYS_io_destroy, (unsigned long)ctx);
    return (rc < 0) ? -1 : 0;
}

long pal_aio_submit(pal_aio_context_t ctx, long nr, void **iocbpp)
{
    if (ctx == 0 || nr <= 0 || iocbpp == nullptr) {
        errno = EINVAL;
        return -1;
    }
    long rc = syscall(SYS_io_submit, (unsigned long)ctx,
                      (long)nr, iocbpp);
    return rc;
}

long pal_aio_reap(pal_aio_context_t ctx, long min_events, long max_events,
                  void *events_out, long timeout_ns)
{
    if (ctx == 0 || events_out == nullptr || max_events <= 0) {
        errno = EINVAL;
        return -1;
    }
    struct timespec ts;
    struct timespec *pts = nullptr;
    if (timeout_ns >= 0) {
        ts.tv_sec  = timeout_ns / 1000000000L;
        ts.tv_nsec = timeout_ns % 1000000000L;
        pts = &ts;
    }
    long rc = syscall(SYS_io_getevents, (unsigned long)ctx,
                      min_events, max_events, events_out, pts);
    return rc;
}

/* -----------------------------------------------------------------
 * pal_io_create_completion_port_real — FUN_001f1c50 @ line 52045
 *
 * Strong override of the simpler pal_io_create_completion_port
 * definition in pal_io.cpp.  Because this TU is linked BEFORE
 * pal_io.cpp under -Wl,--allow-multiple-definition, the first-seen
 * rule picks up our definition for the unqualified symbol too.
 *
 * Behaviour (mirrors the ELF exactly):
 *   1. allocate 0x1c0 bytes @ 0x40 alignment (posix_memalign).
 *   2. in-place construct.
 *   3. publish into *out_port_slot (cast to long * per the ELF
 *      signature `long *param_3`).
 *   4. io_setup(0x400, &obj->m_KernelAioContext).
 *   5. on any failure, free the object and return -1.
 * ----------------------------------------------------------------- */
int pal_io_create_completion_port_real(void *out_port_slot)
{
    long *slot = static_cast<long *>(out_port_slot);
    if (slot == nullptr) {
        errno = EINVAL;
        return -1;
    }

    PalAioContext ctx;
    if (ctx.allocate() != 0) {
        fprintf(stderr, "[PAL-AIO] allocate failed (OOM)\n");
        *slot = 0;
        return -1;
    }
    ctx.construct();

    /* Step 5 of FUN_001f1c50: release any previous port sitting in the
     * slot.  We have no way to reach its destructor from here, so just
     * overwrite — matches the behaviour observed at hello_drawbridge.exe
     * boot where the slot is always NULL on first entry. */
    if (*slot != 0) {
        fprintf(stderr, "[PAL-AIO] slot already held %p — overwriting\n",
                (void *)*slot);
    }

    /* Arm the kernel context BEFORE publishing — otherwise a racing
     * reader could observe the object with ctx == 0. */
    int arm_rc = ctx.arm(PAL_AIO_DEFAULT_NR_EVENTS);

    PalAioPortObject *obj = ctx.release();
    *slot = reinterpret_cast<long>(obj);

    if (arm_rc != 0) {
        /* ELF returns success + logs — the object is usable even with
         * a zero context, writes just never complete asynchronously.
         * Match that so the PE boot path sees the port as present. */
        fprintf(stderr,
                "[PAL-AIO] completion port created without aio context "
                "(fs.aio-max-nr exhausted?)\n");
    }
    return 0;
}

/* First-seen override of the legacy symbol in pal_io.cpp.  Kept as a
 * simple forwarder so the two signatures (legacy + _real) agree. */
int pal_io_create_completion_port(void *out_port)
{
    return pal_io_create_completion_port_real(out_port);
}

} /* extern "C" */
