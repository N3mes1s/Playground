/*
 * pal_scheduler.cpp — Fiber scheduler (Component C15, Milestone M9).
 *
 * Translated from analysis/sqlservr_FULL.c:
 *   FUN_002890a0 @ 156863..156884       thread-subsystem init (full body)
 *   FUN_00355d60 @ 320481..320486       scheduler config registration
 *   FUN_00279f90 @ 148741..148760       AIO callback registration
 *                                       (FUN_00353f90 pthread_create)
 *   FUN_00252bf0 @ 123349..123377       AIO completion callback
 *
 * Multi-worker dispatch, runqueue and preemption are inferred from
 * HEThreads.cpp (ELF lines 148200..158400).  Only the portions the
 * hello_drawbridge.exe boot path actually traverses are implemented
 * here; the rest are `unk_*` slots with TODO markers so the gaps are
 * visible at compile time.
 *
 * Strong symbols owned (override first-seen defs in pal_thread.cpp;
 * Makefile lists pal_scheduler.cpp BEFORE dk_pal.cpp and
 * pal_thread.cpp so the linker picks us under
 * -Wl,--allow-multiple-definition):
 *   pal_scheduler_register
 *   pal_aio_callback_register
 *   pal_aio_callback
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <atomic>
#include <mutex>

#include "pal_scheduler.h"
#include "pal_aio.h"

/* ======================================================================
 * class PalScheduler — singleton that owns the scheduler config and the
 * AIO dispatch worker.  The public extern-"C" entry points are thin
 * shells around this class.
 * ====================================================================== */
class PalScheduler {
public:
    static PalScheduler &instance() noexcept
    {
        static PalScheduler s;
        return s;
    }

    /* FUN_00355d60 @ 320481.  Copy the 32-byte config verbatim. */
    void register_config(const pal_scheduler_config_t *cfg) noexcept
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (cfg != nullptr) {
            memcpy(&config_, cfg, sizeof(config_));
        } else {
            memset(&config_, 0, sizeof(config_));
        }
        config_set_ = true;
        fprintf(stderr,
                "[PAL-SCHED] register: cfg=%p mask_a=0x%lx tick_us=%lu\n",
                (const void *)cfg,
                (unsigned long)config_.mask_a,
                (unsigned long)config_.tick_period_us);
    }

    /* FUN_00279f90 @ 148741.  Install the callback and spawn the
     * dispatch worker pthread that drains the reap queue. */
    void register_aio_callback(pal_aio_callback_fn cb) noexcept
    {
        {
            std::lock_guard<std::mutex> lk(mu_);
            aio_cb_.store(cb, std::memory_order_release);
        }
        fprintf(stderr,
                "[PAL-SCHED] aio_callback_register: cb=%p\n",
                reinterpret_cast<void *>(cb));

        /* Spawn dispatch worker exactly once.  FUN_00353f90 in the ELF
         * is a thin pthread_create wrapper (see FUN_00279f90:148750). */
        bool expected = false;
        if (worker_started_.compare_exchange_strong(expected, true)) {
            int rc = pthread_create(&worker_tid_, nullptr,
                                    &PalScheduler::worker_main, this);
            if (rc != 0) {
                fprintf(stderr,
                        "[PAL-SCHED] pthread_create failed: rc=%d\n", rc);
                worker_started_.store(false);
            }
        }
    }

    /* FUN_00252bf0 @ 123349.  Dispatch to the registered callback. */
    void deliver(void *arg1, long arg2) noexcept
    {
        auto cb = aio_cb_.load(std::memory_order_acquire);
        if (cb != nullptr) {
            cb(arg1, arg2);
        }
    }

    void shutdown() noexcept
    {
        shutdown_.store(true, std::memory_order_release);
    }

private:
    PalScheduler() noexcept
        : config_set_(false)
        , worker_started_(false)
        , shutdown_(false)
        , worker_tid_(0)
    {
        memset(&config_, 0, sizeof(config_));
        aio_cb_.store(nullptr, std::memory_order_relaxed);
    }

    ~PalScheduler() noexcept
    {
        shutdown();
    }

    /* Dispatch worker body.  In a fully-translated host this would
     * pull io_events off every registered completion port's aio
     * context and hand them to deliver().  At M9 it sleeps and polls
     * the shutdown flag so the pthread exists, is observable in
     * /proc/self/task, and can be targeted by downstream Wave-2
     * components without disturbing layout.
     *
     * TODO(C15): integrate with PalAioContext::object() once the
     *            completion-port registry lands (FUN_001f1b40 path). */
    static void *worker_main(void *self_) noexcept
    {
        auto *self = static_cast<PalScheduler *>(self_);
#ifndef SYS_gettid
#define SYS_gettid __NR_gettid
#endif
        fprintf(stderr, "[PAL-SCHED] worker started (tid=%ld)\n",
                (long)syscall(SYS_gettid));
        while (!self->shutdown_.load(std::memory_order_acquire)) {
            /* Poll at the configured tick period (default 3600us).
             * Until the completion-port registry lands we simply idle. */
            uint64_t us = self->config_.tick_period_us;
            if (us == 0) us = 3600;
            struct timespec ts;
            ts.tv_sec  = us / 1000000UL;
            ts.tv_nsec = (us % 1000000UL) * 1000UL;
            nanosleep(&ts, nullptr);
        }
        fprintf(stderr, "[PAL-SCHED] worker exiting\n");
        return nullptr;
    }

    pal_scheduler_config_t              config_;
    bool                                config_set_;
    std::atomic<bool>                   worker_started_;
    std::atomic<bool>                   shutdown_;
    std::atomic<pal_aio_callback_fn>    aio_cb_;
    pthread_t                           worker_tid_;
    std::mutex                          mu_;
};

/* ======================================================================
 * Sanity: the config struct must match the four local_30 / local_28 /
 * uStack_20 / local_18 slots from FUN_002890a0.
 * ====================================================================== */
static_assert(offsetof(pal_scheduler_config_t, mask_a)         == 0x00,
              "mask_a must sit at +0x00 (FUN_002890a0 local_30)");
static_assert(offsetof(pal_scheduler_config_t, mask_b)         == 0x08,
              "mask_b must sit at +0x08 (FUN_002890a0 local_28)");
static_assert(offsetof(pal_scheduler_config_t, mask_c)         == 0x10,
              "mask_c must sit at +0x10 (FUN_002890a0 uStack_20)");
static_assert(offsetof(pal_scheduler_config_t, tick_period_us) == 0x18,
              "tick_period_us must sit at +0x18 (FUN_002890a0 local_18)");
static_assert(sizeof(pal_scheduler_config_t)                   == 0x20,
              "scheduler config is 4*8 bytes (FUN_002890a0 stack frame)");

/* ======================================================================
 * Public ABI (extern "C").  These override the first-seen definitions
 * currently inlined into pal_thread.cpp.  The Makefile orders this TU
 * ahead of dk_pal.cpp / pal_thread.cpp so the linker picks these up
 * under -Wl,--allow-multiple-definition.
 * ====================================================================== */
extern "C" {

void pal_scheduler_register(const void *config)
{
    PalScheduler::instance().register_config(
        static_cast<const pal_scheduler_config_t *>(config));
}

void pal_aio_callback_register(void (*cb)(void *, long))
{
    PalScheduler::instance().register_aio_callback(
        reinterpret_cast<pal_aio_callback_fn>(cb));
}

/* FUN_00252bf0 @ 123349..123377.
 *
 * ELF body (simplified — only the successful path matters for the
 * boot-time hello_drawbridge trace):
 *   cVar1 = FUN_002801d0(asyncObj);              // validate pointer
 *   if (asyncObj != 0 && cVar1 != 0) {
 *       cVar1 = FUN_001ae6e0(asyncObj, 6);       // mark "completed"
 *       if (cVar1 != 0) {
 *           iVar2 = FUN_00289560(asyncObj[0x58]);// query aio_error
 *           if (iVar2 == 0x73) panic;            // EINPROGRESS leaked
 *           FUN_002bf110(asyncObj);              // wake waiter
 *           FUN_002b6190(asyncObj);              // drop refcount
 *           return;
 *       }
 *       FUN_001ae6e0(asyncObj, 6);               // retry mark
 *   }
 *   panic("asyncObj != nullptr");
 *
 * For M9 we implement the shape — validate arg1, log, and forward to
 * the registered user callback via PalScheduler::deliver.  The
 * lower-level FUN_002bf110/FUN_002b6190 helpers are owned by C7/C8
 * and invoked through their public headers once wired. */
void pal_aio_callback(void *arg1, long arg2)
{
    if (arg1 == nullptr) {
        fprintf(stderr,
                "[PAL-SCHED] aio_callback: null asyncObj (arg2=%ld)\n",
                arg2);
        return;
    }
    /* Forward to any downstream handler (none at M9). */
    PalScheduler::instance().deliver(arg1, arg2);
}

} /* extern "C" */
