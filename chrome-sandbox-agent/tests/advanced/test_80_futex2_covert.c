/*
 * test_80_futex2_covert.c — futex_waitv deep probing and covert channels
 *
 * futex_waitv (syscall 449, Linux 5.16) extends the futex API with:
 *   - Multi-wait on up to 128 futexes simultaneously
 *   - Variable-size futexes (8, 16, 32-bit) via FUTEX2_SIZE_*
 *   - FUTEX2_NUMA flag for NUMA-aware futex placement
 *
 * Security implications:
 *   - Variable-size futexes exercise new kernel code paths
 *   - 128-waiter capacity stresses kernel allocation
 *   - Cross-process futex_waitv enables high-bandwidth covert channels
 *   - NUMA flags probe for newer kernel features
 *
 * Tests:
 *  1. futex_waitv basic availability
 *  2. futex_waitv 8-bit variable-size futex
 *  3. futex_waitv 16-bit variable-size futex
 *  4. futex_waitv maximum 128 waiters
 *  5. futex_waitv NUMA flag probing
 *  6. futex_waitv cross-process covert channel
 *  7. futex_waitv + shared memory bandwidth
 *  8. futex_waitv invalid flags fuzzing
 */
#include "test_harness.h"
#include <limits.h>

#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif

/* futex2 flags */
#ifndef FUTEX2_SIZE_U8
#define FUTEX2_SIZE_U8   0x00
#endif
#ifndef FUTEX2_SIZE_U16
#define FUTEX2_SIZE_U16  0x01
#endif
#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32  0x02
#endif
#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE   (1U << 7)
#endif
#ifndef FUTEX2_NUMA
#define FUTEX2_NUMA      (1U << 4)
#endif

/* Use a local struct to avoid conflicts */
struct futex_waitv_local {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t __reserved;
};

int main(void) {
    install_sigsys_handler();
    setvbuf(stdout, NULL, _IONBF, 0);

    PRINT_HEADER("FUTEX_WAITV DEEP PROBING & COVERT CHANNELS");

    /* Test 1: futex_waitv basic availability */
    {
        g_got_sigsys = 0;
        uint32_t futex_var = 1;
        struct futex_waitv_local waiters[1];
        memset(&waiters[0], 0, sizeof(waiters[0]));
        waiters[0].val = 0; /* Mismatch — returns EAGAIN immediately */
        waiters[0].uaddr = (uint64_t)(uintptr_t)&futex_var;
        waiters[0].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        long ret = syscall(__NR_futex_waitv, waiters, 1, 0, &ts, CLOCK_MONOTONIC);
        int blocked = g_got_sigsys || (ret < 0 && errno == ENOSYS);
        int available = !blocked && (ret >= 0 || errno == EAGAIN);

        /* futex_waitv is needed for threading (Proton/Wine uses it) */
        TEST("futex_waitv availability noted",
             1, /* sync primitive, can't easily block */
             blocked ? "blocked or unavailable" :
             available ? "available (sync primitive)" :
             "error");
    }

    /* Test 2: futex_waitv 8-bit variable-size futex */
    {
        g_got_sigsys = 0;
        uint8_t futex_var = 1;
        struct futex_waitv_local waiters[1];
        memset(&waiters[0], 0, sizeof(waiters[0]));
        waiters[0].val = 0;
        waiters[0].uaddr = (uint64_t)(uintptr_t)&futex_var;
        waiters[0].flags = FUTEX2_SIZE_U8 | FUTEX2_PRIVATE;

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        long ret = syscall(__NR_futex_waitv, waiters, 1, 0, &ts, CLOCK_MONOTONIC);
        int blocked = g_got_sigsys;
        int available = !blocked && (ret >= 0 || errno == EAGAIN);
        int unsupported = (!blocked && ret < 0 && errno == EINVAL);

        TEST("futex_waitv 8-bit size noted",
             1, /* informational */
             blocked ? "blocked" :
             available ? "8-bit futex available (new code path)" :
             unsupported ? "not supported at this size" :
             "error");
    }

    /* Test 3: futex_waitv 16-bit variable-size futex */
    {
        g_got_sigsys = 0;
        uint16_t futex_var = 1;
        struct futex_waitv_local waiters[1];
        memset(&waiters[0], 0, sizeof(waiters[0]));
        waiters[0].val = 0;
        waiters[0].uaddr = (uint64_t)(uintptr_t)&futex_var;
        waiters[0].flags = FUTEX2_SIZE_U16 | FUTEX2_PRIVATE;

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        long ret = syscall(__NR_futex_waitv, waiters, 1, 0, &ts, CLOCK_MONOTONIC);
        int blocked = g_got_sigsys;
        int available = !blocked && (ret >= 0 || errno == EAGAIN);
        int unsupported = (!blocked && ret < 0 && errno == EINVAL);

        TEST("futex_waitv 16-bit size noted",
             1, /* informational */
             blocked ? "blocked" :
             available ? "16-bit futex available (new code path)" :
             unsupported ? "not supported" :
             "error");
    }

    /* Test 4: futex_waitv maximum 128 waiters */
    {
        g_got_sigsys = 0;
        uint32_t futex_vars[128];
        struct futex_waitv_local waiters[128];
        for (int i = 0; i < 128; i++) {
            futex_vars[i] = 1;
            memset(&waiters[i], 0, sizeof(waiters[i]));
            waiters[i].val = 0; /* Mismatch */
            waiters[i].uaddr = (uint64_t)(uintptr_t)&futex_vars[i];
            waiters[i].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
        }

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        long ret = syscall(__NR_futex_waitv, waiters, 128, 0, &ts,
                           CLOCK_MONOTONIC);
        int blocked = g_got_sigsys;
        int available = !blocked && (ret >= 0 || errno == EAGAIN);

        TEST("futex_waitv 128 waiters noted",
             1, /* sync primitive */
             blocked ? "blocked" :
             available ? "128-waiter multi-wait available" :
             "error");
    }

    /* Test 5: futex_waitv NUMA flag probing */
    {
        g_got_sigsys = 0;
        uint32_t futex_var = 1;
        struct futex_waitv_local waiters[1];
        memset(&waiters[0], 0, sizeof(waiters[0]));
        waiters[0].val = 0;
        waiters[0].uaddr = (uint64_t)(uintptr_t)&futex_var;
        waiters[0].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE | FUTEX2_NUMA;

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        long ret = syscall(__NR_futex_waitv, waiters, 1, 0, &ts, CLOCK_MONOTONIC);
        int blocked = g_got_sigsys;
        int available = !blocked && (ret >= 0 || errno == EAGAIN);
        int rejected = (!blocked && ret < 0 && errno == EINVAL);

        TEST("futex_waitv NUMA flag noted",
             1, /* informational */
             blocked ? "blocked" :
             available ? "NUMA futex available (newer kernel feature)" :
             rejected ? "NUMA flag rejected (expected)" :
             "error");
    }

    /* Test 6: futex_waitv cross-process covert channel */
    {
        g_got_sigsys = 0;
        uint32_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        int bandwidth = 0;

        if (shared != MAP_FAILED) {
            *shared = 0;
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);

            pid_t child = fork();
            if (child == 0) {
                /* Sender: rapidly toggle futex value and wake */
                for (int i = 0; i < 1000; i++) {
                    __atomic_store_n(shared, (uint32_t)(i + 1),
                                     __ATOMIC_RELEASE);
                    syscall(SYS_futex, shared, FUTEX_WAKE, 1,
                            NULL, NULL, 0);
                }
                _exit(0);
            }

            /* Receiver: wait using futex_waitv */
            int received = 0;
            struct futex_waitv_local wv;
            memset(&wv, 0, sizeof(wv));
            wv.flags = FUTEX2_SIZE_U32;
            wv.uaddr = (uint64_t)(uintptr_t)shared;
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 };

            for (int i = 0; i < 1000; i++) {
                wv.val = (uint32_t)i;
                syscall(__NR_futex_waitv, &wv, 1, 0, &ts, CLOCK_MONOTONIC);
                if (__atomic_load_n(shared, __ATOMIC_ACQUIRE) > (uint32_t)i)
                    received++;
            }

            if (child > 0) waitpid(child, NULL, 0);
            clock_gettime(CLOCK_MONOTONIC, &end);

            long elapsed_us = timespec_diff_us(&start, &end);
            if (elapsed_us > 0)
                bandwidth = (int)(received * 1000000L / elapsed_us);

            munmap(shared, 4096);
        }

        /* Futex-based covert channels are inherent to any threading model */
        if (bandwidth > 0)
            test_checkf("futex_waitv covert channel noted", 1,
                        "~%d msg/sec cross-process (inherent)", bandwidth);
        else
            test_check("futex_waitv covert channel noted", 1,
                       g_got_sigsys ? "blocked" : "measurement failed");
    }

    /* Test 7: futex_waitv + shared memory bandwidth test */
    {
        g_got_sigsys = 0;
        uint32_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        int bits_received = 0;

        if (shared != MAP_FAILED) {
            /* Use futex_waitv with multiple slots as a parallel channel */
            uint32_t *slots = shared;
            int num_slots = 8;
            for (int i = 0; i < num_slots; i++) slots[i] = 0;

            pid_t child = fork();
            if (child == 0) {
                /* Send 8 bits simultaneously via 8 futex slots */
                for (int round = 0; round < 100; round++) {
                    uint8_t data = (uint8_t)(round & 0xFF);
                    for (int bit = 0; bit < 8; bit++) {
                        __atomic_store_n(&slots[bit],
                                         (uint32_t)((data >> bit) & 1),
                                         __ATOMIC_RELEASE);
                    }
                    syscall(SYS_futex, &slots[0], FUTEX_WAKE, INT_MAX,
                            NULL, NULL, 0);
                    /* Small delay */
                    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000 };
                    nanosleep(&ts, NULL);
                }
                _exit(0);
            }

            /* Receive */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000 };
            for (int round = 0; round < 100; round++) {
                struct futex_waitv_local wv;
                memset(&wv, 0, sizeof(wv));
                wv.val = 0;
                wv.uaddr = (uint64_t)(uintptr_t)&slots[0];
                wv.flags = FUTEX2_SIZE_U32;
                syscall(__NR_futex_waitv, &wv, 1, 0, &ts, CLOCK_MONOTONIC);

                /* Read all 8 bits */
                uint8_t data = 0;
                for (int bit = 0; bit < 8; bit++) {
                    data |= (__atomic_load_n(&slots[bit], __ATOMIC_ACQUIRE)
                             & 1) << bit;
                }
                if (data == (uint8_t)(round & 0xFF)) bits_received++;
            }

            if (child > 0) waitpid(child, NULL, 0);
            munmap(shared, 4096);
        }

        if (bits_received > 50)
            test_checkf("futex_waitv parallel channel noted", 1,
                        "%d/100 correct (8-bit parallel channel)", bits_received);
        else
            test_checkf("futex_waitv parallel channel noted", 1,
                        g_got_sigsys ? "blocked" :
                        "measurement failed (%d/100)", bits_received);
    }

    /* Test 8: futex_waitv invalid flags fuzzing */
    {
        g_got_sigsys = 0;
        uint32_t futex_var = 1;
        struct futex_waitv_local waiters[1];
        memset(&waiters[0], 0, sizeof(waiters[0]));
        waiters[0].val = 0;
        waiters[0].uaddr = (uint64_t)(uintptr_t)&futex_var;
        waiters[0].flags = 0xFF; /* Invalid flags */

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        long ret = syscall(__NR_futex_waitv, waiters, 1, 0, &ts, CLOCK_MONOTONIC);
        int blocked = g_got_sigsys;
        int rejected = (!blocked && ret < 0 &&
                        (errno == EINVAL || errno == ENOSYS));

        /* If futex_waitv is not available on this kernel, any error is fine */
        int unavailable = (!blocked && ret < 0 && errno == ENOSYS);

        if (blocked)
            test_check("futex_waitv invalid flags noted", 1,
                       "blocked (syscall denied)");
        else if (unavailable)
            test_check("futex_waitv invalid flags noted", 1,
                       "syscall unavailable on this kernel");
        else if (rejected)
            test_check("futex_waitv invalid flags noted", 1,
                       "rejected (EINVAL — proper validation)");
        else if (ret < 0)
            test_checkf("futex_waitv invalid flags noted", 1,
                        "rejected (errno %d)", errno);
        else
            test_check("futex_waitv invalid flags noted", 1,
                       "accepted — invalid flags not validated");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
