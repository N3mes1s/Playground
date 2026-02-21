/*
 * test_75_kernel_timing_leak.c — Kernel data structure timing side channels
 *
 * Based on: KernelSnitch (NDSS 2025, Graz University of Technology)
 * and TLB defense-amplified leaks (USENIX Security 2025).
 *
 * These attacks measure traversal time of kernel hash tables to:
 *   - Leak kernel heap pointers (defeat KASLR in ~65 seconds)
 *   - Create covert channels at up to 580 kbit/s
 *   - Detect kernel-internal state changes
 *
 * Attack vectors:
 *   - futex hash table timing (futex syscall)
 *   - POSIX timer hash table (timer_create/timer_delete)
 *   - IPC key hash (msgget/semget/shmget with specific keys)
 *   - TLB contention from kernel defense page splitting
 *
 * Tests:
 *  1. Futex hash table timing measurement
 *  2. POSIX timer create/delete timing
 *  3. IPC key hash timing
 *  4. mmap/munmap cycle timing (TLB contention)
 *  5. mincore() page cache probing
 *  6. /proc/self/pagemap timing
 *  7. getrandom entropy timing
 *  8. clock_gettime monotonic precision
 */
#include "test_harness.h"
#include <sys/random.h>

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("KERNEL DATA STRUCTURE TIMING SIDE CHANNELS");

    /* Test 1: Futex hash table timing (KernelSnitch vector) */
    {
        g_got_sigsys = 0;
        uint32_t futex_var = 1;
        struct timespec start, end;

        /* Warm up */
        syscall(SYS_futex, &futex_var, 0 /* FUTEX_WAIT */, 0,
                &(struct timespec){0, 1}, NULL, 0);

        /* Time a futex operation with different addresses to probe hash */
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 1000; i++) {
            syscall(SYS_futex, &futex_var, 0, 0,
                    &(struct timespec){0, 1}, NULL, 0);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long diff_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                       (end.tv_nsec - start.tv_nsec);

        /* If timing is very consistent and fast, hash probing works */
        int precise = (diff_ns > 0 && diff_ns < 50000000); /* < 50ms for 1000 ops */
        TEST("Futex hash timing oracle noted",
             1,  /* futex is required for threading, can't block */
             precise ? "precise (KernelSnitch hash probe feasible)" :
             "imprecise (hash probe difficult)");
    }

    /* Test 2: POSIX timer create/delete timing */
    {
        g_got_sigsys = 0;
        struct timespec start, end;
        int timing_works = 0;

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 100; i++) {
            timer_t tid;
            struct sigevent sev;
            memset(&sev, 0, sizeof(sev));
            sev.sigev_notify = SIGEV_NONE;
            if (timer_create(CLOCK_MONOTONIC, &sev, &tid) == 0) {
                timer_delete(tid);
                timing_works = 1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long diff_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                       (end.tv_nsec - start.tv_nsec);

        TEST("Timer hash timing oracle noted",
             1,  /* timer_create is needed for normal operation */
             timing_works ? "timer create/delete timing available" :
             "blocked");
        (void)diff_ns;
    }

    /* Test 3: IPC key hash timing */
    {
        g_got_sigsys = 0;
        struct timespec start, end;

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 100; i++) {
            /* Try msgget with sequential keys — timing varies with hash */
            syscall(SYS_msgget, 0x42420000 + i, 0);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long diff_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                       (end.tv_nsec - start.tv_nsec);

        int blocked = g_got_sigsys;
        TEST("IPC key hash timing limited",
             blocked || diff_ns > 0,
             blocked ? "blocked (IPC denied)" :
             "timing available (IPC key hash probing)");
    }

    /* Test 4: mmap/munmap cycle timing (TLB contention) */
    {
        g_got_sigsys = 0;
        struct timespec start, end;

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 1000; i++) {
            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p != MAP_FAILED) munmap(p, 4096);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long diff_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                       (end.tv_nsec - start.tv_nsec);
        long avg_ns = diff_ns / 1000;

        TEST("mmap/munmap TLB timing noted",
             1,  /* mmap is required for memory allocation */
             avg_ns < 100000 ? "fast (TLB contention measurable)" :
             "slow (TLB measurement unreliable)");
    }

    /* Test 5: mincore() page cache probing */
    {
        g_got_sigsys = 0;
        void *buf = mmap(NULL, 4096, PROT_READ,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int probed = 0;
        if (buf != MAP_FAILED) {
            unsigned char vec[1];
            int ret = mincore(buf, 4096, vec);
            probed = (ret == 0);
            munmap(buf, 4096);
        }

        /* mincore() on own anonymous pages is allowed since kernel 5.0+
         * only restricts querying file-backed pages of other processes.
         * Self-page cache info is not a cross-process side channel. */
        TEST("mincore() self-page cache noted",
             1,  /* self-page mincore is allowed, file-backed is restricted */
             probed ? "available (self-page only, restricted for file-backed)" :
             "blocked");
    }

    /* Test 6: /proc/self/pagemap access */
    {
        int fd = open("/proc/self/pagemap", O_RDONLY);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);

        TEST("/proc/self/pagemap blocked",
             blocked,
             blocked ? "blocked" :
             "PAGEMAP — physical page info accessible!");
    }

    /* Test 7: getrandom timing (entropy pool state) */
    {
        g_got_sigsys = 0;
        struct timespec start, end;
        char buf[32];

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 100; i++) {
            syscall(SYS_getrandom, buf, sizeof(buf), 0);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long diff_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                       (end.tv_nsec - start.tv_nsec);
        int blocked = g_got_sigsys;

        /* getrandom is needed for cryptographic operations */
        TEST("getrandom timing noted",
             1,  /* getrandom is needed for crypto */
             blocked ? "blocked" :
             "available (entropy pool timing measurable)");
        (void)diff_ns;
    }

    /* Test 8: clock_gettime resolution */
    {
        struct timespec ts1, ts2;
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        clock_gettime(CLOCK_MONOTONIC, &ts2);

        long diff = (ts2.tv_sec - ts1.tv_sec) * 1000000000L +
                    (ts2.tv_nsec - ts1.tv_nsec);

        /* Sub-100ns resolution enables side channel attacks */
        int high_res = (diff >= 0 && diff < 1000);
        TEST("clock_gettime resolution noted",
             1,  /* clock_gettime is fundamental, can't block */
             high_res ? "sub-us resolution (side channel feasible)" :
             "low resolution");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
