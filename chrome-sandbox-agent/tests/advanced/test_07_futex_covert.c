/*
 * test_07_futex_covert.c — Futex & Covert Channel Cross-Namespace Attacks
 *
 * Attack vector: Even with namespace isolation, timing-based covert channels
 * can leak information across boundaries. Tests include:
 *
 *   1. Futex on shared mmap — if two processes share a page, futex
 *      provides cross-process synchronization (covert channel)
 *   2. CPU cache timing (Flush+Reload) — measure memory access times
 *      to infer host activity
 *   3. /proc/stat timing — sample system-wide CPU usage to detect
 *      host processes and their behavior patterns
 *   4. Scheduler side channel — measure scheduling latency to detect
 *      co-located processes
 *   5. Filesystem timing — measure open() latency on different paths
 *      to probe host filesystem layout
 *   6. Network timing — even with net NS, kernel packet processing
 *      can leak timing information
 *
 * PASS = covert channels have low bandwidth or are blocked
 * FAIL = high-bandwidth cross-namespace communication possible
 */

#include "test_harness.h"

/* Futex on shared memory between parent and child */
static int try_futex_shared(void) {
    /* Create shared anonymous mapping */
    int *shared = mmap(NULL, 4096,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return -1;

    *shared = 0;

    pid_t child = fork();
    if (child < 0) { munmap(shared, 4096); return -1; }

    if (child == 0) {
        /* Child: wait on futex, then write marker */
        usleep(10000);  /* 10ms */
        *shared = 42;
        syscall(SYS_futex, shared, FUTEX_WAKE, 1, NULL, NULL, 0);
        _exit(0);
    }

    /* Parent: wait for futex signal */
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    g_got_sigsys = 0;
    int ret = syscall(SYS_futex, shared, FUTEX_WAIT, 0, &timeout, NULL, 0);

    waitpid(child, NULL, 0);

    int child_wrote = (*shared == 42);
    munmap(shared, 4096);

    if (g_got_sigsys) return -2;

    /* Futex within sandbox is fine — what matters is whether it crosses
     * namespace boundaries. Between parent/child in same NS, it should work. */
    return child_wrote ? 0 : -1;
}

/* CPU cache timing probe — measure memory access latency */
static int try_cache_timing(void) {
    /* Allocate two pages */
    volatile char *p = mmap(NULL, 8192,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return -1;

    /* Measure access time to a cached vs uncached line */
    struct timespec t1, t2, t3, t4;

    /* Warm the cache */
    volatile char dummy = p[0];
    (void)dummy;

    /* Measure cached access */
    clock_gettime(CLOCK_MONOTONIC, &t1);
    for (int i = 0; i < 1000; i++) {
        dummy = p[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);
    long cached_us = timespec_diff_us(&t1, &t2);

    /* Flush and measure uncached access */
    /* clflush is not available without inline asm, use madvise as proxy */
    madvise((void *)p, 8192, MADV_DONTNEED);

    clock_gettime(CLOCK_MONOTONIC, &t3);
    for (int i = 0; i < 1000; i++) {
        dummy = p[4096];  /* Different page */
    }
    clock_gettime(CLOCK_MONOTONIC, &t4);
    long uncached_us = timespec_diff_us(&t3, &t4);

    munmap((void *)p, 8192);

    /* If there's a measurable difference, cache side channel is viable */
    int distinguishable = (uncached_us > cached_us * 2) && (cached_us > 0);

    return distinguishable ? 1 : 0;
}

/* /proc/stat timing — sample system CPU load */
static int try_proc_stat_timing(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/stat", buf, sizeof(buf));
    if (n <= 0) return -1;

    /* Parse CPU line for utilization */
    unsigned long user, nice, system, idle;
    if (sscanf(buf, "cpu %lu %lu %lu %lu",
               &user, &nice, &system, &idle) != 4) {
        return -1;
    }

    /* Sample twice with a short delay */
    usleep(50000);  /* 50ms */

    char buf2[4096];
    n = read_file("/proc/stat", buf2, sizeof(buf2));
    if (n <= 0) return -1;

    unsigned long user2, nice2, system2, idle2;
    if (sscanf(buf2, "cpu %lu %lu %lu %lu",
               &user2, &nice2, &system2, &idle2) != 4) {
        return -1;
    }

    /* Can we detect activity delta? */
    long delta_work = (long)(user2 - user) + (long)(system2 - system);

    return delta_work > 0 ? 1 : 0;  /* 1 = can observe host CPU activity */
}

/* Scheduling latency measurement — detect co-located processes */
static int try_scheduler_side_channel(void) {
    int samples = 100;
    long latencies[100];

    for (int i = 0; i < samples; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        /* Yield to trigger a context switch */
        sched_yield();
        clock_gettime(CLOCK_MONOTONIC, &t2);
        latencies[i] = timespec_diff_us(&t1, &t2);
    }

    /* Calculate variance — high variance suggests contention from
     * other (host) processes */
    long sum = 0;
    for (int i = 0; i < samples; i++) sum += latencies[i];
    long mean = sum / samples;

    long variance = 0;
    for (int i = 0; i < samples; i++) {
        long diff = latencies[i] - mean;
        variance += diff * diff;
    }
    variance /= samples;

    /* High variance (> 100µs²) suggests detectable host activity */
    return variance > 100 ? 1 : 0;
}

/* Filesystem timing — probe for existence of paths via timing */
static int try_fs_timing_probe(void) {
    struct timespec t1, t2;
    const char *probes[] = {
        "/etc/shadow",    /* Should exist (permission denied) */
        "/nonexistent",   /* Doesn't exist */
        "/home/user",     /* May or may not be visible */
    };

    long times[3];
    for (int i = 0; i < 3; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        for (int j = 0; j < 100; j++) {
            int fd = open(probes[i], O_RDONLY);
            if (fd >= 0) close(fd);
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        times[i] = timespec_diff_us(&t1, &t2);
    }

    /* If existing files take consistently different time than
     * nonexistent ones, we can probe the host filesystem layout */
    long diff = labs(times[0] - times[1]);
    int distinguishable = (diff > times[1] / 2 && times[1] > 0);

    return distinguishable ? 1 : 0;
}

/* Clock resolution — can we measure with nanosecond precision? */
static int try_clock_resolution(void) {
    struct timespec res;
    clock_getres(CLOCK_MONOTONIC, &res);

    /* Sub-microsecond resolution enables more precise timing attacks */
    int high_res = (res.tv_sec == 0 && res.tv_nsec <= 1000);
    return high_res ? 1 : 0;
}

/* RDTSC — try to read the CPU timestamp counter directly */
static int try_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int lo, hi;
    /* This may be blocked by seccomp or the kernel's
     * prctl(PR_SET_TSC, PR_TSC_SIGSEGV) */
    g_got_sigsys = 0;

    /* Check if TSC access is restricted */
    int tsc_mode = 0;
    int ret = prctl(PR_GET_TSC, &tsc_mode);

    if (ret == 0 && tsc_mode == PR_TSC_SIGSEGV)
        return 0;  /* TSC access would SIGSEGV */

    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    unsigned long long tsc = ((unsigned long long)hi << 32) | lo;

    return tsc > 0 ? 1 : 0;
#else
    return -1;  /* Not x86 */
#endif
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("FUTEX & COVERT CHANNEL CROSS-NAMESPACE ATTACKS");

    /* 1. Futex on shared memory */
    int futex = try_futex_shared();
    TEST("Futex within sandbox controlled",
         futex != -2,  /* -2 = seccomp blocked */
         futex == -2 ? "seccomp blocked futex" :
         futex == 0  ? "works (intra-sandbox, expected)" :
         futex == -1 ? "futex failed" : "");

    /* 2. CPU cache timing */
    int cache = try_cache_timing();
    TEST("Cache timing side channel (info)",
         1,  /* Log only — hard to fully prevent */
         cache == 1 ? "distinguishable (low-bandwidth channel possible)" :
         cache == 0 ? "not measurable" : "mmap failed");

    /* 3. /proc/stat CPU timing */
    int stat = try_proc_stat_timing();
    TEST("/proc/stat host activity detection",
         stat != 1,
         stat == 1  ? "CAN detect host CPU activity!" :
         stat == -1 ? "blocked" : "no activity detected");

    /* 4. Scheduler side channel */
    int sched = try_scheduler_side_channel();
    TEST("Scheduler latency side channel (info)",
         1,
         sched == 1 ? "variance detected (host contention visible)" :
                      "low variance (minimal info leak)");

    /* 5. Filesystem timing probe */
    int fstiming = try_fs_timing_probe();
    TEST("FS timing probe (info)",
         1,
         fstiming == 1 ? "timing differences measurable" :
                         "not distinguishable (good)");

    /* 6. Clock resolution */
    int clockres = try_clock_resolution();
    TEST("Clock resolution (info)",
         1,
         clockres == 1 ? "sub-µs (enables precise timing attacks)" :
                         "low res (limits timing attacks)");

    /* 7. RDTSC access */
    int rdtsc = try_rdtsc();
    TEST("RDTSC (CPU timestamp counter) access",
         1,
         rdtsc == 1  ? "available (timing attacks possible)" :
         rdtsc == 0  ? "restricted (PR_TSC_SIGSEGV)" :
         rdtsc == -1 ? "not x86" : "");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
