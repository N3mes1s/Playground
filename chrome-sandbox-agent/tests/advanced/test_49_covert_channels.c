/*
 * test_49_covert_channels.c — Covert channels and information leak tests
 *
 * Even with all syscalls blocked, a sandboxed process can still communicate
 * information out via covert channels:
 *
 *  - /proc/stat: CPU time accounting (timing side channel)
 *  - /proc/meminfo: Memory pressure monitoring
 *  - /proc/vmstat: VM statistics changes
 *  - /proc/diskstats: Disk I/O monitoring
 *  - /proc/net/dev: Network traffic monitoring
 *  - Filesystem timing: Measure open/read latency to infer file existence
 *  - CPU cache timing: Flush+Reload / Prime+Probe patterns
 *  - Scheduling side channel: Measure sched_yield timing
 *
 * Tests:
 *  1. /proc/stat CPU timing leak
 *  2. /proc/meminfo memory leak
 *  3. /proc/vmstat VM statistics
 *  4. /proc/diskstats I/O info
 *  5. /proc/net/dev network stats
 *  6. Filesystem timing oracle
 *  7. rdtsc/clock_gettime precision
 *  8. sched_yield timing channel
 */
#include "test_harness.h"

/* Test 1: /proc/stat CPU timing leak */
static int try_proc_stat(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/stat", buf, sizeof(buf));
    if (n <= 0) return 0;

    /* Extract CPU times — reveals system activity */
    int has_cpu = (strstr(buf, "cpu ") != NULL);
    int has_intr = (strstr(buf, "intr ") != NULL);
    int has_ctxt = (strstr(buf, "ctxt ") != NULL);
    int has_procs = (strstr(buf, "processes ") != NULL);

    return (has_cpu ? 1 : 0) | (has_intr ? 2 : 0) |
           (has_ctxt ? 4 : 0) | (has_procs ? 8 : 0);
}

/* Test 2: /proc/meminfo memory leak */
static int try_proc_meminfo(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/meminfo", buf, sizeof(buf));
    if (n <= 0) return 0;

    int has_total = (strstr(buf, "MemTotal:") != NULL);
    int has_free = (strstr(buf, "MemFree:") != NULL);
    int has_avail = (strstr(buf, "MemAvailable:") != NULL);
    int has_cached = (strstr(buf, "Cached:") != NULL);

    return (has_total ? 1 : 0) | (has_free ? 2 : 0) |
           (has_avail ? 4 : 0) | (has_cached ? 8 : 0);
}

/* Test 3: /proc/vmstat VM statistics */
static int try_proc_vmstat(void) {
    char buf[8192];
    ssize_t n = read_file("/proc/vmstat", buf, sizeof(buf));
    if (n <= 0) return 0;

    /* These reveal page fault counts, allocation patterns */
    int has_pgfault = (strstr(buf, "pgfault ") != NULL);
    int has_pgalloc = (strstr(buf, "pgalloc_") != NULL);
    int has_slab = (strstr(buf, "nr_slab") != NULL);

    return (has_pgfault ? 1 : 0) | (has_pgalloc ? 2 : 0) |
           (has_slab ? 4 : 0);
}

/* Test 4: /proc/diskstats I/O info */
static int try_proc_diskstats(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/diskstats", buf, sizeof(buf));
    if (n <= 0) return 0;
    return 1; /* Disk I/O statistics readable */
}

/* Test 5: /proc/net/dev network stats */
static int try_proc_net_dev(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/net/dev", buf, sizeof(buf));
    if (n <= 0) return 0;

    int has_lo = (strstr(buf, "lo:") != NULL);
    int has_eth = (strstr(buf, "eth") != NULL || strstr(buf, "ens") != NULL ||
                   strstr(buf, "enp") != NULL);

    return (has_lo ? 1 : 0) | (has_eth ? 2 : 0);
}

/* Test 6: Filesystem timing oracle */
static int try_fs_timing_oracle(void) {
    struct timespec start, end;

    /* Measure time to open an existing file */
    clock_gettime(CLOCK_MONOTONIC, &start);
    int fd1 = open("/etc/hostname", O_RDONLY);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long exist_us = timespec_diff_us(&start, &end);
    if (fd1 >= 0) close(fd1);

    /* Measure time to open a non-existing file */
    clock_gettime(CLOCK_MONOTONIC, &start);
    int fd2 = open("/etc/this_does_not_exist_at_all", O_RDONLY);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long noexist_us = timespec_diff_us(&start, &end);
    if (fd2 >= 0) close(fd2);

    /* If times differ significantly, file existence is detectable */
    long diff = (exist_us > noexist_us) ? exist_us - noexist_us : noexist_us - exist_us;

    /* Return: 1 if timing difference detectable (>5us), 0 otherwise */
    return (diff > 5) ? 1 : 0;
}

/* Test 7: rdtsc/clock_gettime precision measurement */
static int try_timing_precision(void) {
    struct timespec ts1, ts2;

    /* Measure clock_gettime resolution */
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    clock_gettime(CLOCK_MONOTONIC, &ts2);

    long diff_ns = (ts2.tv_sec - ts1.tv_sec) * 1000000000L +
                   (ts2.tv_nsec - ts1.tv_nsec);

    /* Also test CLOCK_REALTIME */
    struct timespec res;
    clock_getres(CLOCK_MONOTONIC, &res);
    long resolution_ns = res.tv_sec * 1000000000L + res.tv_nsec;

    /* < 100ns resolution is exploit-grade */
    return (resolution_ns <= 100) ? 1 : 0;
}

/* Test 8: sched_yield timing channel */
static int try_sched_timing(void) {
    struct timespec start, end;
    long total_us = 0;
    int iterations = 100;

    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        sched_yield();
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_us += timespec_diff_us(&start, &end);
    }

    long avg_us = total_us / iterations;

    /* sched_yield timing reveals system load / other processes */
    /* Avg < 10us = low load, > 100us = high load */
    return (int)avg_us;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("COVERT CHANNELS & INFORMATION LEAKS");

    int stat = try_proc_stat();
    TEST("/proc/stat CPU info (info)",
         1,
         stat == 0 ? "not readable" :
         "readable (cpu=%d intr=%d ctxt=%d procs=%d)",
         !!(stat & 1), !!(stat & 2), !!(stat & 4), !!(stat & 8));

    int mem = try_proc_meminfo();
    TEST("/proc/meminfo (info)",
         1,
         mem == 0 ? "not readable" :
         "readable (total=%d free=%d avail=%d cached=%d)",
         !!(mem & 1), !!(mem & 2), !!(mem & 4), !!(mem & 8));

    int vmstat = try_proc_vmstat();
    TEST("/proc/vmstat (info)",
         1,
         vmstat == 0 ? "not readable" :
         "readable (pgfault=%d pgalloc=%d slab=%d)",
         !!(vmstat & 1), !!(vmstat & 2), !!(vmstat & 4));

    int disk = try_proc_diskstats();
    TEST("/proc/diskstats (info)",
         1,
         disk == 1 ? "readable (disk I/O visible)" : "not readable");

    int netdev = try_proc_net_dev();
    TEST("/proc/net/dev (info)",
         1,
         netdev == 0 ? "not readable" :
         "readable (lo=%d eth=%d)",
         !!(netdev & 1), !!(netdev & 2));

    int fs_oracle = try_fs_timing_oracle();
    TEST("filesystem timing oracle (info)",
         1,
         fs_oracle == 1 ? "detectable timing difference" :
         "no significant timing difference");

    int precision = try_timing_precision();
    TEST("timing precision (info)",
         1,
         precision == 1 ? "<=100ns resolution (exploit-grade)" :
         "coarse resolution");

    int sched = try_sched_timing();
    TEST("sched_yield timing channel (info)",
         1,
         "avg yield time: %dus (load indicator)", sched);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
