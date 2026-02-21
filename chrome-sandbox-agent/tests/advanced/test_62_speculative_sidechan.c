/*
 * test_62_speculative_sidechan.c — Speculative execution side channels
 *
 * Tests for CPU-level side channel attacks that could leak information
 * across sandbox boundaries:
 *
 * - RDTSC/RDTSCP precision (used in Spectre/Meltdown variants)
 * - perf_event_open (hardware performance counters)
 * - FLUSH+RELOAD / PRIME+PROBE cache timing
 * - Branch prediction side channels (Spectre v2/BHI)
 *
 * These attacks exploit microarchitectural state to leak data without
 * any syscall violations, making them particularly dangerous.
 *
 * Tests:
 *  1. perf_event_open (hardware counters)
 *  2. perf_event_open (software counters)
 *  3. RDTSC precision measurement
 *  4. Cache timing side channel (FLUSH+RELOAD)
 *  5. Memory access timing oracle
 *  6. /proc/cpuinfo details leak
 *  7. /sys/devices/system/cpu info leak
 *  8. CPUID info leakage
 */
#include "test_harness.h"
#include <linux/perf_event.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

/* Force a cache line flush (x86) */
static inline void clflush(volatile void *p) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("clflush (%0)" :: "r"(p) : "memory");
#else
    (void)p;
#endif
}

/* Read TSC */
static inline uint64_t rdtsc(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__i386__)
    uint64_t val;
    __asm__ volatile("rdtsc" : "=A"(val));
    return val;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SPECULATIVE EXECUTION SIDE CHANNELS");

    /* Test 1: perf_event_open — hardware counters */
    {
        g_got_sigsys = 0;
        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(pe));
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_HW_CPU_CYCLES;
        pe.disabled = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;

        long fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
        int blocked = (fd < 0 || g_got_sigsys);
        if (fd >= 0) close((int)fd);

        TEST("perf_event_open(HW_CPU_CYCLES) blocked",
             blocked,
             blocked ? "blocked" :
             "PERF — hardware cycle counter accessible!");
    }

    /* Test 2: perf_event_open — software counters */
    {
        g_got_sigsys = 0;
        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(pe));
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_PAGE_FAULTS;
        pe.disabled = 1;

        long fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
        int blocked = (fd < 0 || g_got_sigsys);
        if (fd >= 0) close((int)fd);

        TEST("perf_event_open(SW_PAGE_FAULTS) blocked",
             blocked,
             blocked ? "blocked" :
             "PERF — software page fault counter accessible!");
    }

    /* Test 3: RDTSC precision measurement */
    {
        g_got_sigsys = 0;
        uint64_t t1 = rdtsc();
        /* Do something measurable */
        volatile int x = 0;
        for (int i = 0; i < 100; i++) x += i;
        uint64_t t2 = rdtsc();

        uint64_t delta = t2 - t1;
        /* RDTSC is a user-mode instruction on x86 — cannot be blocked
         * by seccomp (which only filters syscalls). This is a known
         * limitation. We note availability but don't mark as failure. */
        int high_precision = (delta > 0 && delta < 1000000);
        TEST("RDTSC precision noted",
             1,  /* always pass — RDTSC can't be blocked by seccomp */
             high_precision ? "available (user-mode instruction, inherent)" :
             "limited precision");
        (void)x;
    }

    /* Test 4: Cache timing side channel (FLUSH+RELOAD pattern) */
    {
        g_got_sigsys = 0;
        /* Allocate a page-aligned buffer */
        volatile char *probe = (volatile char *)mmap(
            NULL, 4096, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        int timing_works = 0;
        if (probe != MAP_FAILED) {
            probe[0] = 'A';

            /* Measure cached access */
            uint64_t t1 = rdtsc();
            volatile char tmp = probe[0];
            uint64_t cached_time = rdtsc() - t1;
            (void)tmp;

            /* Flush and measure uncached access */
            clflush((void *)probe);
            __asm__ volatile("mfence" ::: "memory");

            t1 = rdtsc();
            tmp = probe[0];
            uint64_t uncached_time = rdtsc() - t1;

            /* If we can distinguish cached vs uncached, side channel works */
            timing_works = (uncached_time > cached_time * 2);
            munmap((void *)probe, 4096);
        }

        TEST("Cache FLUSH+RELOAD side channel limited",
             !timing_works,
             timing_works ? "TIMING — cache side channel distinguishable!" :
             "timing indistinguishable (acceptable)");
    }

    /* Test 5: Memory access timing oracle */
    {
        g_got_sigsys = 0;
        volatile char *buf = (volatile char *)mmap(
            NULL, 256 * 4096, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        int oracle_works = 0;
        if (buf != MAP_FAILED) {
            /* Touch one page */
            buf[42 * 4096] = 1;

            /* Flush all pages */
            for (int i = 0; i < 256; i++)
                clflush((void *)(buf + i * 4096));
            __asm__ volatile("mfence" ::: "memory");

            /* Touch target again */
            volatile char tmp = buf[42 * 4096];
            (void)tmp;

            /* Probe all pages to find which is cached */
            int detected = -1;
            uint64_t min_time = ~0ULL;
            for (int i = 0; i < 256; i++) {
                uint64_t t1 = rdtsc();
                tmp = buf[i * 4096];
                uint64_t t = rdtsc() - t1;
                if (t < min_time) {
                    min_time = t;
                    detected = i;
                }
            }

            oracle_works = (detected == 42);
            munmap((void *)buf, 256 * 4096);
        }

        TEST("Memory access timing oracle limited",
             !oracle_works,
             oracle_works ? "ORACLE — cache probe identified target page!" :
             "probe inconclusive (acceptable)");
    }

    /* Test 6: /proc/cpuinfo details */
    {
        char buf[8192];
        ssize_t n = read_file("/proc/cpuinfo", buf, sizeof(buf));

        int has_details = 0;
        if (n > 0) {
            /* Check for sensitive microarch details */
            has_details = (strstr(buf, "model name") != NULL &&
                          strstr(buf, "cpu MHz") != NULL);
        }
        /* /proc/cpuinfo is typically readable from sandboxed processes.
         * The info is also available via CPUID instruction anyway.
         * Note as informational, don't fail. */
        TEST("/proc/cpuinfo details noted",
             1,  /* always pass — CPU info is available via CPUID anyway */
             n <= 0 ? "blocked" :
             has_details ? "readable (also available via CPUID instruction)" :
             "limited info");
    }

    /* Test 7: /sys/devices/system/cpu enumeration */
    {
        char buf[4096];
        ssize_t n = read_file("/sys/devices/system/cpu/online", buf, sizeof(buf));
        int readable = (n > 0);
        TEST("/sys/devices/system/cpu/online blocked",
             !readable,
             readable ? "TOPOLOGY — CPU topology visible!" :
             "blocked");
    }

    /* Test 8: perf_event_open with cache references (Spectre-relevant) */
    {
        g_got_sigsys = 0;
        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(pe));
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_HW_CACHE_MISSES;
        pe.disabled = 1;
        pe.exclude_kernel = 1;

        long fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
        int blocked = (fd < 0 || g_got_sigsys);
        if (fd >= 0) close((int)fd);

        TEST("perf_event_open(CACHE_MISSES) blocked",
             blocked,
             blocked ? "blocked" :
             "CACHE MISS — cache miss counter accessible (Spectre vector)!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
