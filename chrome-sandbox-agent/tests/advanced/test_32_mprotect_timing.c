/*
 * test_32_mprotect_timing.c — mprotect timing primitive tests (CVE-2025-38236)
 *
 * Jann Horn's CVE-2025-38236 exploit uses mprotect() on a large anonymous
 * VMA to create a ~1 second kernel delay, providing a timing primitive for
 * race condition exploitation. The technique:
 *  1. mmap a large anonymous region (e.g. 1GB)
 *  2. Touch pages to populate PTEs
 *  3. mprotect() on the region forces TLB shootdown across all CPUs
 *  4. The kernel holds mmap_lock for the duration, creating a deterministic delay
 *
 * This is relevant because mprotect() is allowed in most sandboxes (needed
 * for JIT, memory management, etc.) but can be weaponized for timing.
 *
 * Tests:
 *  1. mprotect on anonymous mapping (basic)
 *  2. mprotect timing with small VMA
 *  3. mprotect timing with medium VMA
 *  4. mprotect PROT_NONE then restore
 *  5. mmap large anonymous region
 *  6. mprotect PROT_EXEC (JIT-like)
 *  7. multiple mprotect calls in sequence
 *  8. mprotect + munmap race surface
 */
#include "test_harness.h"

#define SMALL_SIZE  (4 * 4096)           /* 16KB */
#define MEDIUM_SIZE (256 * 4096)         /* 1MB */
#define LARGE_SIZE  (16384 * 4096)       /* 64MB */

/* Test 1: mprotect on anonymous mapping */
static int try_mprotect_basic(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, SMALL_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    int ret = mprotect(p, SMALL_SIZE, PROT_READ);
    munmap(p, SMALL_SIZE);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 2: mprotect timing with small VMA */
static int try_mprotect_timing_small(void) {
    void *p = mmap(NULL, SMALL_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    /* Touch pages */
    memset(p, 0x41, SMALL_SIZE);

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    mprotect(p, SMALL_SIZE, PROT_READ);
    mprotect(p, SMALL_SIZE, PROT_READ | PROT_WRITE);

    clock_gettime(CLOCK_MONOTONIC, &t2);
    munmap(p, SMALL_SIZE);

    long us = timespec_diff_us(&t1, &t2);
    return (int)us; /* Return microseconds */
}

/* Test 3: mprotect timing with medium VMA */
static int try_mprotect_timing_medium(void) {
    void *p = mmap(NULL, MEDIUM_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    /* Touch pages to populate PTEs */
    for (size_t i = 0; i < MEDIUM_SIZE; i += 4096)
        ((volatile char *)p)[i] = 0x41;

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    mprotect(p, MEDIUM_SIZE, PROT_READ);
    mprotect(p, MEDIUM_SIZE, PROT_READ | PROT_WRITE);

    clock_gettime(CLOCK_MONOTONIC, &t2);
    munmap(p, MEDIUM_SIZE);

    long us = timespec_diff_us(&t1, &t2);
    return (int)us;
}

/* Test 4: mprotect PROT_NONE then restore */
static int try_mprotect_none(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, SMALL_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    int ret1 = mprotect(p, SMALL_SIZE, PROT_NONE);
    int ret2 = mprotect(p, SMALL_SIZE, PROT_READ | PROT_WRITE);
    munmap(p, SMALL_SIZE);

    if (g_got_sigsys) return -2;
    return (ret1 == 0 && ret2 == 0) ? 1 : 0;
}

/* Test 5: mmap large anonymous region */
static int try_large_mmap(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, LARGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_got_sigsys) return -2;
    if (p == MAP_FAILED) return 0;
    munmap(p, LARGE_SIZE);
    return 1;
}

/* Test 6: mprotect PROT_EXEC (JIT-like) */
static int try_mprotect_exec(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    int ret = mprotect(p, 4096, PROT_READ | PROT_EXEC);
    munmap(p, 4096);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 7: rapid mprotect toggling */
static int try_mprotect_rapid(void) {
    void *p = mmap(NULL, SMALL_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    memset(p, 0, SMALL_SIZE);

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Rapid toggle — potential mmap_lock contention */
    for (int i = 0; i < 100; i++) {
        mprotect(p, SMALL_SIZE, PROT_READ);
        mprotect(p, SMALL_SIZE, PROT_READ | PROT_WRITE);
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);
    munmap(p, SMALL_SIZE);

    long us = timespec_diff_us(&t1, &t2);
    return (int)us;
}

/* Test 8: mprotect + munmap race surface */
static int try_mprotect_munmap_race(void) {
    /* This tests whether we can create the race surface used in CVE-2025-38236.
     * We don't actually exploit — just check if the primitives are available. */
    g_got_sigsys = 0;

    void *p = mmap(NULL, MEDIUM_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    /* Touch pages */
    for (size_t i = 0; i < MEDIUM_SIZE; i += 4096)
        ((volatile char *)p)[i] = 0;

    /* Both mprotect and munmap available? */
    int ret = mprotect(p, 4096, PROT_READ);
    munmap(p, MEDIUM_SIZE);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MPROTECT TIMING PRIMITIVE (CVE-2025-38236)");

    /* mprotect is a fundamental memory management syscall that can't be
     * blocked without breaking legitimate functionality. These tests verify
     * that the primitives used in CVE-2025-38236 are documented. */

    int basic = try_mprotect_basic();
    TEST("mprotect on anonymous mapping (info)",
         1, /* mprotect is essential — can't block */
         basic == 1  ? "works (expected — essential syscall)" :
         basic == -2 ? "SIGSYS" : "blocked");

    int timing_small = try_mprotect_timing_small();
    TEST("mprotect timing small VMA (info)",
         1,
         "toggle took %d us", timing_small);

    int timing_medium = try_mprotect_timing_medium();
    TEST("mprotect timing medium VMA (info)",
         1,
         "toggle took %d us (exploit needs >100ms)", timing_medium);

    int prot_none = try_mprotect_none();
    TEST("mprotect PROT_NONE (info)",
         1,
         prot_none == 1  ? "works (guard page technique)" :
         prot_none == -2 ? "SIGSYS" : "blocked");

    int large = try_large_mmap();
    TEST("large anonymous mmap (info)",
         1,
         large == 1  ? "64MB allocated (timing amplifier)" :
         large == -2 ? "SIGSYS" : "blocked");

    int exec = try_mprotect_exec();
    TEST("mprotect PROT_EXEC (info)",
         1,
         exec == 1  ? "works (JIT/W^X supported)" :
         exec == -2 ? "SIGSYS" : "blocked");

    int rapid = try_mprotect_rapid();
    TEST("rapid mprotect toggle x100 (info)",
         1,
         "100 toggles in %d us", rapid);

    int race = try_mprotect_munmap_race();
    TEST("mprotect+munmap race surface (info)",
         1,
         race == 1  ? "both available (CVE-2025-38236 surface)" :
         race == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
