/*
 * test_84_tlb_slub_sidechan.c — TLB defense-amplified leaks & SLUB timing
 *
 * Based on:
 *   - Defense-Amplified TLB Side-Channels (USENIX Security 2025, Graz)
 *   - SLUBStick (USENIX Security 2024, Graz)
 *   - Transient Scheduler Attacks (AMD Zen 3/4, July 2025)
 *
 * Key insight: Kernel defenses (vmap stack, KFENCE, vmalloc heap) that
 * split 2MB huge pages into 4KB pages create fine-grained TLB contention
 * patterns observable from userspace. More defenses = more leakage.
 *
 * Tests:
 *  1. TLB eviction set allocation
 *  2. TLB reload timing measurement
 *  3. Large page vs small page TLB behavior
 *  4. SLUB partial slab vs new slab timing
 *  5. Page fault timing (demand paging side channel)
 *  6. /proc/self/smaps TLB info exposure
 *  7. Transparent Huge Pages (THP) status
 *  8. KFENCE detection via timing
 */
#include "test_harness.h"

int main(void) {
    install_sigsys_handler();
    setvbuf(stdout, NULL, _IONBF, 0);

    PRINT_HEADER("TLB DEFENSE-AMPLIFIED LEAKS & SLUB TIMING");

    /* Test 1: TLB eviction set allocation
     * Allocate a mapping to serve as a TLB eviction set.
     * The TLB has limited entries; accessing many pages evicts entries. */
    {
        /* 1MB mapping = 256 pages */
        size_t evict_size = 1024 * 1024;
        void *evict_set = mmap(NULL, evict_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int mapped = (evict_set != MAP_FAILED);

        if (mapped) {
            /* Touch some pages to populate page tables */
            for (size_t i = 0; i < evict_size; i += 4096) {
                ((volatile char *)evict_set)[i] = 0;
            }
            munmap(evict_set, evict_size);
        }

        TEST("TLB eviction set allocation noted",
             1, /* mmap is fundamental */
             mapped ? "1MB eviction set allocated (256 pages)" :
             "mmap failed");
    }

    /* Test 2: TLB reload timing measurement
     * Measure the timing difference between TLB hit and TLB miss.
     * Defense-amplified attacks exploit this delta. */
    {
        size_t size = 512 * 1024; /* 512KB */
        void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        long hit_ns = 0, miss_ns = 0;

        if (mem != MAP_FAILED) {
            struct timespec start, end;

            /* Warm up — ensure pages are in TLB */
            for (size_t i = 0; i < 4096 * 32; i += 4096)
                ((volatile char *)mem)[i] = 0;

            /* Measure TLB hit time (pages should be in TLB) */
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < 4096 * 32; i += 4096) {
                volatile char x = ((volatile char *)mem)[i];
                (void)x;
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            hit_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                     (end.tv_nsec - start.tv_nsec);

            /* Evict TLB by accessing many different pages */
            for (size_t i = 0; i < size; i += 4096)
                ((volatile char *)mem)[i] = 0;

            /* Measure TLB miss time */
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < size; i += 4096 * 4) {
                volatile char x = ((volatile char *)mem)[i];
                (void)x;
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            miss_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);

            munmap(mem, size);
        }

        long delta = miss_ns - hit_ns;
        test_checkf("TLB reload timing delta noted", 1,
                    "hit=%ldns miss=%ldns delta=%ldns",
                    hit_ns, miss_ns, delta);
    }

    /* Test 3: Large page vs small page TLB behavior
     * Check if transparent huge pages affect TLB behavior. */
    {
        /* Map with MAP_HUGETLB to try to get 2MB pages */
        size_t huge_size = 2 * 1024 * 1024; /* 2MB */
        void *huge = mmap(NULL, huge_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        int got_huge = (huge != MAP_FAILED);

        /* Map regular 4KB pages for comparison */
        void *small = mmap(NULL, huge_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int got_small = (small != MAP_FAILED);

        if (got_huge) munmap(huge, huge_size);
        if (got_small) munmap(small, huge_size);

        TEST("Huge page availability noted",
             1, /* informational */
             got_huge ? "2MB huge pages available (fewer TLB entries needed)" :
             "huge pages unavailable (all pages 4KB — defense-amplified leak applies)");
    }

    /* Test 4: SLUB partial slab vs new slab timing */
    {
        struct timespec start, end;
        long partial_ns = 0, new_ns = 0;

        /* Phase 1: Warm up SLUB by creating and closing many pipes
         * This fills the partial slab lists */
        for (int i = 0; i < 20; i++) {
            int pf[2];
            if (pipe(pf) == 0) { close(pf[0]); close(pf[1]); }
        }

        /* Phase 2: Measure time to create a pipe (should allocate from partial slab) */
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 20; i++) {
            int pf[2];
            if (pipe(pf) == 0) { close(pf[0]); close(pf[1]); }
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        partial_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                     (end.tv_nsec - start.tv_nsec);

        /* Phase 3: Exhaust current slabs by holding many open */
        int held_fds[128];
        int held = 0;
        for (int i = 0; i < 32; i++) {
            if (pipe(&held_fds[held]) == 0) held += 2;
        }

        /* Phase 4: Measure time (may need new slab page from buddy) */
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 20; i++) {
            int pf[2];
            if (pipe(pf) == 0) { close(pf[0]); close(pf[1]); }
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        new_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                 (end.tv_nsec - start.tv_nsec);

        /* Clean up held FDs */
        for (int i = 0; i < held; i++) close(held_fds[i]);

        long delta = new_ns - partial_ns;
        TEST("SLUB slab allocation timing noted",
             1, /* fundamental kernel behavior */
             "partial=%ldns exhausted=%ldns delta=%ldns",
             partial_ns, new_ns, delta);
    }

    /* Test 5: Page fault timing (demand paging side channel) */
    {
        struct timespec start, end;
        /* Map but don't populate — first access triggers page fault */
        void *mem = mmap(NULL, 4096 * 4, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        long fault_ns = 0;

        if (mem != MAP_FAILED) {
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (int i = 0; i < 4; i++) {
                ((volatile char *)mem)[i * 4096] = 0;
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            fault_ns = ((end.tv_sec - start.tv_sec) * 1000000000L +
                        (end.tv_nsec - start.tv_nsec)) / 4;
            munmap(mem, 4096 * 4);
        }

        if (fault_ns > 0)
            test_checkf("Page fault timing noted", 1,
                        "~%ldns per page fault (demand paging)", fault_ns);
        else
            test_check("Page fault timing noted", 1,
                       "measurement failed");
    }

    /* Test 6: /proc/self/smaps TLB info exposure */
    {
        char buf[4096];
        ssize_t n = read_file("/proc/self/smaps", buf, sizeof(buf));
        int readable = (n > 0);

        /* smaps reveals page sizes, which aids TLB attacks */
        TEST("/proc/self/smaps noted",
             1, /* process's own info */
             readable ? "readable (page size info available for TLB attacks)" :
             "not readable");
    }

    /* Test 7: Transparent Huge Pages (THP) status */
    {
        char buf[256];
        ssize_t n = read_file("/sys/kernel/mm/transparent_hugepage/enabled",
                              buf, sizeof(buf));
        int readable = (n > 0);

        /* THP status affects TLB side channel viability:
         * - THP enabled = fewer TLB entries = harder to evict
         * - THP disabled = all 4KB = defense-amplified leak applies */
        if (readable)
            test_checkf("Transparent Huge Pages status noted", 1,
                        "THP: %.60s", buf);
        else
            test_check("Transparent Huge Pages status noted", 1,
                       "not readable (sysfs restricted)");
    }

    /* Test 8: KFENCE detection via timing
     * KFENCE places guard pages around slab objects, which creates
     * unique page table patterns detectable via TLB timing. */
    {
        char buf[256];
        ssize_t n = read_file("/sys/kernel/mm/kfence/count", buf, sizeof(buf));
        int readable = (n > 0);
        int enabled = (readable && buf[0] != '0');

        /* KFENCE's guard pages split huge pages, creating TLB side channels */
        if (readable && enabled)
            test_checkf("KFENCE status noted", 1,
                        "active (%.*s objects, creates TLB patterns)",
                        (int)(n > 20 ? 20 : n), buf);
        else
            test_check("KFENCE status noted", 1,
                       readable ? "inactive or zero" :
                       "not readable (sysfs restricted)");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
