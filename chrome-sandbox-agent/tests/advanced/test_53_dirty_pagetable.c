/*
 * test_53_dirty_pagetable.c — Dirty Pagetable exploitation primitives
 *
 * Dirty Pagetable is the dominant kernel exploitation technique of 2024-2025.
 * It overwrites Page Table Entries (PTEs) to remap user-space virtual
 * addresses to kernel physical addresses, bypassing KASLR, CFI, and heap
 * mitigations.
 *
 * Used in: CVE-2024-50264 (Pwnie 2025), CVE-2024-0582, CVE-2024-1086
 *
 * Prerequisites tested:
 *  - Large mmap/munmap for page table pressure
 *  - mincore() for page residency probing
 *  - madvise(MADV_DONTNEED) for PTE manipulation
 *  - mlock/munlock for physical page pinning
 *  - mremap for memory layout manipulation
 *  - Huge pages (THP) for page table hierarchy attacks
 *
 * Tests:
 *  1. Rapid mmap/munmap cycling (PTE pressure)
 *  2. mincore() page residency probing
 *  3. madvise(MADV_DONTNEED) PTE release
 *  4. madvise(MADV_FREE) lazy page release
 *  5. mlock/munlock physical page control
 *  6. mremap memory manipulation
 *  7. Transparent Huge Pages availability
 *  8. /proc/self/pagemap PFN extraction
 */
#include "test_harness.h"

#define MAP_SIZE (256 * 4096)  /* 1MB */

/* Test 1: Rapid mmap/munmap cycling */
static int try_mmap_cycling(void) {
    g_got_sigsys = 0;
    int cycles = 0;

    for (int i = 0; i < 100; i++) {
        void *p = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) break;

        /* Touch pages to allocate PTEs */
        for (size_t off = 0; off < MAP_SIZE; off += 4096)
            ((volatile char*)p)[off] = 0;

        munmap(p, MAP_SIZE);
        cycles++;
    }

    if (g_got_sigsys) return -2;
    return cycles;
}

/* Test 2: mincore() page residency probing */
static int try_mincore(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 16 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    /* Touch some pages */
    ((volatile char*)p)[0] = 1;
    ((volatile char*)p)[4096] = 1;

    unsigned char vec[16];
    int ret = mincore(p, 16 * 4096, vec);

    munmap(p, 16 * 4096);

    if (g_got_sigsys) return -2;
    if (ret == 0) {
        int resident = 0;
        for (int i = 0; i < 16; i++)
            if (vec[i] & 1) resident++;
        return resident;
    }
    return 0;
}

/* Test 3: madvise(MADV_DONTNEED) PTE release */
static int try_madv_dontneed(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    memset(p, 'X', 4096);

    int ret = madvise(p, 4096, MADV_DONTNEED);
    if (ret == 0) {
        /* Check if page was released (data should be zeroed) */
        int zeroed = (((char*)p)[0] == 0);
        munmap(p, 4096);
        return zeroed ? 2 : 1; /* 2 = PTE released, 1 = just advised */
    }

    munmap(p, 4096);
    if (g_got_sigsys) return -2;
    return 0;
}

/* Test 4: madvise(MADV_FREE) lazy page release */
static int try_madv_free(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    memset(p, 'Y', 4096);

#ifndef MADV_FREE
#define MADV_FREE 8
#endif
    int ret = madvise(p, 4096, MADV_FREE);
    munmap(p, 4096);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    return 0;
}

/* Test 5: mlock/munlock physical page control */
static int try_mlock_cycle(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 64 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    /* Touch all pages */
    memset(p, 'Z', 64 * 4096);

    int locked = (mlock(p, 64 * 4096) == 0);
    int unlocked = 0;
    if (locked) {
        unlocked = (munlock(p, 64 * 4096) == 0);
    }

    munmap(p, 64 * 4096);

    if (g_got_sigsys) return -2;
    return (locked ? 1 : 0) | (unlocked ? 2 : 0);
}

/* Test 6: mremap memory manipulation */
static int try_mremap_manip(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    memset(p, 'R', 4096);

    /* Grow the mapping */
    void *newp = mremap(p, 4096, 8 * 4096, MREMAP_MAYMOVE);
    if (newp != MAP_FAILED) {
        /* Check data preserved */
        int ok = (((char*)newp)[0] == 'R');
        munmap(newp, 8 * 4096);
        return ok ? 1 : 0;
    }

    munmap(p, 4096);
    if (g_got_sigsys) return -2;
    return 0;
}

/* Test 7: Transparent Huge Pages availability */
static int try_thp(void) {
    char buf[256];
    ssize_t n = read_file("/sys/kernel/mm/transparent_hugepage/enabled", buf, sizeof(buf));
    if (n <= 0) return 0;

    int always = (strstr(buf, "[always]") != NULL);
    int madvise_enabled = (strstr(buf, "[madvise]") != NULL);

    if (!always && !madvise_enabled) return 0;

    /* Try to get a huge page */
    void *p = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return always ? 1 : madvise_enabled ? 2 : 0;

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif
    madvise(p, 2 * 1024 * 1024, MADV_HUGEPAGE);
    memset(p, 0, 2 * 1024 * 1024);

    munmap(p, 2 * 1024 * 1024);
    return always ? 3 : 4; /* 3 = always+allocated, 4 = madvise+allocated */
}

/* Test 8: /proc/self/pagemap PFN extraction */
static int try_pagemap_pfn(void) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;

    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { close(fd); return 0; }

    /* Touch the page */
    ((volatile char*)p)[0] = 1;

    /* Read pagemap entry */
    unsigned long addr = (unsigned long)p;
    off_t offset = (addr / 4096) * 8;
    uint64_t entry = 0;

    int readable = 0;
    if (lseek(fd, offset, SEEK_SET) >= 0) {
        if (read(fd, &entry, 8) == 8) {
            readable = 1;
            /* Bit 63 = present, bits 0-54 = PFN */
            if (entry & (1ULL << 63)) {
                uint64_t pfn = entry & ((1ULL << 55) - 1);
                (void)pfn; /* PFN reveals physical address */
                readable = 2; /* Has PFN info */
            }
        }
    }

    munmap(p, 4096);
    close(fd);
    return readable;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("DIRTY PAGETABLE PRIMITIVES (PWNIE 2025)");

    int cycles = try_mmap_cycling();
    TEST("mmap/munmap PTE pressure (info)",
         1,
         cycles > 0 ? "%d cycles completed (PTE churn)" :
         cycles == -2 ? "SIGSYS" : "blocked", cycles);

    int mincore_test = try_mincore();
    TEST("mincore() page residency (info)",
         1,
         mincore_test > 0 ? "%d pages resident (side-channel)" :
         mincore_test == -2 ? "SIGSYS" : "blocked", mincore_test);

    int dontneed = try_madv_dontneed();
    TEST("madvise(MADV_DONTNEED) (info)",
         1,
         dontneed == 2  ? "PTE released (data zeroed)" :
         dontneed == 1  ? "advised (data preserved)" :
         dontneed == -2 ? "SIGSYS" : "blocked");

    int mfree = try_madv_free();
    TEST("madvise(MADV_FREE) (info)",
         1,
         mfree == 1  ? "available (lazy page release)" :
         mfree == -2 ? "SIGSYS" : "blocked");

    int mlock_test = try_mlock_cycle();
    TEST("mlock/munlock cycle (info)",
         1,
         mlock_test == 3 ? "lock+unlock work (page pinning)" :
         mlock_test == 1 ? "lock only" :
         mlock_test == -2 ? "SIGSYS" : "blocked");

    int remap = try_mremap_manip();
    TEST("mremap grow (info)",
         1,
         remap == 1  ? "works (layout manipulation)" :
         remap == -2 ? "SIGSYS" : "blocked");

    int thp = try_thp();
    TEST("THP availability (info)",
         1,
         thp >= 3 ? "THP active + huge pages allocated" :
         thp == 2 ? "THP madvise mode" :
         thp == 1 ? "THP always mode (no allocation)" :
         "THP not available");

    int pagemap = try_pagemap_pfn();
    TEST("/proc/self/pagemap PFN blocked",
         pagemap < 2,
         pagemap == 2 ? "PFN READABLE — physical address leak!" :
         pagemap == 1 ? "readable (no PFN — restricted)" :
         "not readable");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
