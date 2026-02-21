/*
 * test_52_mseal_bypass.c — mseal() memory sealing bypass probing
 *
 * mseal(2) (Linux 6.10+) seals memory mappings against modification.
 * Chrome/glibc plan to use mseal to protect critical code/data regions.
 *
 * Known bypass vectors (Trail of Bits, October 2024):
 *  - MADV_DONTNEED on sealed file-backed private mappings
 *  - /proc/self/mem write with FOLL_FORCE to sealed RO memory
 *  - ptrace(PTRACE_POKETEXT) to sealed regions
 *
 * Tests:
 *  1. mseal() availability
 *  2. mseal() on anonymous mapping
 *  3. mprotect() on sealed region (should fail)
 *  4. munmap() on sealed region (should fail)
 *  5. mremap() on sealed region (should fail)
 *  6. madvise(MADV_DONTNEED) on sealed region
 *  7. /proc/self/mem write to sealed region
 *  8. mmap(MAP_FIXED) over sealed region
 */
#include "test_harness.h"

#ifndef __NR_mseal
#define __NR_mseal 462
#endif

/* Test 1: mseal() availability */
static int try_mseal_avail(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    long ret = syscall(__NR_mseal, p, 4096, 0);

    if (g_got_sigsys) { munmap(p, 4096); return -2; }
    if (ret == 0) {
        /* Sealed! Try to unmap (may fail) */
        munmap(p, 4096);
        return 1;
    }
    munmap(p, 4096);
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 2: mseal on anonymous RW mapping */
static int try_mseal_anon(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    /* Write data first */
    memset(p, 'A', 4096);

    long ret = syscall(__NR_mseal, p, 4096, 0);
    if (g_got_sigsys) { munmap(p, 4096); return -2; }
    if (ret != 0) { munmap(p, 4096); return 0; }

    /* Verify data is still readable */
    int ok = (((char*)p)[0] == 'A');
    /* munmap may fail since it's sealed */
    munmap(p, 4096);
    return ok ? 1 : 0;
}

/* Test 3: mprotect on sealed region (should fail) */
static int try_mprotect_sealed(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    long sr = syscall(__NR_mseal, p, 4096, 0);
    if (sr != 0) { munmap(p, 4096); return -1; } /* mseal not available */

    /* Try to change permissions */
    int ret = mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    munmap(p, 4096);

    if (ret == 0) return 1; /* mprotect succeeded on sealed! BAD */
    if (errno == EPERM) return 0; /* Correctly blocked */
    return 0;
}

/* Test 4: munmap on sealed region */
static int try_munmap_sealed(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    long sr = syscall(__NR_mseal, p, 4096, 0);
    if (sr != 0) { munmap(p, 4096); return -1; }

    int ret = munmap(p, 4096);
    if (ret == 0) return 1; /* munmap succeeded on sealed! BAD */
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 5: mremap on sealed region */
static int try_mremap_sealed(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    long sr = syscall(__NR_mseal, p, 4096, 0);
    if (sr != 0) { munmap(p, 4096); return -1; }

    void *newp = mremap(p, 4096, 8192, MREMAP_MAYMOVE);
    if (newp != MAP_FAILED) {
        munmap(newp, 8192);
        return 1; /* mremap succeeded on sealed! BAD */
    }
    munmap(p, 4096);
    return 0;
}

/* Test 6: madvise(MADV_DONTNEED) on sealed region */
static int try_madvise_sealed(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    memset(p, 'B', 4096);

    long sr = syscall(__NR_mseal, p, 4096, 0);
    if (sr != 0) { munmap(p, 4096); return -1; }

    /* MADV_DONTNEED discards pages — known bypass vector on file-backed */
    int ret = madvise(p, 4096, MADV_DONTNEED);
    if (ret == 0) {
        /* Check if data was discarded */
        if (((char*)p)[0] != 'B') {
            munmap(p, 4096);
            return 2; /* Data discarded on sealed mapping! */
        }
        munmap(p, 4096);
        return 1; /* madvise returned ok but data preserved */
    }
    munmap(p, 4096);
    return 0; /* madvise blocked */
}

/* Test 7: /proc/self/mem write to sealed region */
static int try_procmem_sealed(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    long sr = syscall(__NR_mseal, p, 4096, 0);
    if (sr != 0) { munmap(p, 4096); return -1; }

    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) { munmap(p, 4096); return 0; }

    /* Try to write to sealed RO memory via /proc/self/mem */
    if (lseek(fd, (off_t)(unsigned long)p, SEEK_SET) >= 0) {
        ssize_t n = write(fd, "PWNED", 5);
        close(fd);
        if (n > 0) {
            munmap(p, 4096);
            return 1; /* Wrote to sealed memory! */
        }
    } else {
        close(fd);
    }
    munmap(p, 4096);
    return 0;
}

/* Test 8: mmap(MAP_FIXED) over sealed region */
static int try_mmap_fixed_sealed(void) {
    g_got_sigsys = 0;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    long sr = syscall(__NR_mseal, p, 4096, 0);
    if (sr != 0) { munmap(p, 4096); return -1; }

    /* Try to overwrite with MAP_FIXED */
    void *newp = mmap(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (newp == p) {
        munmap(p, 4096);
        return 1; /* Overwritten sealed mapping! */
    }
    munmap(p, 4096);
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MSEAL MEMORY SEALING BYPASS (TRAIL OF BITS 2024)");

    int avail = try_mseal_avail();
    TEST("mseal() availability (info)",
         1,
         avail == 1  ? "available (kernel 6.10+)" :
         avail == -2 ? "SIGSYS (seccomp blocked)" :
         avail == -1 ? "ENOSYS (kernel too old)" : "not available");

    /* Remaining tests only meaningful if mseal exists */
    if (avail == 1) {
        int anon = try_mseal_anon();
        TEST("mseal anonymous mapping (info)",
             1,
             anon == 1 ? "sealed and readable" : "failed");

        int mprot = try_mprotect_sealed();
        TEST("mprotect on sealed region blocked",
             mprot <= 0,
             mprot == 1 ? "BYPASSED — mprotect on sealed!" :
             mprot == 0 ? "correctly blocked" : "mseal N/A");

        int unmap = try_munmap_sealed();
        TEST("munmap on sealed region blocked",
             unmap <= 0,
             unmap == 1 ? "BYPASSED — munmap on sealed!" :
             unmap == 0 ? "correctly blocked" : "mseal N/A");

        int remap = try_mremap_sealed();
        TEST("mremap on sealed region blocked",
             remap <= 0,
             remap == 1 ? "BYPASSED — mremap on sealed!" :
             remap == 0 ? "correctly blocked" : "mseal N/A");

        int madv = try_madvise_sealed();
        TEST("madvise(DONTNEED) on sealed blocked",
             madv <= 0,
             madv == 2 ? "BYPASSED — data discarded from sealed mapping!" :
             madv == 1 ? "accepted but data preserved" :
             madv == 0 ? "correctly blocked" : "mseal N/A");

        int procmem = try_procmem_sealed();
        TEST("/proc/self/mem write to sealed blocked",
             procmem <= 0,
             procmem == 1 ? "BYPASSED — wrote to sealed via procmem!" :
             procmem == 0 ? "blocked" : "mseal N/A");

        int fixed = try_mmap_fixed_sealed();
        TEST("mmap(MAP_FIXED) over sealed blocked",
             fixed <= 0,
             fixed == 1 ? "BYPASSED — MAP_FIXED over sealed!" :
             fixed == 0 ? "correctly blocked" : "mseal N/A");
    } else {
        /* mseal not available — mark as info */
        TEST("mseal tests skipped (not available)", 1, "kernel < 6.10");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
