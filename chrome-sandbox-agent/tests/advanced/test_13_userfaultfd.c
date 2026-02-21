/*
 * test_13_userfaultfd.c — userfaultfd kernel race stabilizer tests
 *
 * userfaultfd allows user-space to handle page faults, which attackers
 * use to pause kernel execution at precise points to win race conditions.
 * Combined with kernel UAF/TOCTOU bugs, it enables reliable exploitation.
 * CVE-2025-38352 demonstrated active in-the-wild exploitation of kernel
 * race conditions from within sandboxes.
 *
 * Tests:
 *  1. userfaultfd() syscall availability
 *  2. UFFD_USER_MODE_ONLY restriction
 *  3. /proc/sys/vm/unprivileged_userfaultfd check
 *  4. mprotect() as alternative race stabilizer
 *  5. FUSE mount for controlled page faults
 *  6. MADV_DONTNEED + fault as race primitive
 *  7. mremap() for page table manipulation
 *  8. process_madvise for cross-process memory influence
 */
#include "test_harness.h"

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif

/* Test 1: Basic userfaultfd syscall */
static int try_userfaultfd(void) {
    g_got_sigsys = 0;
    int fd = (int)syscall(__NR_userfaultfd, 0);
    if (g_got_sigsys) return -2; /* SIGSYS */
    if (fd >= 0) {
        close(fd);
        return 1; /* Available — can stabilize kernel races */
    }
    if (errno == ENOSYS) return -1; /* Not compiled in */
    if (errno == EPERM) return 0;   /* Blocked by privilege */
    return 0;
}

/* Test 2: userfaultfd with UFFD_USER_MODE_ONLY */
static int try_userfaultfd_usermode(void) {
    g_got_sigsys = 0;
    int fd = (int)syscall(__NR_userfaultfd, UFFD_USER_MODE_ONLY);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* User-mode only — less dangerous but still useful */
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 3: Check /proc/sys/vm/unprivileged_userfaultfd */
static int check_unprivileged_userfaultfd(void) {
    char buf[16];
    ssize_t n = read_file("/proc/sys/vm/unprivileged_userfaultfd", buf, sizeof(buf));
    if (n <= 0) return -1;
    return atoi(buf); /* 1 = unprivileged allowed, 0 = restricted */
}

/* Test 4: mprotect() as alternative race stabilizer.
 * Jann Horn (CVE-2025-38236) showed that mprotect() can delay
 * copy_from_user by making pages temporarily inaccessible. */
static int try_mprotect_delay(void) {
    size_t pgsize = (size_t)sysconf(_SC_PAGE_SIZE);
    void *page = mmap(NULL, pgsize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return -1;

    /* Remove access, then immediately restore — simulates the
     * race stabilization pattern used in real exploits */
    int ret1 = mprotect(page, pgsize, PROT_NONE);
    int ret2 = mprotect(page, pgsize, PROT_READ | PROT_WRITE);
    munmap(page, pgsize);

    if (ret1 == 0 && ret2 == 0) return 1; /* mprotect works */
    return 0;
}

/* Test 5: FUSE mount (another way to control page faults) */
static int try_fuse_mount(void) {
    int fd = open("/dev/fuse", O_RDWR);
    if (fd >= 0) {
        close(fd);
        return 1; /* FUSE available — can control I/O delays */
    }
    return 0;
}

/* Test 6: MADV_DONTNEED + fault cycle (weaker race stabilizer) */
static int try_madvise_fault_cycle(void) {
    size_t pgsize = (size_t)sysconf(_SC_PAGE_SIZE);
    void *page = mmap(NULL, pgsize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return -1;

    /* Write data, then discard, then touch — forces page fault */
    *(volatile char *)page = 'A';
    int ret = madvise(page, pgsize, MADV_DONTNEED);
    if (ret < 0) { munmap(page, pgsize); return 0; }

    /* Touch again — triggers a new page fault (allocates new page) */
    volatile char c = *(volatile char *)page;
    (void)c;

    munmap(page, pgsize);
    return 1; /* MADV_DONTNEED works as weak race primitive */
}

/* Test 7: mremap — page table manipulation for race windows */
static int try_mremap_manipulation(void) {
    size_t pgsize = (size_t)sysconf(_SC_PAGE_SIZE);
    void *page = mmap(NULL, pgsize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return -1;

    /* Try to expand mapping — changes page tables */
    void *newp = mremap(page, pgsize, pgsize * 2, MREMAP_MAYMOVE);
    if (newp == MAP_FAILED) {
        munmap(page, pgsize);
        return 0;
    }
    munmap(newp, pgsize * 2);
    return 1; /* mremap available for page table manipulation */
}

/* Test 8: process_madvise — cross-process memory influence */
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif
static int try_process_madvise(void) {
    g_got_sigsys = 0;
    /* Try on our own PID with an invalid iovec to just test availability */
    struct iovec iov = { NULL, 0 };
    long ret = syscall(__NR_process_madvise, getpid(), &iov, 1,
                       MADV_DONTNEED, 0);
    if (g_got_sigsys) return -2;
    if (ret < 0 && errno == ENOSYS) return -1;
    if (ret < 0 && errno == EPERM) return 0;
    /* EINVAL is expected for NULL address — but syscall was reachable */
    return 1;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("USERFAULTFD RACE STABILIZER (CVE-2025-38352)");

    int uffd = try_userfaultfd();
    TEST("userfaultfd() blocked",
         uffd <= 0,
         uffd == 1  ? "AVAILABLE — can stabilize kernel races!" :
         uffd == -2 ? "SIGSYS (seccomp killed)" :
         uffd == -1 ? "ENOSYS (not compiled in)" : "blocked (EPERM)");

    int uffd_user = try_userfaultfd_usermode();
    TEST("userfaultfd(USER_MODE_ONLY) blocked",
         uffd_user <= 0,
         uffd_user == 1  ? "USER_MODE_ONLY available (limited)" :
         uffd_user == -2 ? "SIGSYS" :
         uffd_user == -1 ? "ENOSYS" : "blocked");

    int sysctl = check_unprivileged_userfaultfd();
    TEST("unprivileged_userfaultfd sysctl restricted",
         sysctl <= 0,
         sysctl == 1  ? "ENABLED — unprivileged uffd allowed!" :
         sysctl == 0  ? "restricted (good)" :
         sysctl == -1 ? "sysctl not readable" : "");

    int mprotect_ok = try_mprotect_delay();
    TEST("mprotect() race stabilizer (info)",
         1, /* info only — mprotect is inherently needed */
         mprotect_ok ? "available (alternative to userfaultfd)" :
                       "restricted");

    int fuse = try_fuse_mount();
    TEST("/dev/fuse blocked (FUSE race stabilizer)",
         fuse == 0,
         fuse ? "AVAILABLE — FUSE-based race control possible!" : "blocked");

    int madvise_cycle = try_madvise_fault_cycle();
    TEST("MADV_DONTNEED fault cycle (info)",
         1, /* info only — MADV_DONTNEED is needed for normal operation */
         madvise_cycle ? "available (weak race primitive)" : "restricted");

    int mremap_ok = try_mremap_manipulation();
    TEST("mremap() page table manipulation (info)",
         1, /* info only */
         mremap_ok ? "available (page table rewrite)" : "restricted");

    int proc_madvise = try_process_madvise();
    TEST("process_madvise() blocked",
         proc_madvise <= 0,
         proc_madvise == 1  ? "REACHABLE — cross-process memory influence!" :
         proc_madvise == -2 ? "SIGSYS" :
         proc_madvise == -1 ? "ENOSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
