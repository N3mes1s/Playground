/*
 * test_55_process_madvise.c — Cross-process memory manipulation
 *
 * process_madvise(2) (Linux 5.10+) and process_mrelease(2) (Linux 5.15+)
 * allow cross-process memory management via pidfd. A compromised renderer
 * could use these to:
 *  - Discard pages from browser process (MADV_DONTNEED)
 *  - Force page eviction for timing side-channels (MADV_COLD/PAGEOUT)
 *  - Release memory of dying processes (process_mrelease)
 *
 * Tests:
 *  1. process_madvise() on self
 *  2. process_madvise() on child (MADV_DONTNEED)
 *  3. process_madvise() on child (MADV_COLD)
 *  4. process_madvise() on child (MADV_PAGEOUT)
 *  5. process_mrelease() on dying child
 *  6. process_madvise() permission check (cross-user)
 *  7. process_madvise() on pid 1
 *  8. Rapid cross-process page eviction
 */
#include "test_harness.h"

#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif
#ifndef __NR_process_mrelease
#define __NR_process_mrelease 448
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

/* Test 1: process_madvise on self */
static int try_pmadvise_self(void) {
    g_got_sigsys = 0;

    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    memset(p, 'A', 4096);

    int pidfd = syscall(__NR_pidfd_open, getpid(), 0);
    if (pidfd < 0) { munmap(p, 4096); return g_got_sigsys ? -2 : 0; }

    struct iovec iov = { .iov_base = p, .iov_len = 4096 };
    g_got_sigsys = 0;
    long ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);

    close(pidfd);

    int result;
    if (g_got_sigsys) result = -2;
    else if (ret >= 0) {
        /* Check if page was discarded */
        result = (((char*)p)[0] == 0) ? 2 : 1;
    }
    else if (errno == ENOSYS) result = -1;
    else if (errno == EPERM) result = 0;
    else result = 0;

    munmap(p, 4096);
    return result;
}

/* Test 2: process_madvise on child (MADV_DONTNEED) */
static int try_pmadvise_child_dontneed(void) {
    g_got_sigsys = 0;

    /* Create shared mapping so we can see changes */
    void *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 0;
    memset(shared, 'B', 4096);

    pid_t child = fork();
    if (child == 0) {
        /* Child: keep the shared mapping and sleep */
        sleep(2);
        _exit(0);
    }
    if (child < 0) { munmap(shared, 4096); return 0; }

    int pidfd = syscall(__NR_pidfd_open, child, 0);
    int result = 0;

    if (pidfd >= 0) {
        struct iovec iov = { .iov_base = shared, .iov_len = 4096 };
        g_got_sigsys = 0;
        long ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);

        if (g_got_sigsys) result = -2;
        else if (ret >= 0) result = 1;
        else if (errno == ENOSYS) result = -1;
        else result = 0;

        close(pidfd);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    munmap(shared, 4096);
    return result;
}

/* Test 3: process_madvise MADV_COLD */
static int try_pmadvise_cold(void) {
    g_got_sigsys = 0;

    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    memset(p, 'C', 4096);

    int pidfd = syscall(__NR_pidfd_open, getpid(), 0);
    if (pidfd < 0) { munmap(p, 4096); return g_got_sigsys ? -2 : 0; }

    struct iovec iov = { .iov_base = p, .iov_len = 4096 };
    g_got_sigsys = 0;
    long ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_COLD, 0);

    close(pidfd);
    munmap(p, 4096);

    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1;
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 4: process_madvise MADV_PAGEOUT */
static int try_pmadvise_pageout(void) {
    g_got_sigsys = 0;

    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    memset(p, 'D', 4096);

    int pidfd = syscall(__NR_pidfd_open, getpid(), 0);
    if (pidfd < 0) { munmap(p, 4096); return g_got_sigsys ? -2 : 0; }

    struct iovec iov = { .iov_base = p, .iov_len = 4096 };
    g_got_sigsys = 0;
    long ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_PAGEOUT, 0);

    close(pidfd);
    munmap(p, 4096);

    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1;
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 5: process_mrelease on dying child */
static int try_mrelease(void) {
    g_got_sigsys = 0;

    pid_t child = fork();
    if (child == 0) {
        /* Allocate a lot of memory then die */
        void *p = mmap(NULL, 64 * 1024 * 1024, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) memset(p, 0, 64 * 1024 * 1024);
        _exit(0);
    }
    if (child < 0) return 0;

    int pidfd = syscall(__NR_pidfd_open, child, 0);
    if (pidfd < 0) {
        waitpid(child, NULL, 0);
        return g_got_sigsys ? -2 : 0;
    }

    /* Send SIGKILL and try to release memory while dying */
    kill(child, SIGKILL);

    g_got_sigsys = 0;
    long ret = syscall(__NR_process_mrelease, pidfd, 0);
    int result;

    if (g_got_sigsys) result = -2;
    else if (ret == 0) result = 1;
    else if (errno == ENOSYS) result = -1;
    else result = 0;

    close(pidfd);
    waitpid(child, NULL, 0);
    return result;
}

/* Test 6: process_madvise permission check */
static int try_pmadvise_perm(void) {
    g_got_sigsys = 0;
    /* Try on pid 1 (init) */
    int pidfd = syscall(__NR_pidfd_open, 1, 0);
    if (pidfd < 0) return g_got_sigsys ? -2 : 0;

    char dummy[4096];
    struct iovec iov = { .iov_base = dummy, .iov_len = 4096 };
    g_got_sigsys = 0;
    long ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_COLD, 0);

    close(pidfd);

    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1; /* Cross-process madvise on init! */
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 7: process_madvise on pid 1 (blocked check) */
static int try_pmadvise_init(void) {
    g_got_sigsys = 0;
    int pidfd = syscall(__NR_pidfd_open, 1, 0);
    if (pidfd < 0) return g_got_sigsys ? -2 : 0;

    /* Just check if pidfd_open worked for init */
    close(pidfd);
    return 1;
}

/* Test 8: Rapid cross-process page eviction */
static int try_rapid_eviction(void) {
    g_got_sigsys = 0;

    pid_t child = fork();
    if (child == 0) {
        sleep(2);
        _exit(0);
    }
    if (child < 0) return 0;

    int pidfd = syscall(__NR_pidfd_open, child, 0);
    int evictions = 0;

    if (pidfd >= 0) {
        void *p = mmap(NULL, 16 * 4096, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            memset(p, 'E', 16 * 4096);
            struct iovec iov = { .iov_base = p, .iov_len = 16 * 4096 };

            for (int i = 0; i < 10; i++) {
                g_got_sigsys = 0;
                long ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_PAGEOUT, 0);
                if (g_got_sigsys || ret < 0) break;
                evictions++;
            }
            munmap(p, 16 * 4096);
        }
        close(pidfd);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return evictions;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("CROSS-PROCESS MEMORY MANIPULATION");

    int self = try_pmadvise_self();
    TEST("process_madvise(self) blocked",
         self <= 0,
         self == 2  ? "DISCARDED — cross-process page eviction!" :
         self == 1  ? "ACCESSIBLE — process_madvise works!" :
         self == -2 ? "SIGSYS" :
         self == -1 ? "ENOSYS" : "blocked");

    int child_dn = try_pmadvise_child_dontneed();
    TEST("process_madvise(child, DONTNEED) blocked",
         child_dn <= 0,
         child_dn == 1  ? "EVICTED — child pages discarded!" :
         child_dn == -2 ? "SIGSYS" :
         child_dn == -1 ? "ENOSYS" : "blocked");

    int cold = try_pmadvise_cold();
    TEST("process_madvise(MADV_COLD) blocked",
         cold <= 0,
         cold == 1  ? "COOLED — pages marked cold!" :
         cold == -2 ? "SIGSYS" :
         cold == -1 ? "ENOSYS" : "blocked");

    int pageout = try_pmadvise_pageout();
    TEST("process_madvise(MADV_PAGEOUT) blocked",
         pageout <= 0,
         pageout == 1  ? "PAGED OUT — forced page eviction!" :
         pageout == -2 ? "SIGSYS" :
         pageout == -1 ? "ENOSYS" : "blocked");

    int mrel = try_mrelease();
    TEST("process_mrelease() blocked",
         mrel <= 0,
         mrel == 1  ? "RELEASED — cross-process memory free!" :
         mrel == -2 ? "SIGSYS" :
         mrel == -1 ? "ENOSYS" : "blocked");

    int perm = try_pmadvise_perm();
    TEST("process_madvise on init blocked",
         perm <= 0,
         perm == 1  ? "ACCESSIBLE — madvise on init!" :
         perm == -2 ? "SIGSYS" : "blocked");

    int initfd = try_pmadvise_init();
    TEST("pidfd_open(init) (info)",
         1,
         initfd == 1  ? "pidfd for init accessible" :
         initfd == -2 ? "SIGSYS" : "blocked");

    int evict = try_rapid_eviction();
    TEST("rapid page eviction (info)",
         1,
         evict > 0 ? "%d eviction rounds completed" :
         "no evictions", evict);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
