/*
 * test_47_rlimit_escape.c — Resource limit manipulation and bypass tests
 *
 * Resource limits (rlimits) are a defense layer, but manipulating them can:
 *  - prlimit64(): Change limits of other processes
 *  - setrlimit(RLIMIT_CORE, UNLIMITED): Enable core dumps (leak secrets)
 *  - setrlimit(RLIMIT_NPROC, HIGH): Increase process limits (fork bombs)
 *  - setrlimit(RLIMIT_STACK, UNLIMITED): Disable stack guard pages
 *  - setrlimit(RLIMIT_MEMLOCK, HIGH): Lock more memory (mlock/mlockall)
 *  - mlockall(): Lock all pages (prevent swapping — DoS + side channel)
 *  - mlock2(): Lock pages with MLOCK_ONFAULT
 *
 * Tests:
 *  1. prlimit64() on self
 *  2. prlimit64() on other process (cross-process limit change)
 *  3. setrlimit(RLIMIT_CORE) raise attempt
 *  4. setrlimit(RLIMIT_NPROC) raise attempt
 *  5. setrlimit(RLIMIT_STACK) raise attempt
 *  6. mlockall() blocked
 *  7. mlock() on sensitive region
 *  8. setrlimit(RLIMIT_MEMLOCK) raise attempt
 */
#include "test_harness.h"

/* Test 1: prlimit64() on self — read current limits */
static int try_prlimit_self(void) {
    g_got_sigsys = 0;
    struct rlimit rl;
    long ret = syscall(__NR_prlimit64, 0, RLIMIT_NOFILE, NULL, &rl);

    if (g_got_sigsys) return -2;
    if (ret == 0) return (int)rl.rlim_cur;
    return 0;
}

/* Test 2: prlimit64() on other process */
static int try_prlimit_other(void) {
    g_got_sigsys = 0;

    pid_t child = fork();
    if (child == 0) {
        sleep(1);
        _exit(0);
    }
    if (child < 0) return 0;

    struct rlimit rl;
    long ret = syscall(__NR_prlimit64, child, RLIMIT_NOFILE, NULL, &rl);
    int result;

    if (g_got_sigsys) result = -2;
    else if (ret == 0) result = 1; /* Can read other process limits */
    else if (errno == EPERM) result = 0;
    else result = 0;

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

/* Test 3: setrlimit(RLIMIT_CORE) raise attempt */
static int try_raise_core(void) {
    g_got_sigsys = 0;
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);

    rlim_t old_cur = rl.rlim_cur;
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;

    int ret = setrlimit(RLIMIT_CORE, &rl);

    if (g_got_sigsys) return -2;
    if (ret == 0) {
        /* Restore */
        rl.rlim_cur = old_cur;
        setrlimit(RLIMIT_CORE, &rl);
        return 1; /* Raised to unlimited! */
    }
    return 0;
}

/* Test 4: setrlimit(RLIMIT_NPROC) raise attempt */
static int try_raise_nproc(void) {
    g_got_sigsys = 0;
    struct rlimit rl;
    getrlimit(RLIMIT_NPROC, &rl);

    rlim_t old_cur = rl.rlim_cur;
    rlim_t old_max = rl.rlim_max;

    /* Try to raise above current hard limit */
    rl.rlim_cur = 100000;
    rl.rlim_max = 100000;

    int ret = setrlimit(RLIMIT_NPROC, &rl);

    if (g_got_sigsys) return -2;
    if (ret == 0) {
        /* Restore */
        rl.rlim_cur = old_cur;
        rl.rlim_max = old_max;
        setrlimit(RLIMIT_NPROC, &rl);
        return 1; /* Raised! */
    }

    /* Try to raise just soft within hard limit */
    getrlimit(RLIMIT_NPROC, &rl);
    if (rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        ret = setrlimit(RLIMIT_NPROC, &rl);
        if (ret == 0) return 2; /* Raised soft to hard */
    }

    return 0;
}

/* Test 5: setrlimit(RLIMIT_STACK) raise attempt */
static int try_raise_stack(void) {
    g_got_sigsys = 0;
    struct rlimit rl;
    getrlimit(RLIMIT_STACK, &rl);

    /* Try unlimited — disables stack guard pages */
    struct rlimit new_rl = { RLIM_INFINITY, RLIM_INFINITY };
    int ret = setrlimit(RLIMIT_STACK, &new_rl);

    if (g_got_sigsys) return -2;
    if (ret == 0) {
        /* Restore */
        setrlimit(RLIMIT_STACK, &rl);
        return 1; /* Stack unlimited! */
    }
    return 0;
}

/* Test 6: mlockall() blocked */
static int try_mlockall(void) {
    g_got_sigsys = 0;
    int ret = mlockall(MCL_CURRENT | MCL_FUTURE);

    if (g_got_sigsys) return -2;
    if (ret == 0) {
        munlockall();
        return 1; /* All memory locked! */
    }
    if (errno == EPERM) return 0;
    if (errno == ENOMEM) return 2; /* Would succeed but limit too low */
    return 0;
}

/* Test 7: mlock() on sensitive region */
static int try_mlock_sensitive(void) {
    g_got_sigsys = 0;

    /* mlock a page — used in exploits to prevent swapping of payload */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 0;

    int ret = mlock(page, 4096);

    if (ret == 0) munlock(page, 4096);
    munmap(page, 4096);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 8: setrlimit(RLIMIT_MEMLOCK) raise attempt */
static int try_raise_memlock(void) {
    g_got_sigsys = 0;
    struct rlimit rl;
    getrlimit(RLIMIT_MEMLOCK, &rl);

    /* Try to raise to unlimited */
    struct rlimit new_rl = { RLIM_INFINITY, RLIM_INFINITY };
    int ret = setrlimit(RLIMIT_MEMLOCK, &new_rl);

    if (g_got_sigsys) return -2;
    if (ret == 0) {
        /* Restore */
        setrlimit(RLIMIT_MEMLOCK, &rl);
        return 1; /* Unlimited memory locking! */
    }

    /* Return current limit for info */
    return (int)(rl.rlim_cur / 1024); /* In KB */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("RESOURCE LIMIT MANIPULATION & BYPASS");

    int prlimit_self = try_prlimit_self();
    TEST("prlimit64() on self (info)",
         1,
         prlimit_self > 0 ? "RLIMIT_NOFILE cur=%d" :
         prlimit_self == -2 ? "SIGSYS" : "blocked", prlimit_self);

    int prlimit_other = try_prlimit_other();
    TEST("prlimit64() on other process blocked",
         prlimit_other <= 0,
         prlimit_other == 1  ? "READ — cross-process limit access!" :
         prlimit_other == -2 ? "SIGSYS" : "blocked");

    int core = try_raise_core();
    TEST("raise RLIMIT_CORE blocked",
         core <= 0,
         core == 1  ? "RAISED — core dumps enabled (secret leak)!" :
         core == -2 ? "SIGSYS" : "blocked");

    int nproc = try_raise_nproc();
    TEST("raise RLIMIT_NPROC blocked",
         nproc <= 0,
         nproc == 1  ? "RAISED hard limit — fork bomb amplified!" :
         nproc == 2  ? "raised soft to hard (within limit)" :
         nproc == -2 ? "SIGSYS" : "blocked");

    int stack = try_raise_stack();
    TEST("raise RLIMIT_STACK unlimited blocked",
         stack <= 0,
         stack == 1  ? "UNLIMITED — stack guard pages disabled!" :
         stack == -2 ? "SIGSYS" : "blocked");

    int mla = try_mlockall();
    TEST("mlockall() blocked",
         mla != 1,  /* ENOMEM (=2) counts as limited, not escaped */
         mla == 1  ? "LOCKED ALL — memory pinned (DoS)!" :
         mla == 2  ? "ENOMEM (limited by rlimit)" :
         mla == -2 ? "SIGSYS" : "blocked (EPERM)");

    int ml = try_mlock_sensitive();
    TEST("mlock() (info)",
         1,
         ml == 1  ? "works (can pin pages)" :
         ml == -2 ? "SIGSYS" : "blocked");

    int memlock = try_raise_memlock();
    TEST("raise RLIMIT_MEMLOCK blocked",
         memlock <= 0 || memlock > 1, /* allow small existing limits */
         memlock == 1    ? "UNLIMITED — arbitrary memory locking!" :
         memlock == -2   ? "SIGSYS" :
         memlock > 0     ? "current limit: %dKB" : "blocked", memlock);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
