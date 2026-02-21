/*
 * test_34_prctl_audit.c — prctl allowlist audit
 *
 * prctl() is a Swiss Army knife of process attributes. Many PR_SET_*
 * operations have security-relevant side effects:
 *  - PR_SET_DUMPABLE: controls /proc/self/mem access from other processes
 *  - PR_SET_NO_NEW_PRIVS: should already be set by seccomp
 *  - PR_SET_NAME: can confuse process identification
 *  - PR_SET_PDEATHSIG: can manipulate parent death signal
 *  - PR_SET_CHILD_SUBREAPER: intercept child process exits
 *  - PR_SET_MM: modify /proc/self/exe and memory layout (needs CAP_SYS_RESOURCE)
 *  - PR_SET_TIMERSLACK: timing manipulation
 *  - PR_SET_SPECULATION_CTRL: Spectre mitigations
 *
 * Tests:
 *  1. PR_SET_DUMPABLE (controls /proc access)
 *  2. PR_GET_NO_NEW_PRIVS (verify set)
 *  3. PR_SET_NAME (process naming)
 *  4. PR_SET_PDEATHSIG (parent death signal)
 *  5. PR_SET_CHILD_SUBREAPER
 *  6. PR_SET_MM (memory layout modification)
 *  7. PR_SET_TIMERSLACK (timing)
 *  8. PR_SET_SECCOMP (alternative seccomp entry)
 */
#include "test_harness.h"

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif
#ifndef PR_GET_CHILD_SUBREAPER
#define PR_GET_CHILD_SUBREAPER 37
#endif
#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif
#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL 52
#endif
#ifndef PR_SPEC_STORE_BYPASS
#define PR_SPEC_STORE_BYPASS 0
#endif

/* Test 1: PR_SET_DUMPABLE */
static int try_set_dumpable(void) {
    g_got_sigsys = 0;
    /* PR_SET_DUMPABLE=1 allows ptrace/proc access from same-UID processes.
     * PR_SET_DUMPABLE=0 restricts it. If we can toggle this, we control
     * whether our memory is accessible to the broker. */
    int old = prctl(PR_GET_DUMPABLE);
    if (g_got_sigsys) return -2;

    int ret = prctl(PR_SET_DUMPABLE, 1);
    if (ret == 0) {
        /* Can set dumpable — this is expected but worth noting */
        prctl(PR_SET_DUMPABLE, old);
        return 1;
    }
    return 0;
}

/* Test 2: PR_GET_NO_NEW_PRIVS — should already be set by seccomp */
static int try_get_nnp(void) {
    g_got_sigsys = 0;
    int ret = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (g_got_sigsys) return -2;
    return ret; /* 1 = set (good), 0 = not set (bad) */
}

/* Test 3: PR_SET_NAME */
static int try_set_name(void) {
    g_got_sigsys = 0;
    char old_name[16];
    prctl(PR_GET_NAME, old_name);

    int ret = prctl(PR_SET_NAME, "evil_process");
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        prctl(PR_SET_NAME, old_name);
        return 1;
    }
    return 0;
}

/* Test 4: PR_SET_PDEATHSIG */
static int try_set_pdeathsig(void) {
    g_got_sigsys = 0;
    /* Setting parent death signal — commonly used but can be abused
     * to detect when parent broker dies */
    int old = 0;
    prctl(PR_GET_PDEATHSIG, &old);

    int ret = prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        prctl(PR_SET_PDEATHSIG, old);
        return 1;
    }
    return 0;
}

/* Test 5: PR_SET_CHILD_SUBREAPER */
static int try_child_subreaper(void) {
    g_got_sigsys = 0;
    int ret = prctl(PR_SET_CHILD_SUBREAPER, 1);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        prctl(PR_SET_CHILD_SUBREAPER, 0);
        return 1;
    }
    return 0;
}

/* Test 6: PR_SET_MM — modify memory layout (needs CAP_SYS_RESOURCE) */
static int try_set_mm(void) {
    g_got_sigsys = 0;
    /* PR_SET_MM_EXE_FILE = 13 — modify /proc/self/exe link */
    int ret = prctl(PR_SET_MM, 13 /* PR_SET_MM_EXE_FILE */, -1, 0, 0);
    if (g_got_sigsys) return -2;
    /* EPERM is expected (need CAP_SYS_RESOURCE), EINVAL is OK too */
    if (ret == 0) return 1; /* Shouldn't happen without CAP */
    if (errno == EPERM || errno == EINVAL || errno == EBADF) return 0;
    return 0;
}

/* Test 7: PR_SET_TIMERSLACK */
static int try_set_timerslack(void) {
    g_got_sigsys = 0;
    /* Timer slack affects sleep/timer precision — useful for timing attacks */
    int ret = prctl(PR_SET_TIMERSLACK, 1 /* 1 nanosecond */);
    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 8: PR_SET_SECCOMP (alternative seccomp entry via prctl) */
static int try_prctl_seccomp(void) {
    g_got_sigsys = 0;
    /* prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...) is an alternative
     * to seccomp(SECCOMP_SET_MODE_FILTER). Should be blocked. */
    struct sock_filter filter[] = {
        /* BPF: return ALLOW for everything */
        { 0x06, 0, 0, 0x7fff0000 }, /* ret SECCOMP_RET_ALLOW */
    };
    struct sock_fprog prog = {
        .len = 1,
        .filter = filter,
    };

    int ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0; /* 1 = BAD — added seccomp filter */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("PRCTL ALLOWLIST AUDIT");

    int dumpable = try_set_dumpable();
    TEST("PR_SET_DUMPABLE (info)",
         1, /* setting dumpable is normal */
         dumpable == 1  ? "can toggle (expected)" :
         dumpable == -2 ? "SIGSYS" : "blocked");

    int nnp = try_get_nnp();
    TEST("PR_GET_NO_NEW_PRIVS set",
         nnp == 1,
         nnp == 1  ? "set (good — prevents privilege escalation)" :
         nnp == -2 ? "SIGSYS" :
         nnp == 0  ? "NOT SET — privilege escalation possible!" : "error");

    int name = try_set_name();
    TEST("PR_SET_NAME (info)",
         1,
         name == 1  ? "can set (minor — process naming)" :
         name == -2 ? "SIGSYS" : "blocked");

    int pdeathsig = try_set_pdeathsig();
    TEST("PR_SET_PDEATHSIG (info)",
         1,
         pdeathsig == 1  ? "can set (detects broker death)" :
         pdeathsig == -2 ? "SIGSYS" : "blocked");

    int subreaper = try_child_subreaper();
    TEST("PR_SET_CHILD_SUBREAPER (info)",
         1,
         subreaper == 1  ? "can set (process reparenting)" :
         subreaper == -2 ? "SIGSYS" : "blocked");

    int mm = try_set_mm();
    TEST("PR_SET_MM blocked",
         mm <= 0,
         mm == 1  ? "ACCESSIBLE — memory layout modification!" :
         mm == -2 ? "SIGSYS" : "blocked (EPERM — needs CAP_SYS_RESOURCE)");

    int timerslack = try_set_timerslack();
    TEST("PR_SET_TIMERSLACK (info)",
         1,
         timerslack == 1  ? "can set (timing precision)" :
         timerslack == -2 ? "SIGSYS" : "blocked");

    int seccomp = try_prctl_seccomp();
    TEST("PR_SET_SECCOMP blocked",
         seccomp <= 0,
         seccomp == 1  ? "ADDED FILTER — seccomp reconfiguration!" :
         seccomp == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
