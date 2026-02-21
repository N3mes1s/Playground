/*
 * test_46_seccomp_notify.c — SECCOMP_RET_USER_NOTIF and filter bypass tests
 *
 * SECCOMP_RET_USER_NOTIF (added in Linux 5.0) allows a supervisor process
 * to handle syscalls on behalf of the filtered process. This creates a
 * powerful delegation mechanism that can be abused:
 *
 *  - A compromised sandbox process could try to install its own seccomp
 *    filter with USER_NOTIF to intercept syscalls
 *  - SECCOMP_IOCTL_NOTIF_ADDFD allows injecting FDs into the traced process
 *  - seccomp_unotify_id race conditions (TOCTOU on notification IDs)
 *  - Stacking filters: a new ALLOW-all filter doesn't override existing ones,
 *    but TSYNC + USER_NOTIF could be attempted
 *
 * Also tests:
 *  - /proc/self/seccomp status
 *  - PR_GET_SECCOMP / PR_SET_SECCOMP
 *  - SECCOMP_GET_ACTION_AVAIL
 *  - SECCOMP_GET_NOTIF_SIZES
 *
 * Tests:
 *  1. SECCOMP_SET_MODE_FILTER blocked
 *  2. SECCOMP_SET_MODE_FILTER with SECCOMP_FILTER_FLAG_NEW_LISTENER
 *  3. SECCOMP_GET_ACTION_AVAIL for USER_NOTIF
 *  4. SECCOMP_GET_NOTIF_SIZES
 *  5. PR_SET_SECCOMP (prctl interface)
 *  6. PR_GET_SECCOMP status
 *  7. /proc/self/status Seccomp field
 *  8. Seccomp filter stacking attempt
 */
#include "test_harness.h"

#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT  0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER  1
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL 2
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES  3
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER  (1UL << 3)
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC         (1UL << 0)
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF  0x7fc00000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW       0x7fff0000U
#endif
#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE       0x7ff00000U
#endif

/* Test 1: SECCOMP_SET_MODE_FILTER with ALLOW-all */
static int try_seccomp_filter_allow(void) {
    g_got_sigsys = 0;

    struct sock_filter filter[] = {
        { 0x06, 0, 0, SECCOMP_RET_ALLOW },
    };
    struct sock_fprog prog = { .len = 1, .filter = filter };

    long ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Installed filter! */
    if (errno == EPERM) return 0;
    if (errno == EACCES) return 0;
    return 0;
}

/* Test 2: SECCOMP_SET_MODE_FILTER + NEW_LISTENER (user notification) */
static int try_seccomp_new_listener(void) {
    g_got_sigsys = 0;

    struct sock_filter filter[] = {
        { 0x06, 0, 0, SECCOMP_RET_USER_NOTIF },
    };
    struct sock_fprog prog = { .len = 1, .filter = filter };

    /* Do in child to avoid trashing our own seccomp */
    pid_t pid = fork();
    if (pid == 0) {
        long ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
        if (ret >= 0) {
            /* Got a notification FD! */
            close((int)ret);
            _exit(99);
        }
        _exit(errno == EPERM ? 0 : errno == EACCES ? 1 : 2);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (g_got_sigsys) return -2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 99) return 1; /* Got listener! */
    return 0;
}

/* Test 3: SECCOMP_GET_ACTION_AVAIL for USER_NOTIF */
static int try_seccomp_action_avail(void) {
    g_got_sigsys = 0;

    uint32_t action = SECCOMP_RET_USER_NOTIF;
    long ret = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* USER_NOTIF is available */
    if (errno == EOPNOTSUPP) return 0;
    return 0;
}

/* Test 4: SECCOMP_GET_NOTIF_SIZES */
static int try_seccomp_notif_sizes(void) {
    g_got_sigsys = 0;

    struct {
        uint16_t seccomp_notif;
        uint16_t seccomp_notif_resp;
        uint16_t seccomp_data;
    } sizes = {0};

    long ret = syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes);

    if (g_got_sigsys) return -2;
    if (ret == 0) return sizes.seccomp_notif; /* Return notification struct size */
    return 0;
}

/* Test 5: PR_SET_SECCOMP via prctl */
static int try_prctl_set_seccomp(void) {
    g_got_sigsys = 0;

    pid_t pid = fork();
    if (pid == 0) {
        /* Try strict mode via prctl */
        long ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
        if (ret == 0) {
            /* In strict mode — only read, write, exit, sigreturn */
            _exit(99);
        }
        _exit(errno == EPERM ? 0 : 1);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (g_got_sigsys) return -2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 99) return 1;
    return 0;
}

/* Test 6: PR_GET_SECCOMP status */
static int try_prctl_get_seccomp(void) {
    g_got_sigsys = 0;
    long ret = prctl(PR_GET_SECCOMP);

    if (g_got_sigsys) return -2;
    if (ret >= 0) return (int)ret; /* 0=disabled, 1=strict, 2=filter */
    return -1;
}

/* Test 7: /proc/self/status Seccomp field */
static int try_proc_seccomp_status(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/status", buf, sizeof(buf));
    if (n <= 0) return -1;

    char *line = strstr(buf, "Seccomp:");
    if (!line) return -1;

    int mode = -1;
    sscanf(line, "Seccomp:\t%d", &mode);

    /* Also check Seccomp_filters */
    char *fline = strstr(buf, "Seccomp_filters:");
    int filters = 0;
    if (fline) sscanf(fline, "Seccomp_filters:\t%d", &filters);

    return (mode << 8) | (filters & 0xFF);
}

/* Test 8: Seccomp filter stacking attempt */
static int try_seccomp_stack(void) {
    g_got_sigsys = 0;

    pid_t pid = fork();
    if (pid == 0) {
        /* Try to stack two filters */
        struct sock_filter f1[] = { { 0x06, 0, 0, SECCOMP_RET_ALLOW } };
        struct sock_fprog p1 = { .len = 1, .filter = f1 };

        long ret1 = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p1);
        if (ret1 != 0) _exit(0); /* First filter blocked */

        /* Try to add second filter */
        struct sock_filter f2[] = { { 0x06, 0, 0, SECCOMP_RET_ALLOW } };
        struct sock_fprog p2 = { .len = 1, .filter = f2 };
        long ret2 = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p2);

        _exit(ret2 == 0 ? 99 : 1);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (g_got_sigsys) return -2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 99) return 1; /* Stacked! */
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SECCOMP NOTIFICATION & FILTER BYPASS");

    int filter = try_seccomp_filter_allow();
    TEST("SECCOMP_SET_MODE_FILTER blocked",
         filter <= 0,
         filter == 1  ? "INSTALLED — new seccomp filter from sandbox!" :
         filter == -2 ? "SIGSYS" : "blocked (EPERM)");

    int listener = try_seccomp_new_listener();
    TEST("SECCOMP USER_NOTIF listener blocked",
         listener <= 0,
         listener == 1  ? "CREATED — user notification listener!" :
         listener == -2 ? "SIGSYS" : "blocked");

    int avail = try_seccomp_action_avail();
    TEST("SECCOMP_GET_ACTION_AVAIL (info)",
         1,
         avail == 1  ? "USER_NOTIF action available in kernel" :
         avail == -2 ? "SIGSYS" : "not available");

    int sizes = try_seccomp_notif_sizes();
    TEST("SECCOMP_GET_NOTIF_SIZES (info)",
         1,
         sizes > 0 ? "notif struct = %d bytes" :
         sizes == -2 ? "SIGSYS" : "not available", sizes);

    int prctl_set = try_prctl_set_seccomp();
    TEST("PR_SET_SECCOMP blocked",
         prctl_set <= 0,
         prctl_set == 1  ? "SET — seccomp mode changed from sandbox!" :
         prctl_set == -2 ? "SIGSYS" : "blocked");

    int prctl_get = try_prctl_get_seccomp();
    TEST("PR_GET_SECCOMP mode (info)",
         1,
         prctl_get == 2 ? "mode 2 (filter active)" :
         prctl_get == 1 ? "mode 1 (strict)" :
         prctl_get == 0 ? "mode 0 (disabled!)" :
         prctl_get == -2 ? "SIGSYS" : "error");

    int proc_status = try_proc_seccomp_status();
    int mode = (proc_status >> 8) & 0xFF;
    int filters = proc_status & 0xFF;
    TEST("seccomp status in /proc (info)",
         1,
         proc_status >= 0 ? "mode=%d, filters=%d" : "not readable",
         mode, filters);

    int stack = try_seccomp_stack();
    TEST("seccomp filter stacking blocked",
         stack <= 0,
         stack == 1  ? "STACKED — multiple filters from sandbox!" :
         stack == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
