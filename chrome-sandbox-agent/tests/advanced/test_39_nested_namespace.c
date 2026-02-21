/*
 * test_39_nested_namespace.c — nested namespace bypass tests (Qualys 2025)
 *
 * Qualys researchers discovered three bypasses of Ubuntu's user namespace
 * restrictions in 2025. Even with restrictions like unprivileged_userns_clone=0,
 * attackers found ways to create user namespaces through:
 *  1. aa-exec abuse: Switching to unconfined AppArmor profile
 *  2. busybox/dash: Processes that are unconfined by default
 *  3. LD_PRELOAD: Injecting code into unconfined binaries
 *
 * From sandbox perspective, namespace creation is a critical primitive:
 *  - User namespace provides fake root (uid 0 inside)
 *  - Network namespace provides independent netfilter tables
 *  - Mount namespace enables overlayfs/tmpfs (needed for many exploits)
 *  - PID namespace hides processes
 *
 * Tests:
 *  1. clone with CLONE_NEWUSER
 *  2. unshare(CLONE_NEWUSER)
 *  3. clone with CLONE_NEWNET
 *  4. clone with CLONE_NEWNS (mount)
 *  5. clone with CLONE_NEWPID
 *  6. /proc/self/ns symlink readability
 *  7. setns() with /proc/self/ns fds
 *  8. nested namespace: CLONE_NEWUSER | CLONE_NEWNET combined
 */
#include "test_harness.h"

/* Test 1: clone with CLONE_NEWUSER */
static int try_clone_newuser(void) {
    g_got_sigsys = 0;

    pid_t pid = (pid_t)syscall(__NR_clone, CLONE_NEWUSER | SIGCHLD, NULL);
    if (g_got_sigsys) return -2;
    if (pid == 0) {
        /* Child in new user namespace */
        _exit(0);
    }
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        return 1; /* Created user namespace! */
    }
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 2: unshare(CLONE_NEWUSER) */
static int try_unshare_user(void) {
    g_got_sigsys = 0;

    /* Do in child to avoid affecting our namespace */
    pid_t pid = fork();
    if (pid == 0) {
        int ret = unshare(CLONE_NEWUSER);
        _exit(ret == 0 ? 99 : 0);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);
    if (g_got_sigsys) return -2;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 99)
        return 1; /* unshare worked! */
    return 0;
}

/* Test 3: clone with CLONE_NEWNET */
static int try_clone_newnet(void) {
    g_got_sigsys = 0;

    pid_t pid = (pid_t)syscall(__NR_clone, CLONE_NEWNET | SIGCHLD, NULL);
    if (g_got_sigsys) return -2;
    if (pid == 0) _exit(0);
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        return 1;
    }
    return 0;
}

/* Test 4: clone with CLONE_NEWNS (mount namespace) */
static int try_clone_newns(void) {
    g_got_sigsys = 0;

    pid_t pid = (pid_t)syscall(__NR_clone, CLONE_NEWNS | SIGCHLD, NULL);
    if (g_got_sigsys) return -2;
    if (pid == 0) _exit(0);
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        return 1;
    }
    return 0;
}

/* Test 5: clone with CLONE_NEWPID */
static int try_clone_newpid(void) {
    g_got_sigsys = 0;

    pid_t pid = (pid_t)syscall(__NR_clone, CLONE_NEWPID | SIGCHLD, NULL);
    if (g_got_sigsys) return -2;
    if (pid == 0) _exit(0);
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        return 1;
    }
    return 0;
}

/* Test 6: /proc/self/ns symlink readability */
static int try_ns_readlinks(void) {
    char buf[256];
    int readable = 0;
    const char *ns_names[] = {
        "user", "net", "mnt", "pid", "ipc", "uts", "cgroup", "time"
    };

    for (int i = 0; i < 8; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/ns/%s", ns_names[i]);
        ssize_t n = readlink(path, buf, sizeof(buf) - 1);
        if (n > 0) readable++;
    }

    return readable;
}

/* Test 7: setns() with /proc/self/ns fds */
static int try_setns(void) {
    g_got_sigsys = 0;
    /* setns is blocked in our sandbox, but verify */
    int fd = open("/proc/self/ns/user", O_RDONLY);
    if (fd < 0) return 0;

    int ret = setns(fd, CLONE_NEWUSER);
    close(fd);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 8: Combined CLONE_NEWUSER | CLONE_NEWNET (full escape pattern) */
static int try_nested_user_net(void) {
    g_got_sigsys = 0;

    pid_t pid = fork();
    if (pid == 0) {
        /* Try the full Qualys pattern: user NS + net NS */
        int ret = unshare(CLONE_NEWUSER | CLONE_NEWNET);
        if (ret != 0) _exit(0);

        /* If we got here, we have fake root in new user+net namespace.
         * This would allow creating netfilter rules, etc. */
        _exit(99);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);
    if (g_got_sigsys) return -2;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 99)
        return 1;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NESTED NAMESPACE BYPASS (QUALYS 2025)");

    int clone_user = try_clone_newuser();
    TEST("clone(CLONE_NEWUSER) blocked",
         clone_user <= 0,
         clone_user == 1  ? "CREATED — user namespace from sandbox!" :
         clone_user == -2 ? "SIGSYS" : "blocked");

    int unshare_user = try_unshare_user();
    TEST("unshare(CLONE_NEWUSER) blocked",
         unshare_user <= 0,
         unshare_user == 1  ? "UNSHARED — user namespace escape!" :
         unshare_user == -2 ? "SIGSYS" : "blocked");

    int clone_net = try_clone_newnet();
    TEST("clone(CLONE_NEWNET) blocked",
         clone_net <= 0,
         clone_net == 1  ? "CREATED — network namespace!" :
         clone_net == -2 ? "SIGSYS" : "blocked");

    int clone_ns = try_clone_newns();
    TEST("clone(CLONE_NEWNS) blocked",
         clone_ns <= 0,
         clone_ns == 1  ? "CREATED — mount namespace!" :
         clone_ns == -2 ? "SIGSYS" : "blocked");

    int clone_pid = try_clone_newpid();
    TEST("clone(CLONE_NEWPID) blocked",
         clone_pid <= 0,
         clone_pid == 1  ? "CREATED — PID namespace!" :
         clone_pid == -2 ? "SIGSYS" : "blocked");

    int ns_links = try_ns_readlinks();
    TEST("/proc/self/ns/* readlinks (info)",
         1,
         "%d namespace links readable", ns_links);

    int setns_test = try_setns();
    TEST("setns() blocked",
         setns_test <= 0,
         setns_test == 1  ? "JOINED — namespace via setns!" :
         setns_test == -2 ? "SIGSYS" : "blocked");

    int nested = try_nested_user_net();
    TEST("CLONE_NEWUSER|CLONE_NEWNET combined blocked",
         nested <= 0,
         nested == 1  ? "ESCAPED — full user+net namespace!" :
         nested == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
