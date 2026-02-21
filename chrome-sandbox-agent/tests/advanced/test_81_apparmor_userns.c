/*
 * test_81_apparmor_userns.c — AppArmor user namespace restriction bypasses
 *
 * Based on: Qualys TRU (January-March 2025), DEVCORE (February 2025).
 *
 * Ubuntu 24.04+ restricts unprivileged user namespace creation via AppArmor.
 * Three bypasses were discovered:
 *   1. aa-exec -p trinity/chrome/flatpak: transition to permissive profile
 *   2. busybox: default AppArmor profile allows unrestricted namespaces
 *   3. LD_PRELOAD into a process with permissive AppArmor profile
 *
 * Also tests general namespace creation restrictions and profile transitions.
 *
 * Tests:
 *  1. Direct unshare(CLONE_NEWUSER) availability
 *  2. clone3 + CLONE_NEWUSER
 *  3. /proc/self/attr/apparmor/current profile reading
 *  4. AppArmor profile transition attempt
 *  5. busybox availability (bypass vector)
 *  6. aa-exec availability (bypass vector)
 *  7. Nested user namespace creation
 *  8. User namespace + mount namespace chaining
 */
#include "test_harness.h"

int main(void) {
    install_sigsys_handler();
    setvbuf(stdout, NULL, _IONBF, 0);

    PRINT_HEADER("APPARMOR USER NAMESPACE RESTRICTION BYPASSES");

    /* Test 1: Direct unshare(CLONE_NEWUSER) */
    {
        pid_t pid = fork();
        if (pid == 0) {
            int ret = unshare(CLONE_NEWUSER);
            _exit(ret == 0 ? 99 : 0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int succeeded = (WIFEXITED(status) && WEXITSTATUS(status) == 99);

        TEST("unshare(CLONE_NEWUSER) blocked",
             !succeeded,
             succeeded ? "USERNS — user namespace created!" :
             "blocked");
    }

    /* Test 2: clone3 + CLONE_NEWUSER */
    {
        g_got_sigsys = 0;
        struct {
            uint64_t flags;
            uint64_t pidfd;
            uint64_t child_tid;
            uint64_t parent_tid;
            uint64_t exit_signal;
            uint64_t stack;
            uint64_t stack_size;
            uint64_t tls;
            uint64_t set_tid;
            uint64_t set_tid_size;
            uint64_t cgroup;
        } args;
        memset(&args, 0, sizeof(args));
        args.flags = CLONE_NEWUSER;
        args.exit_signal = SIGCHLD;

        long ret = syscall(SYS_clone3, &args, sizeof(args));
        int blocked = (ret < 0);
        if (ret == 0) _exit(0); /* child */
        if (ret > 0) {
            waitpid(ret, NULL, 0);
            blocked = 0;
        }

        TEST("clone3(CLONE_NEWUSER) blocked",
             blocked || g_got_sigsys,
             blocked ? "blocked" :
             "USERNS — created via clone3!");
    }

    /* Test 3: Read AppArmor profile */
    {
        char buf[1024];
        ssize_t n = read_file("/proc/self/attr/apparmor/current", buf, sizeof(buf));
        if (n <= 0)
            n = read_file("/proc/self/attr/current", buf, sizeof(buf));

        int readable = (n > 0);

        /* Reading own AppArmor profile is informational */
        if (readable)
            test_checkf("AppArmor profile readable", 1,
                        "profile: %.*s", (int)(n > 60 ? 60 : n), buf);
        else
            test_check("AppArmor profile readable", 1,
                       "not readable (AppArmor may not be active)");
    }

    /* Test 4: AppArmor profile transition attempt */
    {
        /* Try to write to /proc/self/attr/apparmor/current to change profile */
        int fd = open("/proc/self/attr/apparmor/current", O_WRONLY);
        int wrote = 0;
        if (fd >= 0) {
            const char *target = "changeprofile unconfined";
            ssize_t w = write(fd, target, strlen(target));
            wrote = (w > 0);
            close(fd);
        }

        TEST("AppArmor profile transition blocked",
             !wrote,
             wrote ? "TRANSITION — changed to unconfined!" :
             "blocked (expected)");
    }

    /* Test 5: busybox availability (bypass vector for AppArmor NS restriction) */
    {
        /* Check if busybox exists — it's a known bypass vector because
         * its default AppArmor profile allows unrestricted namespace creation */
        int exists = (access("/bin/busybox", X_OK) == 0 ||
                      access("/usr/bin/busybox", X_OK) == 0);

        /* Just note availability — actual bypass would require execve */
        TEST("busybox availability noted",
             1, /* informational */
             exists ? "present (potential AppArmor NS bypass vector)" :
             "not found");
    }

    /* Test 6: aa-exec availability (bypass vector) */
    {
        int exists = (access("/usr/bin/aa-exec", X_OK) == 0 ||
                      access("/usr/sbin/aa-exec", X_OK) == 0);

        TEST("aa-exec availability noted",
             1, /* informational */
             exists ? "present (profile transition bypass vector)" :
             "not found");
    }

    /* Test 7: Nested user namespace creation */
    {
        pid_t pid = fork();
        if (pid == 0) {
            /* Try to create a user namespace, then another inside it */
            if (unshare(CLONE_NEWUSER) != 0) _exit(0);

            pid_t inner = fork();
            if (inner == 0) {
                int ret = unshare(CLONE_NEWUSER);
                _exit(ret == 0 ? 99 : 0);
            }
            int st = 0;
            waitpid(inner, &st, 0);
            _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 0);
        }

        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int nested = (WIFEXITED(status) && WEXITSTATUS(status) == 99);

        TEST("Nested user namespace blocked",
             !nested,
             nested ? "NESTED — double user namespace created!" :
             "blocked");
    }

    /* Test 8: User namespace + mount namespace chaining */
    {
        pid_t pid = fork();
        if (pid == 0) {
            /* Try userns first, then mount ns for chroot escape */
            if (unshare(CLONE_NEWUSER) != 0) _exit(0);

            /* Write uid/gid mapping */
            char map[64];
            snprintf(map, sizeof(map), "0 %d 1\n", getuid());
            int fd = open("/proc/self/uid_map", O_WRONLY);
            if (fd >= 0) { (void)write(fd, map, strlen(map)); close(fd); }

            fd = open("/proc/self/setgroups", O_WRONLY);
            if (fd >= 0) { (void)write(fd, "deny", 4); close(fd); }

            snprintf(map, sizeof(map), "0 %d 1\n", getgid());
            fd = open("/proc/self/gid_map", O_WRONLY);
            if (fd >= 0) { (void)write(fd, map, strlen(map)); close(fd); }

            /* Now try to get a mount namespace */
            int ret = unshare(CLONE_NEWNS);
            _exit(ret == 0 ? 99 : 0);
        }

        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int chained = (WIFEXITED(status) && WEXITSTATUS(status) == 99);

        TEST("User NS + Mount NS chain blocked",
             !chained,
             chained ? "CHAIN — userns+mntns created!" :
             "blocked");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
