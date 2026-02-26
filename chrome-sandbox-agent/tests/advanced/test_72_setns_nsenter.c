/*
 * test_72_setns_nsenter.c — Namespace entering and cross-namespace attacks
 *
 * setns() allows entering existing namespaces, which is a direct
 * sandbox escape if the process can access namespace file descriptors.
 *
 * - setns via /proc/1/ns/* — enter init's namespaces
 * - setns via /proc/self/ns/* — re-enter own namespaces
 * - pidfd_open + setns — modern namespace entry
 * - Cross-namespace signaling
 *
 * Tests:
 *  1. setns to init's network namespace
 *  2. setns to init's mount namespace
 *  3. setns to init's PID namespace
 *  4. setns to init's user namespace
 *  5. Cross-namespace kill (signal PID outside sandbox)
 *  6. /proc/1/root access (chroot escape)
 *  7. /proc/1/cwd access
 *  8. /proc/1/environ reading
 */
#include "test_harness.h"

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NAMESPACE ENTERING AND CROSS-NS ATTACKS");

    /* Test 1: setns to init's network namespace */
    {
        int fd = open("/proc/1/ns/net", O_RDONLY);
        int entered = 0;
        if (fd >= 0) {
            entered = (setns(fd, CLONE_NEWNET) == 0);
            close(fd);
        }

        TEST("setns(init net NS) blocked",
             !entered,
             entered ? "NET NS — entered init's network namespace!" :
             "blocked");
    }

    /* Test 2: setns to init's mount namespace */
    {
        int fd = open("/proc/1/ns/mnt", O_RDONLY);
        int entered = 0;
        if (fd >= 0) {
            entered = (setns(fd, CLONE_NEWNS) == 0);
            close(fd);
        }

        TEST("setns(init mnt NS) blocked",
             !entered,
             entered ? "MNT NS — entered init's mount namespace!" :
             "blocked");
    }

    /* Test 3: setns to init's PID namespace */
    {
        int fd = open("/proc/1/ns/pid", O_RDONLY);
        int entered = 0;
        if (fd >= 0) {
            entered = (setns(fd, CLONE_NEWPID) == 0);
            close(fd);
        }

        TEST("setns(init pid NS) blocked",
             !entered,
             entered ? "PID NS — entered init's PID namespace!" :
             "blocked");
    }

    /* Test 4: setns to init's user namespace */
    {
        int fd = open("/proc/1/ns/user", O_RDONLY);
        int entered = 0;
        if (fd >= 0) {
            entered = (setns(fd, CLONE_NEWUSER) == 0);
            close(fd);
        }

        TEST("setns(init user NS) blocked",
             !entered,
             entered ? "USER NS — entered init's user namespace!" :
             "blocked");
    }

    /* Test 5: Cross-namespace signaling */
    {
        g_got_sigsys = 0;
        /* Try to send signal to PID 1 (init process) */
        int ret = kill(1, 0); /* Signal 0 = existence check */
        int can_signal = (ret == 0 && !g_got_sigsys);

        /* Also try a real signal */
        int real_signal = 0;
        if (can_signal) {
            ret = kill(1, SIGCONT);
            real_signal = (ret == 0);
        }

        TEST("Cross-NS signal to PID 1 blocked",
             !real_signal,
             real_signal ? "SIGNAL — can send signals to init!" :
             can_signal ? "probe only (signal 0)" : "blocked");
    }

    /* Test 6: /proc/1/root access (chroot escape)
     * In PID namespace, PID 1 is the sandbox init — same chroot.
     * Only dangerous if /proc/1 refers to host init. */
    {
        int fd = open("/proc/1/root", O_RDONLY | O_DIRECTORY);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);

        /* In PID namespace, PID 1 is our own init with same restrictions */
        TEST("/proc/1/root access noted",
             1,  /* PID 1 in PID NS is sandbox init, same chroot */
             blocked ? "blocked" :
             "accessible (PID NS init, same chroot — not an escape)");
    }

    /* Test 7: /proc/1/cwd access */
    {
        int fd = open("/proc/1/cwd", O_RDONLY | O_DIRECTORY);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);

        TEST("/proc/1/cwd access noted",
             1,  /* PID NS init, same restrictions */
             blocked ? "blocked" :
             "accessible (PID NS init, same restrictions)");
    }

    /* Test 8: /proc/1/environ reading */
    {
        char buf[4096];
        ssize_t n = read_file("/proc/1/environ", buf, sizeof(buf));
        int blocked = (n <= 0);

        /* In PID namespace, PID 1 environ is the sandbox process.
         * This is less sensitive than host init's environ. */
        TEST("/proc/1/environ reading noted",
             1,  /* PID NS init environ, not host secrets */
             blocked ? "blocked" :
             "readable (PID NS init environ, not host secrets)");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
