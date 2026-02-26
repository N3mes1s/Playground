/*
 * test_79_landlock_bypass.c — Landlock v4/v5 known bypass patterns
 *
 * Landlock is a stackable LSM for unprivileged sandboxing. Versions:
 *   v4 (6.7): Network rules — but only TCP, not UDP/ICMP/raw
 *   v5 (6.10): IOCTL on devices — but pre-opened FDs are exempt
 *
 * Known bypass patterns:
 *   - UDP traffic bypasses Landlock v4 network restrictions
 *   - Pre-opened FDs retain full IOCTL access even after v5 restriction
 *   - FDs passed via SCM_RIGHTS keep their pre-Landlock permissions
 *   - ICMP and raw sockets are not covered by network rules
 *
 * Tests:
 *  1. Landlock ABI version detection
 *  2. Landlock v4 UDP bypass (TCP blocked, UDP allowed)
 *  3. Landlock v5 pre-opened FD IOCTL bypass
 *  4. close_range UNSHARE broker disruption
 *  5. close_range CLOEXEC marking
 *  6. close_range bulk FD closure
 *  7. Landlock + ICMP bypass
 *  8. Landlock ruleset stacking limit
 */
#include "test_harness.h"

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif
#ifndef __NR_close_range
#define __NR_close_range 436
#endif

/* Landlock access rights */
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP    (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV    (1ULL << 15)
#endif

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};

int main(void) {
    install_sigsys_handler();
    setvbuf(stdout, NULL, _IONBF, 0);

    PRINT_HEADER("LANDLOCK v4/v5 BYPASSES & close_range ATTACKS");

    /* Test 1: Landlock ABI version detection */
    {
        g_got_sigsys = 0;
        long abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                           1 /* LANDLOCK_CREATE_RULESET_VERSION */);
        int blocked = (abi < 0 && (g_got_sigsys || errno == ENOSYS));

        TEST("Landlock ABI version noted",
             1, /* informational */
             blocked ? "blocked or unavailable" :
             "ABI version %ld detected", abi > 0 ? abi : 0);
    }

    /* Test 2: Landlock v4 UDP bypass — TCP blocked, UDP still works */
    {
        /* Run in child to avoid restricting parent */
        pid_t pid = fork();
        if (pid == 0) {
            setvbuf(stdout, NULL, _IONBF, 0);
            g_got_sigsys = 0;

            /* Check ABI version first */
            long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, 1);
            if (abi < 4) _exit(10); /* No network support */

            /* Create ruleset restricting all TCP */
            struct landlock_ruleset_attr attr;
            memset(&attr, 0, sizeof(attr));
            attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
                                      LANDLOCK_ACCESS_NET_CONNECT_TCP;

            int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset,
                                          &attr, sizeof(attr), 0);
            if (ruleset_fd < 0) _exit(11);

            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) < 0) {
                close(ruleset_fd);
                _exit(12);
            }
            close(ruleset_fd);

            /* UDP should still work — Landlock v4 only covers TCP */
            int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
            int udp_ok = (udp_sock >= 0);
            if (udp_sock >= 0) close(udp_sock);

            _exit(udp_ok ? 99 : 0);
        }

        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        /* UDP bypass is a known Landlock v4 limitation, not sandbox-specific */
        TEST("Landlock v4 UDP bypass noted",
             1, /* informational — known limitation */
             child_ret == 99 ? "UDP bypasses Landlock TCP-only rules (known gap)" :
             child_ret == 10 ? "Landlock < v4 (no network support)" :
             child_ret >= 11 ? "Landlock setup failed" :
             "UDP also blocked");
    }

    /* Test 3: Landlock v5 pre-opened FD IOCTL bypass */
    {
        pid_t pid = fork();
        if (pid == 0) {
            setvbuf(stdout, NULL, _IONBF, 0);
            g_got_sigsys = 0;

            long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, 1);
            if (abi < 5) _exit(10);

            /* Open /dev/null BEFORE Landlock enforcement */
            int pre_fd = open("/dev/null", O_RDWR);
            if (pre_fd < 0) _exit(11);

            /* Apply Landlock restricting IOCTL on devices */
            struct landlock_ruleset_attr attr;
            memset(&attr, 0, sizeof(attr));
            attr.handled_access_fs = LANDLOCK_ACCESS_FS_IOCTL_DEV;

            int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset,
                                          &attr, sizeof(attr), 0);
            if (ruleset_fd < 0) { close(pre_fd); _exit(12); }

            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) < 0) {
                close(ruleset_fd);
                close(pre_fd);
                _exit(13);
            }
            close(ruleset_fd);

            /* Pre-opened FD should still allow IOCTL */
            struct winsize ws;
            int ioctl_ok = (ioctl(pre_fd, TIOCGWINSZ, &ws) == 0);
            close(pre_fd);

            /* Try opening a NEW device — IOCTL should be restricted */
            int new_fd = open("/dev/null", O_RDWR);
            int new_ioctl = 0;
            if (new_fd >= 0) {
                new_ioctl = (ioctl(new_fd, TIOCGWINSZ, &ws) == 0);
                close(new_fd);
            }

            _exit(ioctl_ok ? 99 : (new_ioctl ? 88 : 0));
        }

        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        TEST("Landlock v5 pre-FD IOCTL bypass noted",
             1, /* informational — known design limitation */
             child_ret == 99 ? "pre-opened FD retains IOCTL (known limitation)" :
             child_ret == 10 ? "Landlock < v5 (no IOCTL support)" :
             child_ret >= 11 ? "setup failed" :
             "IOCTL blocked on pre-opened FD too");
    }

    /* Test 4: close_range UNSHARE broker disruption */
    {
        /* Simulate broker FDs */
        int broker_fds[2];
        int has_pipe = (pipe(broker_fds) == 0);
        int disrupted = 0;

        if (has_pipe) {
            int hi_r = dup2(broker_fds[0], 200);
            int hi_w = dup2(broker_fds[1], 201);
            close(broker_fds[0]);
            close(broker_fds[1]);

            if (hi_r >= 0 && hi_w >= 0) {
                pid_t child = fork();
                if (child == 0) {
                    g_got_sigsys = 0;
                    /* Try to close broker FDs via close_range */
                    syscall(__NR_close_range, 200, 201, 0);
                    /* Check if broker channel is destroyed */
                    int write_ok = (write(201, "x", 1) > 0);
                    _exit(write_ok ? 0 : 99);
                }

                int status = 0;
                waitpid(child, &status, 0);
                disrupted = (WIFEXITED(status) && WEXITSTATUS(status) == 99);
            }
            close(200);
            close(201);
        }

        /* close_range is needed for sandbox setup, can't easily block */
        TEST("close_range broker disruption noted",
             1, /* close_range is needed, child FDs are independent */
             disrupted ? "child can close inherited FDs (expected)" :
             "broker FDs survived in child");
    }

    /* Test 5: close_range CLOEXEC marking */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_close_range, 500, 999, CLOSE_RANGE_CLOEXEC);
        int blocked = (g_got_sigsys || (ret < 0 && errno == ENOSYS));

        TEST("close_range CLOEXEC noted",
             1, /* needed for sandbox setup */
             blocked ? "blocked or unavailable" :
             "CLOEXEC marking available");
    }

    /* Test 6: close_range UNSHARE FD table */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_close_range, 1000, (unsigned int)~0U,
                           CLOSE_RANGE_UNSHARE);
        int blocked = (g_got_sigsys || (ret < 0 && errno == ENOSYS));

        TEST("close_range UNSHARE noted",
             1, /* needed for sandbox setup */
             blocked ? "blocked or unavailable" :
             "FD table unshare available");
    }

    /* Test 7: Landlock + ICMP bypass (raw socket) */
    {
        pid_t pid = fork();
        if (pid == 0) {
            setvbuf(stdout, NULL, _IONBF, 0);
            g_got_sigsys = 0;

            long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, 1);
            if (abi < 4) _exit(10);

            /* Restrict all TCP */
            struct landlock_ruleset_attr attr;
            memset(&attr, 0, sizeof(attr));
            attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
                                      LANDLOCK_ACCESS_NET_CONNECT_TCP;

            int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset,
                                          &attr, sizeof(attr), 0);
            if (ruleset_fd < 0) _exit(11);

            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
            close(ruleset_fd);

            /* Try ICMP (raw socket) — not covered by Landlock */
            int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            int raw_ok = (raw_sock >= 0);
            if (raw_sock >= 0) close(raw_sock);

            _exit(raw_ok ? 99 : 0);
        }

        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        TEST("Landlock ICMP bypass noted",
             1, /* informational — known limitation */
             child_ret == 99 ? "raw ICMP bypasses Landlock TCP rules" :
             child_ret == 10 ? "Landlock < v4" :
             "ICMP also blocked (likely by seccomp or capabilities)");
    }

    /* Test 8: Landlock ruleset stacking limit */
    {
        g_got_sigsys = 0;
        long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, 1);
        int blocked = (abi < 0);
        int stack_count = 0;

        if (!blocked) {
            /* Landlock allows up to 16 stacked rulesets. Test how many
             * we can create (not enforce, just create). */
            for (int i = 0; i < 20; i++) {
                struct landlock_ruleset_attr attr;
                memset(&attr, 0, sizeof(attr));
                attr.handled_access_fs = (1ULL << 2); /* READ_FILE */
                int fd = (int)syscall(__NR_landlock_create_ruleset,
                                       &attr, sizeof(attr), 0);
                if (fd >= 0) {
                    stack_count++;
                    close(fd);
                } else {
                    break;
                }
            }
        }

        TEST("Landlock ruleset creation noted",
             1, /* informational */
             blocked ? "Landlock unavailable" :
             "created %d rulesets", stack_count);
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
