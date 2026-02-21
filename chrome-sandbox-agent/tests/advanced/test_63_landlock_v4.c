/*
 * test_63_landlock_v4.c — Landlock v4/v5 and self-restriction bypass
 *
 * Landlock is a self-restricting security mechanism. While test_20 covers
 * basic Landlock, this tests newer Landlock v4/v5 features and bypass
 * techniques:
 *
 * - Landlock ABI v4 (Linux 6.7): LANDLOCK_ACCESS_NET_* for network
 * - Landlock ABI v5 (Linux 6.10): LANDLOCK_SCOPE_*
 * - Attempting to use Landlock to WEAKEN restrictions
 * - Landlock + user namespace interaction
 * - Landlock TCP/UDP bind/connect control
 *
 * Tests:
 *  1. landlock_create_ruleset (ABI v4 network)
 *  2. landlock_add_rule LANDLOCK_RULE_NET_PORT
 *  3. landlock_restrict_self with broader rules
 *  4. Landlock ABI v5 scope control
 *  5. Landlock + fork to escape restriction stacking
 *  6. Landlock self-restrict then bind privileged port
 *  7. /proc/self/attr/landlock/* reads
 *  8. Landlock + user NS combined attack
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

/* Landlock access flags */
#define LANDLOCK_ACCESS_FS_EXECUTE        (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE     (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE      (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR       (1ULL << 3)

/* Landlock v4 network access */
#define LANDLOCK_ACCESS_NET_BIND_TCP      (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP   (1ULL << 1)

/* Landlock v5 scope */
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL               (1ULL << 1)

/* Rule types */
#define LANDLOCK_RULE_PATH_BENEATH  1
#define LANDLOCK_RULE_NET_PORT      2

struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

struct landlock_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};

struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t  parent_fd;
};

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("LANDLOCK V4/V5 AND BYPASS TECHNIQUES");

    /* Test 1: landlock_create_ruleset with network (ABI v4) */
    {
        g_got_sigsys = 0;
        struct landlock_ruleset_attr attr = {
            .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                                 LANDLOCK_ACCESS_FS_WRITE_FILE,
            .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
                                  LANDLOCK_ACCESS_NET_CONNECT_TCP,
            .scoped = 0,
        };
        long fd = syscall(__NR_landlock_create_ruleset,
                          &attr, sizeof(attr), 0);
        int blocked = (fd < 0 || g_got_sigsys);
        if (fd >= 0) close((int)fd);

        TEST("landlock_create_ruleset(NET) limited",
             blocked,
             blocked ? "blocked" :
             "LANDLOCK — ruleset with network created from sandbox!");
    }

    /* Test 2: landlock_add_rule for NET_PORT */
    {
        g_got_sigsys = 0;
        /* First try to create a ruleset */
        struct landlock_ruleset_attr attr = {
            .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP,
        };
        long rfd = syscall(__NR_landlock_create_ruleset,
                           &attr, sizeof(attr), 0);

        struct landlock_net_port_attr port_attr = {
            .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP,
            .port = 80,
        };
        long ret = -1;
        if (rfd >= 0) {
            ret = syscall(__NR_landlock_add_rule, (int)rfd,
                          LANDLOCK_RULE_NET_PORT, &port_attr, 0);
            close((int)rfd);
        }

        int blocked = (rfd < 0 || ret < 0 || g_got_sigsys);
        TEST("landlock_add_rule(NET_PORT) limited",
             blocked,
             blocked ? "blocked" :
             "NET PORT — Landlock net port rule added!");
    }

    /* Test 3: landlock_restrict_self with broad access */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            struct landlock_ruleset_attr attr = {
                .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
            };
            long rfd = syscall(__NR_landlock_create_ruleset,
                               &attr, sizeof(attr), 0);
            if (rfd < 0) _exit(0);

            /* Add rule allowing execute on / (very broad) */
            struct landlock_path_beneath_attr path_attr = {
                .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE,
                .parent_fd = open("/", O_PATH),
            };
            if (path_attr.parent_fd >= 0) {
                syscall(__NR_landlock_add_rule, (int)rfd,
                        LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
                close(path_attr.parent_fd);
            }

            long ret = syscall(__NR_landlock_restrict_self, (int)rfd, 0);
            close((int)rfd);
            _exit(ret == 0 ? 99 : 0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        TEST("landlock_restrict_self limited",
             child_ret != 99 || g_got_sigsys,
             child_ret == 99 ? "RESTRICTED — self-restriction applied!"
             : "blocked");
    }

    /* Test 4: Landlock ABI v5 scope control */
    {
        g_got_sigsys = 0;
        struct landlock_ruleset_attr attr = {
            .scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
                      LANDLOCK_SCOPE_SIGNAL,
        };
        long fd = syscall(__NR_landlock_create_ruleset,
                          &attr, sizeof(attr), 0);
        int blocked = (fd < 0 || g_got_sigsys);
        if (fd >= 0) close((int)fd);

        TEST("Landlock v5 SCOPE control limited",
             blocked,
             blocked ? "blocked" :
             "SCOPE — Landlock scoped ruleset created!");
    }

    /* Test 5: Landlock ABI version query */
    {
        g_got_sigsys = 0;
        /* flags=LANDLOCK_CREATE_RULESET_VERSION (1) */
        long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, 1);
        int blocked = (abi < 0 || g_got_sigsys);
        TEST("Landlock ABI version query limited",
             blocked,
             blocked ? "blocked" :
             abi >= 4 ? "ABI v4+ — network Landlock available!" :
             "older ABI version");
    }

    /* Test 6: Landlock + bind privileged port */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            /* Try to create landlock allowing port 80 bind */
            struct landlock_ruleset_attr attr = {
                .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP,
            };
            long rfd = syscall(__NR_landlock_create_ruleset,
                               &attr, sizeof(attr), 0);
            if (rfd >= 0) {
                struct landlock_net_port_attr pa = {
                    .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP,
                    .port = 80,
                };
                syscall(__NR_landlock_add_rule, (int)rfd,
                        LANDLOCK_RULE_NET_PORT, &pa, 0);
                syscall(__NR_landlock_restrict_self, (int)rfd, 0);
                close((int)rfd);

                /* Now try to bind port 80 */
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock >= 0) {
                    struct sockaddr_in addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(80),
                        .sin_addr.s_addr = INADDR_ANY,
                    };
                    int ret = bind(sock, (struct sockaddr *)&addr,
                                   sizeof(addr));
                    close(sock);
                    _exit(ret == 0 ? 99 : 0);
                }
            }
            _exit(0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        TEST("Landlock + bind port 80 blocked",
             child_ret != 99,
             child_ret == 99 ? "BIND — privileged port via Landlock!"
             : "blocked");
    }

    /* Test 7: /proc/self/attr/landlock reads */
    {
        char buf[4096];
        ssize_t n = read_file("/proc/self/attr/apparmor/current",
                              buf, sizeof(buf));
        int has_lsm_info = (n > 0);

        ssize_t n2 = read_file("/proc/self/attr/current", buf, sizeof(buf));
        if (n2 > 0) has_lsm_info = 1;

        TEST("/proc/self/attr/ LSM info limited",
             !has_lsm_info,
             has_lsm_info ? "LSM INFO — security attributes readable!"
             : "blocked");
    }

    /* Test 8: Landlock + user namespace */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            /* Enter user NS first, then try Landlock */
            if (unshare(CLONE_NEWUSER) == 0) {
                struct landlock_ruleset_attr attr = {
                    .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
                };
                long rfd = syscall(__NR_landlock_create_ruleset,
                                   &attr, sizeof(attr), 0);
                if (rfd >= 0) {
                    close((int)rfd);
                    _exit(99);
                }
            }
            _exit(0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        TEST("Landlock in user NS blocked",
             child_ret != 99,
             child_ret == 99 ? "USERNS LANDLOCK — Landlock from user NS!"
             : "blocked");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
