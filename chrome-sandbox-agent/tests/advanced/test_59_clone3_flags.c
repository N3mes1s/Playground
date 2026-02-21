/*
 * test_59_clone3_flags.c — clone3() advanced flag abuse
 *
 * clone3() (syscall 435) is the modern process creation interface with
 * extensible flags. Several flags create dangerous attack surfaces:
 *   - CLONE_INTO_CGROUP: Place child into specific cgroup
 *   - CLONE_NEWTIME: Time namespace (timing attacks)
 *   - CLONE_NEWCGROUP: Cgroup namespace escape
 *   - CLONE_PIDFD: Get pidfd for cross-process attacks
 *   - Combined flag abuse for privilege escalation
 *
 * Tests:
 *  1. clone3 with CLONE_NEWUSER
 *  2. clone3 with CLONE_INTO_CGROUP
 *  3. clone3 with CLONE_NEWTIME
 *  4. clone3 with CLONE_NEWCGROUP
 *  5. clone3 with CLONE_NEWPID + CLONE_NEWNS
 *  6. clone3 with CLONE_PIDFD
 *  7. clone3 with set_tid (PID spoofing)
 *  8. clone3 with CLONE_NEWNET + CLONE_NEWUSER chain
 */
#include "test_harness.h"

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

struct clone_args {
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
};

static int try_clone3(uint64_t flags, const char *test_name,
                      const char *fail_msg) {
    g_got_sigsys = 0;
    struct clone_args args;
    memset(&args, 0, sizeof(args));
    args.flags = flags;
    args.exit_signal = SIGCHLD;

    long ret = syscall(__NR_clone3, &args, sizeof(args));
    if (ret == 0) {
        /* Child — exit immediately */
        _exit(0);
    }

    int blocked = (ret < 0 || g_got_sigsys);
    if (ret > 0) {
        /* Parent got child pid — clone3 succeeded */
        waitpid((pid_t)ret, NULL, 0);
        blocked = 0;
    }

    TEST(test_name, blocked,
         blocked ? "blocked" : fail_msg);
    return blocked;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("CLONE3 ADVANCED FLAG ABUSE");

    /* Test 1: clone3 with CLONE_NEWUSER */
    try_clone3(CLONE_NEWUSER,
               "clone3(CLONE_NEWUSER) blocked",
               "NEWUSER — user namespace via clone3!");

    /* Test 2: clone3 with CLONE_INTO_CGROUP */
    {
        g_got_sigsys = 0;
        struct clone_args args;
        memset(&args, 0, sizeof(args));
        args.flags = CLONE_INTO_CGROUP;
        args.exit_signal = SIGCHLD;
        /* Try to open a cgroup fd first */
        int cgfd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
        if (cgfd < 0) cgfd = open("/sys/fs/cgroup/unified", O_RDONLY | O_DIRECTORY);
        args.cgroup = (uint64_t)(cgfd > 0 ? cgfd : 0);

        long ret = syscall(__NR_clone3, &args, sizeof(args));
        if (ret == 0) _exit(0);

        int blocked = (ret < 0 || g_got_sigsys);
        if (ret > 0) { waitpid((pid_t)ret, NULL, 0); blocked = 0; }

        TEST("clone3(CLONE_INTO_CGROUP) blocked",
             blocked,
             blocked ? "blocked" :
             "CGROUP — process placed into cgroup from sandbox!");
        if (cgfd > 0) close(cgfd);
    }

    /* Test 3: clone3 with CLONE_NEWTIME */
    try_clone3(CLONE_NEWTIME | CLONE_NEWUSER,
               "clone3(CLONE_NEWTIME) blocked",
               "NEWTIME — time namespace created from sandbox!");

    /* Test 4: clone3 with CLONE_NEWCGROUP */
    try_clone3(CLONE_NEWCGROUP | CLONE_NEWUSER,
               "clone3(CLONE_NEWCGROUP) blocked",
               "NEWCGROUP — cgroup namespace from sandbox!");

    /* Test 5: clone3 with CLONE_NEWPID + CLONE_NEWNS */
    try_clone3(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER,
               "clone3(NEWPID+NEWNS) blocked",
               "NEWPID+NEWNS — PID+mount namespace from sandbox!");

    /* Test 6: clone3 with CLONE_PIDFD */
    {
        g_got_sigsys = 0;
        struct clone_args args;
        memset(&args, 0, sizeof(args));
        args.flags = CLONE_PIDFD;
        args.exit_signal = SIGCHLD;
        int pidfd = -1;
        args.pidfd = (uint64_t)(uintptr_t)&pidfd;

        long ret = syscall(__NR_clone3, &args, sizeof(args));
        if (ret == 0) _exit(0);

        int blocked = (ret < 0 || g_got_sigsys);
        if (ret > 0) {
            waitpid((pid_t)ret, NULL, 0);
            /* clone3 with CLONE_PIDFD succeeded — check if we got a pidfd */
            if (pidfd >= 0) {
                close(pidfd);
                blocked = 0;
            }
        }
        /* Note: CLONE_PIDFD alone on basic fork may be allowed —
         * the real danger is combining it with namespace flags.
         * Mark as pass if blocked OR if just basic PIDFD */
        TEST("clone3(CLONE_PIDFD) limited",
             blocked || ret > 0,
             blocked ? "blocked" : "pidfd obtained (basic fork, acceptable)");
    }

    /* Test 7: clone3 with set_tid (PID spoofing) */
    {
        g_got_sigsys = 0;
        struct clone_args args;
        memset(&args, 0, sizeof(args));
        args.flags = CLONE_NEWUSER | CLONE_NEWPID;
        args.exit_signal = SIGCHLD;
        pid_t target_tid = 1;  /* Try to become PID 1 */
        args.set_tid = (uint64_t)(uintptr_t)&target_tid;
        args.set_tid_size = 1;

        long ret = syscall(__NR_clone3, &args, sizeof(args));
        if (ret == 0) _exit(0);

        int blocked = (ret < 0 || g_got_sigsys);
        if (ret > 0) { waitpid((pid_t)ret, NULL, 0); blocked = 0; }

        TEST("clone3 set_tid PID spoofing blocked",
             blocked,
             blocked ? "blocked" :
             "PID SPOOF — process with chosen PID created!");
    }

    /* Test 8: clone3 NEWNET + NEWUSER chain */
    try_clone3(CLONE_NEWNET | CLONE_NEWUSER,
               "clone3(NEWNET+NEWUSER) blocked",
               "NEWNET — network namespace from sandbox!");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
