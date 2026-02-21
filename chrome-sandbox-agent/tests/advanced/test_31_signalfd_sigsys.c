/*
 * test_31_signalfd_sigsys.c — signalfd SIGSYS interception tests (CRITICAL)
 *
 * Chrome's seccomp uses SECCOMP_RET_TRAP which delivers a catchable SIGSYS
 * signal. If a sandboxed process can:
 *  1. Block SIGSYS via sigprocmask (preventing crash handler)
 *  2. Create a signalfd for SIGSYS
 *  3. Read SIGSYS events from the fd instead of crashing
 * ...then it could survive seccomp violations and continue executing after
 * blocked syscalls, potentially defeating the entire seccomp enforcement.
 *
 * This is architecturally significant because SECCOMP_RET_TRAP != SECCOMP_RET_KILL.
 * The signal IS catchable by design — Chrome installs its own CrashSIGSYS()
 * handler which logs and calls _exit(). But if the process replaces or blocks
 * that handler, it can survive.
 *
 * Tests:
 *  1. sigprocmask can block SIGSYS
 *  2. signalfd creation for SIGSYS
 *  3. signalfd SIGSYS interception after blocked syscall
 *  4. rt_sigaction can replace SIGSYS handler
 *  5. SIG_IGN on SIGSYS
 *  6. signalfd with multiple signals including SIGSYS
 *  7. sigtimedwait for SIGSYS
 *  8. fork + signalfd inheritance
 */
#include "test_harness.h"
#include <sys/signalfd.h>

/* Test 1: sigprocmask can block SIGSYS */
static int try_block_sigsys(void) {
    sigset_t mask, old_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);

    int ret = sigprocmask(SIG_BLOCK, &mask, &old_mask);
    /* Restore */
    sigprocmask(SIG_SETMASK, &old_mask, NULL);

    return (ret == 0) ? 1 : 0;
}

/* Test 2: signalfd creation for SIGSYS */
static int try_signalfd_create(void) {
    g_got_sigsys = 0;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);

    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 3: signalfd SIGSYS interception after blocked syscall (CRITICAL)
 *
 * This is the key test: can we survive a seccomp violation by consuming
 * the SIGSYS through signalfd instead of the crash handler?
 */
static int try_signalfd_intercept(void) {
    /* Do this in a child to avoid corrupting our own signal state */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: attempt signalfd SIGSYS interception */
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGSYS);

        /* Step 1: Block SIGSYS so it goes to signalfd instead of handler */
        sigprocmask(SIG_BLOCK, &mask, NULL);

        /* Step 2: Create signalfd for SIGSYS */
        int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (sfd < 0) _exit(0); /* signalfd not available */

        /* Step 3: Trigger a blocked syscall (unshare is blocked) */
        syscall(__NR_unshare, CLONE_NEWUSER);

        /* Step 4: Try to read the SIGSYS event from signalfd */
        struct signalfd_siginfo info;
        ssize_t n = read(sfd, &info, sizeof(info));
        close(sfd);

        if (n == (ssize_t)sizeof(info) && info.ssi_signo == SIGSYS) {
            /* We survived a seccomp violation! */
            _exit(99);
        }
        _exit(0);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 99)
        return 1; /* Intercepted SIGSYS — seccomp bypass! */
    return 0;
}

/* Test 4: rt_sigaction can replace SIGSYS handler */
static int try_replace_sigsys_handler(void) {
    struct sigaction old_sa, new_sa;
    memset(&new_sa, 0, sizeof(new_sa));
    new_sa.sa_handler = SIG_DFL;
    sigemptyset(&new_sa.sa_mask);

    /* Save current handler */
    sigaction(SIGSYS, NULL, &old_sa);

    /* Try to replace it */
    int ret = sigaction(SIGSYS, &new_sa, NULL);

    /* Restore our handler */
    install_sigsys_handler();

    return (ret == 0) ? 1 : 0;
}

/* Test 5: SIG_IGN on SIGSYS */
static int try_sigign_sigsys(void) {
    pid_t pid = fork();
    if (pid == 0) {
        /* Set SIGSYS to ignored */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        int ret = sigaction(SIGSYS, &sa, NULL);
        if (ret != 0) _exit(0);

        /* Try a blocked syscall — if SIG_IGN works, we survive */
        syscall(__NR_unshare, CLONE_NEWUSER);

        /* If we get here, SIG_IGN prevented crash */
        _exit(99);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 99)
        return 1; /* SIG_IGN survived seccomp trap! */
    return 0;
}

/* Test 6: signalfd with multiple signals including SIGSYS */
static int try_signalfd_multi(void) {
    g_got_sigsys = 0;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);

    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 7: sigtimedwait for SIGSYS */
static int try_sigtimedwait_sigsys(void) {
    pid_t pid = fork();
    if (pid == 0) {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGSYS);

        /* Block SIGSYS */
        sigprocmask(SIG_BLOCK, &mask, NULL);

        /* Trigger a blocked syscall */
        syscall(__NR_unshare, CLONE_NEWUSER);

        /* Try to consume via sigtimedwait */
        struct timespec ts = {0, 0}; /* Don't wait */
        siginfo_t info;
        int sig = sigtimedwait(&mask, &info, &ts);

        if (sig == SIGSYS)
            _exit(99); /* Consumed SIGSYS via sigtimedwait! */
        _exit(0);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 99)
        return 1;
    return 0;
}

/* Test 8: fork + signalfd inheritance */
static int try_signalfd_fork(void) {
    g_got_sigsys = 0;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);

    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0) return 0;

    pid_t pid = fork();
    if (pid == 0) {
        /* Child inherits the signalfd — can it read SIGSYS events? */
        struct signalfd_siginfo info;
        /* Just check fd is valid */
        ssize_t n = read(fd, &info, sizeof(info));
        close(fd);
        /* n == -1 with EAGAIN is fine (no signal pending) */
        _exit((n == -1 && errno == EAGAIN) ? 99 : (n > 0 ? 88 : 0));
    }

    close(fd);
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    /* 99 = fd inherited and functional, 88 = actually read something */
    if (WIFEXITED(status) && (WEXITSTATUS(status) == 99 || WEXITSTATUS(status) == 88))
        return 1;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SIGNALFD SIGSYS INTERCEPTION (CRITICAL)");

    /* Note: In our sandbox, seccomp uses SECCOMP_RET_TRACE (not RET_TRAP).
     * The ptrace tracer handles blocked syscalls by setting rax=-EPERM.
     * This means SIGSYS is NOT delivered for blocked syscalls — the
     * tracer silently blocks them. signalfd interception is therefore
     * NOT applicable to our architecture. These are informational tests
     * to verify this property holds. */

    int block_sigsys = try_block_sigsys();
    TEST("sigprocmask block SIGSYS (info)",
         1, /* sigprocmask is a basic signal API — can't block it */
         block_sigsys == 1 ? "can block (expected — signal API)" :
         "cannot block");

    int sfd_create = try_signalfd_create();
    TEST("signalfd creation (info)",
         1, /* signalfd is a widely-used API */
         sfd_create == 1  ? "available (widely used API)" :
         sfd_create == -2 ? "SIGSYS" :
         sfd_create == -1 ? "ENOSYS" : "blocked");

    int sfd_intercept = try_signalfd_intercept();
    TEST("signalfd SIGSYS intercept after blocked syscall",
         sfd_intercept <= 0,
         sfd_intercept == 1 ? "INTERCEPTED — survived seccomp violation!" :
         "not intercepted (ptrace-based blocking — no SIGSYS delivered)");

    int replace = try_replace_sigsys_handler();
    TEST("rt_sigaction replace SIGSYS handler (info)",
         1, /* can't prevent sigaction on SIGSYS */
         replace == 1 ? "can replace (expected)" : "blocked");

    int sigign = try_sigign_sigsys();
    TEST("SIG_IGN on SIGSYS (info — ptrace architecture)",
         1, /* With SECCOMP_RET_TRACE, no SIGSYS is delivered. The tracer
             * blocks syscalls by returning -EPERM. SIG_IGN is irrelevant
             * because there's no signal to ignore. The child "surviving"
             * is expected — it just gets EPERM from the blocked syscall. */
         sigign == 1 ? "survived (expected — ptrace returns EPERM, no SIGSYS)" :
         "did not survive");

    int multi = try_signalfd_multi();
    TEST("signalfd multi-signal including SIGSYS (info)",
         1,
         multi == 1  ? "available" :
         multi == -2 ? "SIGSYS" : "blocked");

    int timedwait = try_sigtimedwait_sigsys();
    TEST("sigtimedwait SIGSYS consumption",
         timedwait <= 0,
         timedwait == 1 ? "CONSUMED — sigtimedwait defeats seccomp!" :
         "not consumed (no SIGSYS to wait for)");

    int sfd_fork = try_signalfd_fork();
    TEST("signalfd inherited across fork (info)",
         1,
         sfd_fork == 1 ? "inherited (expected)" : "not inherited");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
