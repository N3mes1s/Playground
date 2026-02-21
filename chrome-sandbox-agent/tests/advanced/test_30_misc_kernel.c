/*
 * test_30_misc_kernel.c — Miscellaneous kernel attack surface probes
 *
 * Collection of smaller but important attack surfaces:
 *
 * - signalfd: Creates file descriptor for signal delivery. Can interfere
 *   with sandbox signal handling (SIGSYS handler for seccomp).
 * - pidfd_open: Creates file descriptor for a process. Could be used
 *   to manipulate processes across PID namespaces.
 * - rseq: Restartable sequences allow user-space code to define critical
 *   sections the kernel restarts on preemption. Bugs here enable races.
 * - sched_setattr: Deadline scheduler manipulation for timing attacks.
 * - copy_file_range: Kernel-side file copy that bypasses read/write.
 * - execveat: Execute program via fd (bypass path restrictions).
 * - seccomp SECCOMP_RET_USER_NOTIF: Delegate filtering to userspace.
 * - personality(): Change execution domain (disable ASLR, etc.)
 *
 * Tests:
 *  1. signalfd() availability
 *  2. pidfd_open() availability
 *  3. rseq() registration
 *  4. sched_setattr() manipulation
 *  5. copy_file_range() availability
 *  6. execveat() with AT_EMPTY_PATH
 *  7. seccomp(SECCOMP_SET_MODE_FILTER) — add new filter
 *  8. personality() — change execution domain
 */
#include "test_harness.h"
#include <sys/signalfd.h>
#include <sys/personality.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_rseq
#define __NR_rseq 334
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif
#ifndef __NR_execveat
#define __NR_execveat 322
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

/* Test 1: signalfd — create fd for signal delivery */
static int try_signalfd(void) {
    g_got_sigsys = 0;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);

    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 2: pidfd_open — create fd for process */
static int try_pidfd_open(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_pidfd_open, getpid(), 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 3: rseq registration */
static int try_rseq(void) {
    g_got_sigsys = 0;
    /* rseq struct must be properly aligned */
    struct {
        uint32_t cpu_id_start;
        uint32_t cpu_id;
        uint64_t rseq_cs;
        uint32_t flags;
        uint32_t node_id;
        uint32_t mm_cid;
        char padding[128]; /* Ensure enough space */
    } __attribute__((aligned(32))) rseq_area;

    memset(&rseq_area, 0, sizeof(rseq_area));

    /* Try to register — glibc may have already registered */
    long ret = syscall(__NR_rseq, &rseq_area, sizeof(rseq_area), 0, 0x53053053);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        /* Unregister */
        syscall(__NR_rseq, &rseq_area, sizeof(rseq_area), 1 /* RSEQ_FLAG_UNREGISTER */, 0x53053053);
        return 1;
    }
    if (errno == EBUSY) return 1; /* Already registered by glibc */
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 4: sched_setattr — deadline scheduler manipulation */
static int try_sched_setattr(void) {
    g_got_sigsys = 0;
    /* sched_getattr first */
    struct {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
    } attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);

    long ret = syscall(315 /* __NR_sched_getattr */, 0, &attr, sizeof(attr), 0);
    if (g_got_sigsys) return -2;
    if (ret < 0 && errno == ENOSYS) return -1;
    if (ret < 0) return 0;

    /* Try to set SCHED_DEADLINE (requires CAP_SYS_NICE) */
    attr.sched_policy = 6; /* SCHED_DEADLINE */
    attr.sched_runtime = 10000000;  /* 10ms */
    attr.sched_deadline = 30000000; /* 30ms */
    attr.sched_period = 30000000;   /* 30ms */

    ret = syscall(314 /* __NR_sched_setattr */, 0, &attr, 0);
    if (ret == 0) return 2; /* SCHED_DEADLINE set! */
    return 1; /* sched_getattr worked at least */
}

/* Test 5: copy_file_range — kernel-side file copy */
static int try_copy_file_range(void) {
    g_got_sigsys = 0;
    int in_fd = open("/proc/self/status", O_RDONLY);
    if (in_fd < 0) return 0;

    /* Need a writable destination */
    char tmpfile[] = "/tmp/cfr_XXXXXX";
    int out_fd = mkstemp(tmpfile);
    if (out_fd < 0) { close(in_fd); return 0; }

    loff_t off_in = 0, off_out = 0;
    ssize_t ret = syscall(__NR_copy_file_range, in_fd, &off_in,
                          out_fd, &off_out, 4096, 0);

    close(in_fd);
    close(out_fd);
    unlink(tmpfile);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1;
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 6: execveat with AT_EMPTY_PATH (execute by fd, no path) */
static int try_execveat_empty(void) {
    g_got_sigsys = 0;
    /* Open /bin/true or similar */
    int fd = open("/bin/true", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fd = open("/usr/bin/true", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { "true", NULL };
        char *envp[] = { NULL };
        syscall(__NR_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
        _exit(errno == EACCES ? 43 : errno == ENOENT ? 44 : 45);
    }
    close(fd);
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (g_got_sigsys) return -2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 1; /* Executed! */
    if (WIFEXITED(status) && WEXITSTATUS(status) == 43) return 0; /* EACCES */
    return 0;
}

/* Test 7: seccomp(SECCOMP_SET_MODE_FILTER) — try to add own filter */
static int try_seccomp_add_filter(void) {
    g_got_sigsys = 0;
    /* Minimal BPF program: allow all */
    struct sock_filter filter[] = {
        { 0x06, 0, 0, 0x7fff0000 }, /* SECCOMP_RET_ALLOW */
    };
    struct sock_fprog prog = {
        .len = 1,
        .filter = filter,
    };

    long ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Added a filter! */
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 8: personality() — change execution domain */
static int try_personality(void) {
    g_got_sigsys = 0;
    /* Get current personality */
    unsigned long current = personality(0xFFFFFFFF);
    if (g_got_sigsys) return -2;
    if (current == (unsigned long)-1) return 0;

    /* Try to disable ASLR via ADDR_NO_RANDOMIZE */
    unsigned long new_pers = current | 0x0040000 /* ADDR_NO_RANDOMIZE */;
    long ret = personality(new_pers);

    /* Restore */
    personality(current);

    if (g_got_sigsys) return -2;
    if (ret >= 0 && (unsigned long)ret == new_pers) return 1; /* ASLR disabled! */
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MISCELLANEOUS KERNEL ATTACK SURFACES");

    int sigfd = try_signalfd();
    TEST("signalfd() (info)",
         1, /* signalfd is useful for async signal handling */
         sigfd == 1  ? "available (expected)" :
         sigfd == -2 ? "SIGSYS" : "blocked");

    int pidfd = try_pidfd_open();
    TEST("pidfd_open() blocked",
         pidfd <= 0,
         pidfd == 1  ? "CREATED — process fd manipulation!" :
         pidfd == -2 ? "SIGSYS" :
         pidfd == -1 ? "ENOSYS" : "blocked");

    /* rseq is expected — glibc needs it */
    int rseq = try_rseq();
    TEST("rseq() (info)",
         1,
         rseq == 1  ? "available (expected — glibc)" :
         rseq == -2 ? "SIGSYS" :
         rseq == -1 ? "ENOSYS" : "blocked");

    int sched = try_sched_setattr();
    TEST("sched_setattr DEADLINE blocked",
         sched <= 1,
         sched == 2  ? "SCHED_DEADLINE set — timing attack!" :
         sched == 1  ? "sched_getattr works (expected)" :
         sched == -2 ? "SIGSYS" :
         sched == -1 ? "ENOSYS" : "blocked");

    int cfr = try_copy_file_range();
    TEST("copy_file_range (info)",
         1,
         cfr == 1  ? "available" :
         cfr == -2 ? "SIGSYS" :
         cfr == -1 ? "ENOSYS" : "blocked");

    int execveat = try_execveat_empty();
    TEST("execveat AT_EMPTY_PATH blocked",
         execveat <= 0,
         execveat == 1  ? "EXECUTED — fd-based execution!" :
         execveat == -2 ? "SIGSYS" : "blocked");

    int seccomp_filter = try_seccomp_add_filter();
    TEST("seccomp add filter blocked",
         seccomp_filter <= 0,
         seccomp_filter == 1  ? "ADDED FILTER — seccomp reconfiguration!" :
         seccomp_filter == -2 ? "SIGSYS" : "blocked");

    int pers = try_personality();
    TEST("personality ASLR disable blocked",
         pers <= 0,
         pers == 1  ? "DISABLED ASLR — address randomization bypass!" :
         pers == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
