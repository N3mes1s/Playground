/*
 * test_50_pidfd_getfd.c — pidfd_getfd cross-process FD theft
 *
 * pidfd_getfd(2) (Linux 5.6+) allows non-cooperative duplication of file
 * descriptors from other processes. Unlike SCM_RIGHTS (test_06) which
 * requires the target to voluntarily send FDs, pidfd_getfd enables
 * unilateral FD theft with only ptrace-level permission.
 *
 * This is critical for Chrome sandbox escapes because:
 *  - A compromised renderer could steal FDs from the browser process
 *  - Browser FDs include network sockets, GPU device, filesystem handles
 *  - Docker's seccomp profile explicitly blocks this syscall
 *
 * Based on: CVE-2023-34059 (open-vm-tools FD hijack via pidfd_getfd)
 *           "pidfd_getfd is harmful" (lifecs.likai.org, 2020)
 *
 * Tests:
 *  1. pidfd_open() for self
 *  2. pidfd_open() for child process
 *  3. pidfd_getfd() from child (FD theft)
 *  4. pidfd_send_signal() to child
 *  5. pidfd_open() for pid 1 (init)
 *  6. pidfd_open() flags validation
 *  7. pidfd_getfd() with invalid target fd
 *  8. pidfd_open() + close race
 */
#include "test_harness.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

/* Test 1: pidfd_open for self */
static int try_pidfd_self(void) {
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

/* Test 2: pidfd_open for child process */
static int try_pidfd_child(void) {
    g_got_sigsys = 0;

    pid_t child = fork();
    if (child == 0) {
        sleep(2);
        _exit(0);
    }
    if (child < 0) return 0;

    int fd = syscall(__NR_pidfd_open, child, 0);
    int result;

    if (g_got_sigsys) result = -2;
    else if (fd >= 0) { close(fd); result = 1; }
    else if (errno == ENOSYS) result = -1;
    else result = 0;

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

/* Test 3: pidfd_getfd — steal an FD from child */
static int try_pidfd_getfd(void) {
    g_got_sigsys = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) return 0;

    pid_t child = fork();
    if (child == 0) {
        close(pipefd[0]);
        /* Child holds pipefd[1] as fd 3 (after close) */
        /* Keep open a known FD: /dev/null as fd=open result */
        int target_fd = open("/dev/null", O_RDONLY);
        /* Signal parent that we're ready by writing the fd number */
        (void)!write(pipefd[1], &target_fd, sizeof(target_fd));
        close(pipefd[1]);
        sleep(2);
        _exit(0);
    }
    if (child < 0) { close(pipefd[0]); close(pipefd[1]); return 0; }

    close(pipefd[1]);

    /* Read the child's fd number */
    int child_fd;
    read(pipefd[0], &child_fd, sizeof(child_fd));
    close(pipefd[0]);

    /* Open a pidfd for the child */
    int pidfd = syscall(__NR_pidfd_open, child, 0);
    if (pidfd < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return g_got_sigsys ? -2 : 0;
    }

    /* Attempt to steal the child's FD */
    g_got_sigsys = 0;
    int stolen = syscall(__NR_pidfd_getfd, pidfd, child_fd, 0);
    int result;

    if (g_got_sigsys) result = -2;
    else if (stolen >= 0) {
        close(stolen);
        result = 1; /* Successfully stole FD! */
    }
    else if (errno == ENOSYS) result = -1;
    else if (errno == EPERM) result = 0;
    else result = 0;

    close(pidfd);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

/* Test 4: pidfd_send_signal */
static int try_pidfd_send_signal(void) {
    g_got_sigsys = 0;

    pid_t child = fork();
    if (child == 0) {
        sleep(2);
        _exit(0);
    }
    if (child < 0) return 0;

    int pidfd = syscall(__NR_pidfd_open, child, 0);
    int result = 0;

    if (pidfd >= 0) {
        g_got_sigsys = 0;
        long ret = syscall(__NR_pidfd_send_signal, pidfd, SIGKILL, NULL, 0);
        if (g_got_sigsys) result = -2;
        else if (ret == 0) result = 1;
        close(pidfd);
    } else {
        result = g_got_sigsys ? -2 : 0;
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

/* Test 5: pidfd_open for pid 1 (init) */
static int try_pidfd_init(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_pidfd_open, 1, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 6: pidfd_open with invalid flags */
static int try_pidfd_flags(void) {
    g_got_sigsys = 0;
    /* PIDFD_NONBLOCK = O_NONBLOCK = 04000 */
    int fd = syscall(__NR_pidfd_open, getpid(), 04000 /* PIDFD_NONBLOCK */);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 7: pidfd_getfd with invalid target fd */
static int try_pidfd_getfd_invalid(void) {
    g_got_sigsys = 0;
    int pidfd = syscall(__NR_pidfd_open, getpid(), 0);
    if (pidfd < 0) return g_got_sigsys ? -2 : 0;

    g_got_sigsys = 0;
    int stolen = syscall(__NR_pidfd_getfd, pidfd, 99999, 0);
    int result;

    if (g_got_sigsys) result = -2;
    else if (stolen >= 0) { close(stolen); result = 1; }
    else if (errno == EBADF) result = 2; /* Correct: invalid fd rejected */
    else if (errno == ENOSYS) result = -1;
    else result = 0;

    close(pidfd);
    return result;
}

/* Test 8: pidfd_open + rapid close race */
static int try_pidfd_race(void) {
    g_got_sigsys = 0;
    int success = 0;

    for (int i = 0; i < 10; i++) {
        pid_t child = fork();
        if (child == 0) _exit(0);
        if (child < 0) continue;

        /* Race: open pidfd while child is exiting */
        int fd = syscall(__NR_pidfd_open, child, 0);
        if (fd >= 0) {
            success++;
            close(fd);
        }
        waitpid(child, NULL, 0);
    }

    if (g_got_sigsys) return -2;
    return success;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("PIDFD_GETFD CROSS-PROCESS FD THEFT");

    int self = try_pidfd_self();
    TEST("pidfd_open(self) blocked",
         self <= 0,
         self == 1  ? "OPENED — pidfd for self!" :
         self == -2 ? "SIGSYS" :
         self == -1 ? "ENOSYS" : "blocked");

    int child = try_pidfd_child();
    TEST("pidfd_open(child) blocked",
         child <= 0,
         child == 1  ? "OPENED — pidfd for child process!" :
         child == -2 ? "SIGSYS" :
         child == -1 ? "ENOSYS" : "blocked");

    int getfd = try_pidfd_getfd();
    TEST("pidfd_getfd (FD theft) blocked",
         getfd <= 0,
         getfd == 1  ? "STOLEN — cross-process FD theft succeeded!" :
         getfd == -2 ? "SIGSYS" :
         getfd == -1 ? "ENOSYS" : "blocked");

    int sig = try_pidfd_send_signal();
    TEST("pidfd_send_signal blocked",
         sig <= 0,
         sig == 1  ? "SENT — signal via pidfd!" :
         sig == -2 ? "SIGSYS" : "blocked");

    int init = try_pidfd_init();
    TEST("pidfd_open(pid 1) blocked",
         init <= 0,
         init == 1  ? "OPENED — pidfd for init process!" :
         init == -2 ? "SIGSYS" :
         init == -1 ? "ENOSYS" : "blocked");

    int flags = try_pidfd_flags();
    TEST("pidfd_open NONBLOCK blocked",
         flags <= 0,
         flags == 1  ? "OPENED — nonblock pidfd!" :
         flags == -2 ? "SIGSYS" :
         flags == -1 ? "ENOSYS" : "blocked");

    int invalid = try_pidfd_getfd_invalid();
    TEST("pidfd_getfd invalid fd (info)",
         1,
         invalid == 2  ? "EBADF (correct rejection)" :
         invalid == 1  ? "unexpected success" :
         invalid == -2 ? "SIGSYS" :
         invalid == -1 ? "ENOSYS" : "blocked");

    int race = try_pidfd_race();
    TEST("pidfd_open race (info)",
         1,
         race > 0 ? "%d/10 racing pidfds opened" :
         race == -2 ? "SIGSYS" : "none opened", race);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
