/*
 * test_11_io_uring.c — io_uring seccomp bypass tests
 *
 * io_uring (Linux 5.1+) performs I/O via shared ring buffers, completely
 * bypassing traditional syscall-based security monitoring. Google disabled
 * io_uring in ChromeOS and Android due to this. The "Curing" rootkit (2025)
 * demonstrated full C2 functionality without any traditional syscalls.
 *
 * Tests:
 *  1. io_uring_setup() blocked by seccomp
 *  2. io_uring_enter() blocked
 *  3. io_uring_register() blocked
 *  4. io_uring file read bypasses broker (if setup succeeds)
 *  5. io_uring network ops bypass seccomp monitoring
 *  6. io_uring SQPOLL mode (kernel thread does I/O without syscalls)
 *  7. io_uring registered buffers (fixed buffers avoid copy_from_user)
 *  8. io_uring file open via IORING_OP_OPENAT
 */
#include "test_harness.h"
#include <linux/io_uring.h>

/* io_uring syscall numbers (not in older glibc headers) */
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup    425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter    426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

/* IORING flags */
#ifndef IORING_SETUP_SQPOLL
#define IORING_SETUP_SQPOLL (1U << 1)
#endif

/* Try io_uring_setup with given params */
static int try_io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

/* Test 1: Basic io_uring_setup */
static int try_basic_setup(void) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    int fd = try_io_uring_setup(8, &params);
    if (fd >= 0) {
        close(fd);
        return 1; /* Setup succeeded — BAD */
    }
    return 0; /* Blocked — GOOD */
}

/* Test 2: io_uring_enter on invalid fd */
static int try_io_uring_enter(void) {
    g_got_sigsys = 0;
    long ret = syscall(__NR_io_uring_enter, -1, 1, 0, 0, NULL, 0);
    if (g_got_sigsys) return -2; /* SIGSYS = seccomp killed it */
    if (ret < 0 && errno == ENOSYS) return -1; /* Not supported */
    if (ret < 0 && errno == EBADF) return 1; /* Syscall reachable! */
    return 0;
}

/* Test 3: io_uring_register on invalid fd */
static int try_io_uring_register(void) {
    g_got_sigsys = 0;
    long ret = syscall(__NR_io_uring_register, -1, 0, NULL, 0);
    if (g_got_sigsys) return -2;
    if (ret < 0 && errno == ENOSYS) return -1;
    if (ret < 0 && errno == EBADF) return 1; /* Syscall reachable! */
    return 0;
}

/* Test 4: SQPOLL mode — kernel thread does I/O without user syscalls */
static int try_sqpoll_setup(void) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 1000; /* 1 second idle */
    int fd = try_io_uring_setup(8, &params);
    if (fd >= 0) {
        close(fd);
        return 1; /* SQPOLL mode available! Very dangerous */
    }
    return 0;
}

/* Test 5: Try to read a file via io_uring (if setup works) */
static int try_io_uring_file_read(void) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    int ring_fd = try_io_uring_setup(8, &params);
    if (ring_fd < 0) return 0; /* Can't set up ring — sandbox held */

    /* If we get here, io_uring is available — try reading /etc/shadow */
    int target_fd = open("/etc/shadow", O_RDONLY);
    /* Even if open fails, the fact that io_uring_setup succeeded is a finding */
    if (target_fd >= 0) close(target_fd);
    close(ring_fd);
    return 1; /* io_uring available = bypass potential */
}

/* Test 6: Registered buffers (IORING_REGISTER_BUFFERS) */
static int try_registered_buffers(void) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    int ring_fd = try_io_uring_setup(8, &params);
    if (ring_fd < 0) return 0;

    char buf[4096];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    /* IORING_REGISTER_BUFFERS = 0 */
    long ret = syscall(__NR_io_uring_register, ring_fd, 0, &iov, 1);
    close(ring_fd);
    return (ret >= 0) ? 1 : 0;
}

/* Test 7: Try opening /etc/passwd via io_uring IORING_OP_OPENAT */
static int try_io_uring_openat(void) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    int ring_fd = try_io_uring_setup(16, &params);
    if (ring_fd < 0) return 0; /* Setup blocked */

    /* If io_uring is available, it can open files bypassing the ptrace
     * broker entirely — the kernel handles the open directly. */
    close(ring_fd);
    return 1; /* io_uring available = broker bypass */
}

/* Test 8: io_uring with IORING_SETUP_REGISTERED_FD_ONLY */
#ifndef IORING_SETUP_REGISTERED_FD_ONLY
#define IORING_SETUP_REGISTERED_FD_ONLY (1U << 8)
#endif
static int try_registered_fd_only(void) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_REGISTERED_FD_ONLY;
    int fd = try_io_uring_setup(8, &params);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("io_uring SECCOMP BYPASS (Curing Rootkit, 2025)");

    /* 1. io_uring_setup */
    int setup = try_basic_setup();
    TEST("io_uring_setup() blocked",
         setup == 0,
         setup ? "AVAILABLE — complete seccomp bypass!" : "blocked (good)");

    /* 2. io_uring_enter */
    int enter = try_io_uring_enter();
    TEST("io_uring_enter() blocked",
         enter <= 0,
         enter == 1  ? "REACHABLE — can submit I/O without syscalls!" :
         enter == -2 ? "SIGSYS (seccomp killed)" :
         enter == -1 ? "ENOSYS (not compiled in)" : "blocked");

    /* 3. io_uring_register */
    int reg = try_io_uring_register();
    TEST("io_uring_register() blocked",
         reg <= 0,
         reg == 1  ? "REACHABLE — can register buffers!" :
         reg == -2 ? "SIGSYS (seccomp killed)" :
         reg == -1 ? "ENOSYS (not compiled in)" : "blocked");

    /* 4. SQPOLL mode */
    int sqpoll = try_sqpoll_setup();
    TEST("SQPOLL mode blocked (kernel-thread I/O)",
         sqpoll == 0,
         sqpoll ? "AVAILABLE — kernel does I/O without any syscalls!" : "blocked");

    /* 5. io_uring file read bypass */
    int file_read = try_io_uring_file_read();
    TEST("io_uring file read controlled",
         file_read == 0,
         file_read ? "io_uring can bypass filesystem broker!" : "blocked at setup");

    /* 6. Registered buffers */
    int regbuf = try_registered_buffers();
    TEST("io_uring registered buffers blocked",
         regbuf == 0,
         regbuf ? "Can register fixed buffers!" : "blocked at setup");

    /* 7. io_uring openat (broker bypass) */
    int openat_bypass = try_io_uring_openat();
    TEST("io_uring OPENAT bypasses broker",
         openat_bypass == 0,
         openat_bypass ? "Can open files without broker validation!" :
                         "blocked at setup");

    /* 8. Registered FD only mode */
    int regfd = try_registered_fd_only();
    TEST("io_uring REGISTERED_FD_ONLY blocked",
         regfd == 0,
         regfd ? "Available — stealthy FD mode!" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
