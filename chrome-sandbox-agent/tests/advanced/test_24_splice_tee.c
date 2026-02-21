/*
 * test_24_splice_tee.c — splice/vmsplice/tee zero-copy attack surface tests
 *
 * The zero-copy data path (splice, vmsplice, tee, sendfile) has been
 * a rich source of kernel vulnerabilities:
 *  - CVE-2022-0847 (Dirty Pipe): splice splice_pipe_to_pipe race
 *  - CVE-2024-0646: kTLS + splice() OOB write
 *  - CVE-2008-0009: vmsplice pointer validation bypass
 *
 * These syscalls share page references between kernel buffers,
 * creating opportunities for UAF and data corruption when reference
 * counting or permissions are mishandled.
 *
 * Tests:
 *  1. splice() availability (pipe-to-pipe)
 *  2. splice() file-to-pipe
 *  3. vmsplice() — user memory to pipe (zero-copy)
 *  4. tee() — pipe-to-pipe duplication
 *  5. sendfile() availability
 *  6. splice() with SPLICE_F_MOVE flag
 *  7. Large splice transfer (memory pressure)
 *  8. splice to /dev/null (kernel sink)
 */
#include "test_harness.h"
#include <sys/uio.h>

#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 2
#endif

/* Test 1: splice() pipe-to-pipe */
static int try_splice_pipe_to_pipe(void) {
    g_got_sigsys = 0;
    int pipe_in[2], pipe_out[2];
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) return 0;

    /* Write data to input pipe */
    write(pipe_in[1], "ABCDEFGH", 8);

    /* splice from pipe_in to pipe_out */
    ssize_t ret = splice(pipe_in[0], NULL, pipe_out[1], NULL, 8, SPLICE_F_NONBLOCK);
    int saved_errno = errno;

    close(pipe_in[0]); close(pipe_in[1]);
    close(pipe_out[0]); close(pipe_out[1]);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1; /* splice worked */
    if (saved_errno == ENOSYS) return -1;
    return 0;
}

/* Test 2: splice() file-to-pipe */
static int try_splice_file_to_pipe(void) {
    g_got_sigsys = 0;
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;

    int pipefd[2];
    if (pipe(pipefd) < 0) { close(fd); return 0; }

    loff_t off = 0;
    ssize_t ret = splice(fd, &off, pipefd[1], NULL, 4096, SPLICE_F_NONBLOCK);

    close(fd);
    close(pipefd[0]); close(pipefd[1]);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1;
    return 0;
}

/* Test 3: vmsplice() — maps user memory pages into pipe */
static int try_vmsplice(void) {
    g_got_sigsys = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    char buf[4096];
    memset(buf, 'X', sizeof(buf));

    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    ssize_t ret = vmsplice(pipefd[1], &iov, 1, 0);

    close(pipefd[0]); close(pipefd[1]);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1; /* vmsplice worked — zero-copy user→kernel */
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 4: tee() — duplicate pipe data without consuming */
static int try_tee(void) {
    g_got_sigsys = 0;
    int pipe_a[2], pipe_b[2];
    if (pipe(pipe_a) < 0 || pipe(pipe_b) < 0) return 0;

    write(pipe_a[1], "TESTDATA", 8);

    ssize_t ret = tee(pipe_a[0], pipe_b[1], 8, SPLICE_F_NONBLOCK);

    close(pipe_a[0]); close(pipe_a[1]);
    close(pipe_b[0]); close(pipe_b[1]);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1; /* tee worked */
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 5: sendfile() availability */
static int try_sendfile(void) {
    g_got_sigsys = 0;
    int in_fd = open("/proc/self/status", O_RDONLY);
    if (in_fd < 0) return 0;

    int pipefd[2];
    if (pipe(pipefd) < 0) { close(in_fd); return 0; }

    off_t off = 0;
    ssize_t ret = sendfile(pipefd[1], in_fd, &off, 4096);

    close(in_fd);
    close(pipefd[0]); close(pipefd[1]);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1;
    if (errno == EPERM) return 0; /* Blocked by seccomp */
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 6: splice() with SPLICE_F_MOVE (attempts page migration) */
static int try_splice_move(void) {
    g_got_sigsys = 0;
    int pipe_in[2], pipe_out[2];
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) return 0;

    write(pipe_in[1], "MOVETEST", 8);

    ssize_t ret = splice(pipe_in[0], NULL, pipe_out[1], NULL, 8, SPLICE_F_MOVE);

    close(pipe_in[0]); close(pipe_in[1]);
    close(pipe_out[0]); close(pipe_out[1]);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1;
    return 0;
}

/* Test 7: Large splice transfer (64KB — tests kernel buffer handling) */
static int try_splice_large(void) {
    g_got_sigsys = 0;
    int pipe_in[2], pipe_out[2];
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) return 0;

    /* Set pipe size large enough */
    fcntl(pipe_in[0], 1031 /* F_SETPIPE_SZ */, 65536);
    fcntl(pipe_out[0], 1031 /* F_SETPIPE_SZ */, 65536);

    /* Fill input pipe */
    char buf[65536];
    memset(buf, 'Z', sizeof(buf));
    ssize_t written = write(pipe_in[1], buf, sizeof(buf));
    if (written < (ssize_t)sizeof(buf)) {
        /* Pipe might be smaller */
        close(pipe_in[0]); close(pipe_in[1]);
        close(pipe_out[0]); close(pipe_out[1]);
        return 0;
    }

    ssize_t ret = splice(pipe_in[0], NULL, pipe_out[1], NULL, 65536, SPLICE_F_NONBLOCK);

    close(pipe_in[0]); close(pipe_in[1]);
    close(pipe_out[0]); close(pipe_out[1]);

    if (g_got_sigsys) return -2;
    return (ret > 0) ? 1 : 0;
}

/* Test 8: splice to /dev/null */
static int try_splice_devnull(void) {
    g_got_sigsys = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    write(pipefd[1], "NULLTEST", 8);

    int devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return 0;
    }

    ssize_t ret = splice(pipefd[0], NULL, devnull, NULL, 8, SPLICE_F_NONBLOCK);

    close(devnull);
    close(pipefd[0]); close(pipefd[1]);

    if (g_got_sigsys) return -2;
    return (ret > 0) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SPLICE/VMSPLICE/TEE ZERO-COPY (CVE-2024-0646, Dirty Pipe)");

    /* splice/tee/vmsplice are fundamental operations used by many programs.
     * They're in Chrome's IsAllowedGeneralIo. We test for awareness. */

    int sp_p2p = try_splice_pipe_to_pipe();
    TEST("splice() pipe-to-pipe (info)",
         1, /* splice is widely needed — info only */
         sp_p2p == 1  ? "available (expected)" :
         sp_p2p == -2 ? "SIGSYS" :
         sp_p2p == -1 ? "ENOSYS" : "blocked");

    int sp_f2p = try_splice_file_to_pipe();
    TEST("splice() file-to-pipe (info)",
         1, /* info only */
         sp_f2p == 1  ? "available (expected)" :
         sp_f2p == -2 ? "SIGSYS" : "blocked");

    int vmspl = try_vmsplice();
    TEST("vmsplice() blocked",
         vmspl <= 0,
         vmspl == 1  ? "AVAILABLE — user-to-kernel zero-copy!" :
         vmspl == -2 ? "SIGSYS" :
         vmspl == -1 ? "ENOSYS" : "blocked");

    int tee_res = try_tee();
    TEST("tee() (info)",
         1, /* tee is useful for logging patterns */
         tee_res == 1  ? "available" :
         tee_res == -2 ? "SIGSYS" :
         tee_res == -1 ? "ENOSYS" : "blocked");

    int sf = try_sendfile();
    TEST("sendfile() blocked in STRICT (info)",
         1, /* Chrome returns EPERM to force fallback */
         sf == 1  ? "available" :
         sf == -2 ? "SIGSYS" :
         sf == -1 ? "ENOSYS" : "blocked (EPERM fallback)");

    int sp_move = try_splice_move();
    TEST("splice() SPLICE_F_MOVE (info)",
         1,
         sp_move == 1  ? "available (page migration)" :
         sp_move == -2 ? "SIGSYS" : "blocked");

    int sp_large = try_splice_large();
    TEST("Large splice (64KB) (info)",
         1,
         sp_large == 1  ? "64KB transferred" :
         sp_large == -2 ? "SIGSYS" : "blocked/limited");

    int sp_null = try_splice_devnull();
    TEST("splice to /dev/null (info)",
         1,
         sp_null == 1  ? "available" :
         sp_null == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
