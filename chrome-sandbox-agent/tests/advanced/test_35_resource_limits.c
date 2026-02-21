/*
 * test_35_resource_limits.c — eventfd/epoll resource exhaustion tests
 *
 * Kernel heap spray attacks require creating many kernel objects to
 * manipulate slab allocator state. Key primitives:
 *  - eventfd: creates eventfd_ctx objects (kmalloc-64/128)
 *  - epoll: creates epoll file entries (kmalloc-256)
 *  - pipe: creates pipe_buffer arrays (cross-cache spray, CVE-2022-0847)
 *  - socket pairs: creates various socket structures
 *  - timerfd: creates timerfd_ctx objects
 *
 * These tests check what resource limits exist and how many kernel
 * objects can be created from within the sandbox.
 *
 * Tests:
 *  1. eventfd creation spray
 *  2. epoll_create spray
 *  3. pipe creation spray
 *  4. socketpair spray
 *  5. dup/dup2 fd limits
 *  6. RLIMIT_NOFILE check
 *  7. /proc/sys/fs resource limits
 *  8. memfd_create spray (shmem inodes)
 */
#include "test_harness.h"
#include <sys/eventfd.h>
#include <sys/epoll.h>

/* Test 1: eventfd creation spray */
static int try_eventfd_spray(void) {
    g_got_sigsys = 0;
    int count = 0;
    int fds[1024];

    for (int i = 0; i < 1024; i++) {
        int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (g_got_sigsys) break;
        if (fd < 0) break;
        fds[count++] = fd;
    }

    for (int i = 0; i < count; i++) close(fds[i]);

    if (g_got_sigsys) return -2;
    return count;
}

/* Test 2: epoll_create spray */
static int try_epoll_spray(void) {
    g_got_sigsys = 0;
    int count = 0;
    int fds[1024];

    for (int i = 0; i < 1024; i++) {
        int fd = epoll_create1(EPOLL_CLOEXEC);
        if (g_got_sigsys) break;
        if (fd < 0) break;
        fds[count++] = fd;
    }

    for (int i = 0; i < count; i++) close(fds[i]);

    if (g_got_sigsys) return -2;
    return count;
}

/* Test 3: pipe creation spray */
static int try_pipe_spray(void) {
    g_got_sigsys = 0;
    int count = 0;
    int pipes[512][2];

    for (int i = 0; i < 512; i++) {
        if (pipe2(pipes[i], O_NONBLOCK | O_CLOEXEC) != 0) break;
        count++;
    }

    for (int i = 0; i < count; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    if (g_got_sigsys) return -2;
    return count;
}

/* Test 4: socketpair spray */
static int try_socketpair_spray(void) {
    g_got_sigsys = 0;
    int count = 0;
    int pairs[256][2];

    for (int i = 0; i < 256; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pairs[i]) != 0)
            break;
        count++;
    }

    for (int i = 0; i < count; i++) {
        close(pairs[i][0]);
        close(pairs[i][1]);
    }

    if (g_got_sigsys) return -2;
    return count;
}

/* Test 5: dup/dup2 fd limits */
static int try_dup_limits(void) {
    g_got_sigsys = 0;
    int src_fd = eventfd(0, EFD_CLOEXEC);
    if (src_fd < 0) return 0;

    int count = 0;
    int fds[1024];

    for (int i = 0; i < 1024; i++) {
        int fd = dup(src_fd);
        if (fd < 0) break;
        fds[count++] = fd;
    }

    for (int i = 0; i < count; i++) close(fds[i]);
    close(src_fd);

    if (g_got_sigsys) return -2;
    return count;
}

/* Test 6: RLIMIT_NOFILE check */
static int try_rlimit_nofile(void) {
    g_got_sigsys = 0;
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;

    /* Also check if we can increase it */
    struct rlimit new_rl = rl;
    new_rl.rlim_cur = new_rl.rlim_max;
    int can_raise = (setrlimit(RLIMIT_NOFILE, &new_rl) == 0);

    /* Restore */
    setrlimit(RLIMIT_NOFILE, &rl);

    if (g_got_sigsys) return -2;
    /* Encode: positive = soft limit, negate if can't raise */
    return can_raise ? (int)rl.rlim_cur : -(int)rl.rlim_cur;
}

/* Test 7: /proc/sys/fs resource limits */
static int try_proc_fs_limits(void) {
    char buf[64];
    int readable = 0;

    if (read_file("/proc/sys/fs/file-max", buf, sizeof(buf)) > 0)
        readable++;
    if (read_file("/proc/sys/fs/nr_open", buf, sizeof(buf)) > 0)
        readable++;
    if (read_file("/proc/sys/fs/pipe-max-size", buf, sizeof(buf)) > 0)
        readable++;
    if (read_file("/proc/sys/fs/epoll/max_user_watches", buf, sizeof(buf)) > 0)
        readable++;

    return readable;
}

/* Test 8: memfd_create spray */
static int try_memfd_spray(void) {
    g_got_sigsys = 0;
    int count = 0;
    int fds[512];

    for (int i = 0; i < 512; i++) {
        int fd = syscall(__NR_memfd_create, "spray", 0);
        if (g_got_sigsys) break;
        if (fd < 0) break;
        fds[count++] = fd;
    }

    for (int i = 0; i < count; i++) close(fds[i]);

    if (g_got_sigsys) return -2;
    return count;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("RESOURCE LIMITS & KERNEL HEAP SPRAY SURFACE");

    int efd = try_eventfd_spray();
    TEST("eventfd spray (info)",
         1,
         efd == -2 ? "SIGSYS" : "created %d eventfds", efd);

    int epoll = try_epoll_spray();
    TEST("epoll_create spray (info)",
         1,
         epoll == -2 ? "SIGSYS" : "created %d epolls", epoll);

    int pipes = try_pipe_spray();
    TEST("pipe spray (info)",
         1,
         pipes == -2 ? "SIGSYS" : "created %d pipes", pipes);

    int socks = try_socketpair_spray();
    TEST("socketpair spray (info)",
         1,
         socks == -2 ? "SIGSYS" : "created %d pairs", socks);

    int dups = try_dup_limits();
    TEST("dup spray (info)",
         1,
         dups == -2 ? "SIGSYS" : "created %d dups", dups);

    int rl = try_rlimit_nofile();
    TEST("RLIMIT_NOFILE (info)",
         1,
         rl == -2 ? "SIGSYS" :
         rl > 0 ? "soft=%d (can raise to max)" :
         "soft=%d (cannot raise)", rl > 0 ? rl : -rl);

    int proc = try_proc_fs_limits();
    TEST("/proc/sys/fs limits readable (info)",
         1,
         "%d limit files readable", proc);

    int memfd = try_memfd_spray();
    TEST("memfd_create spray (info)",
         1,
         memfd == -2 ? "SIGSYS" : "created %d memfds", memfd);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
