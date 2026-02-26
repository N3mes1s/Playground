/*
 * test_36_broker_ipc.c — broker IPC probing tests
 *
 * The broker process is the primary escape vector in Chrome-style sandboxes.
 * CVE-2025-2783 and CVE-2025-4609 both exploit IPC boundaries. This test
 * probes the sandbox-broker communication channel:
 *  - Enumerate inherited file descriptors (find broker socket)
 *  - Analyze socket types and options
 *  - Check for unexpected FDs (leaked from parent)
 *  - Test UNIX socket ancillary data on broker channel
 *  - Probe /proc/self/fd for fd types
 *
 * Tests:
 *  1. Enumerate open file descriptors
 *  2. Identify socket FDs (getsockopt)
 *  3. Check /proc/self/fd symlinks
 *  4. Socket type analysis
 *  5. SO_PEERCRED on sockets
 *  6. sendmsg ancillary data on socket FDs
 *  7. /proc/self/fdinfo contents
 *  8. unexpected FD detection (high numbered FDs)
 */
#include "test_harness.h"

/* Test 1: Enumerate open file descriptors */
static int try_enumerate_fds(void) {
    int count = 0;
    int max_fd = 0;

    /* Check FDs 0 through 1023 */
    for (int fd = 0; fd < 1024; fd++) {
        if (fcntl(fd, F_GETFD) >= 0) {
            count++;
            max_fd = fd;
        }
    }

    /* Encode: count in lower 16 bits, max_fd in upper */
    return (max_fd << 16) | (count & 0xFFFF);
}

/* Test 2: Identify socket FDs */
static int try_identify_sockets(void) {
    int socket_count = 0;

    for (int fd = 0; fd < 256; fd++) {
        if (fcntl(fd, F_GETFD) < 0) continue;

        int type;
        socklen_t len = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
            socket_count++;
        }
    }

    return socket_count;
}

/* Test 3: Check /proc/self/fd symlinks */
static int try_proc_self_fd(void) {
    int readable = 0;
    char buf[256];
    char path[64];

    for (int fd = 0; fd < 64; fd++) {
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(path, buf, sizeof(buf) - 1);
        if (n > 0) {
            readable++;
        }
    }

    return readable;
}

/* Test 4: Socket type analysis */
static int try_socket_analysis(void) {
    int found_unix = 0;
    int found_inet = 0;
    int found_other = 0;

    for (int fd = 0; fd < 256; fd++) {
        if (fcntl(fd, F_GETFD) < 0) continue;

        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        if (getsockname(fd, (struct sockaddr *)&addr, &len) == 0) {
            switch (addr.ss_family) {
                case AF_UNIX:  found_unix++;  break;
                case AF_INET:
                case AF_INET6: found_inet++;  break;
                default:       found_other++; break;
            }
        }
    }

    /* Encode: unix in bits 0-7, inet in 8-15, other in 16-23 */
    return (found_other << 16) | (found_inet << 8) | found_unix;
}

/* Test 5: SO_PEERCRED on sockets */
static int try_peercred_probe(void) {
    int found = 0;

    for (int fd = 0; fd < 256; fd++) {
        if (fcntl(fd, F_GETFD) < 0) continue;

        struct ucred cred;
        socklen_t len = sizeof(cred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
            found++;
        }
    }

    return found;
}

/* Test 6: sendmsg ancillary data test on socket FDs */
static int try_sendmsg_ancillary(void) {
    g_got_sigsys = 0;
    /* Find first socket fd */
    int sock_fd = -1;
    for (int fd = 3; fd < 256; fd++) {
        int type;
        socklen_t len = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
            sock_fd = fd;
            break;
        }
    }

    if (sock_fd < 0) return 0;

    /* Try to send an FD via SCM_RIGHTS on this socket */
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) return 0;

    struct msghdr msg;
    struct iovec iov;
    char buf = 'X';
    char cmsg_buf[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &buf;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = pipe_fds[0];

    ssize_t ret = sendmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
    close(pipe_fds[0]);
    close(pipe_fds[1]);

    if (g_got_sigsys) return -2;
    return (ret > 0) ? 1 : 0;
}

/* Test 7: /proc/self/fdinfo contents */
static int try_fdinfo(void) {
    int readable = 0;
    char buf[512];
    char path[64];

    for (int fd = 0; fd < 16; fd++) {
        snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
        ssize_t n = read_file(path, buf, sizeof(buf));
        if (n > 0) readable++;
    }

    return readable;
}

/* Test 8: unexpected FD detection (high numbered FDs) */
static int try_high_fds(void) {
    int high_count = 0;

    /* Check for FDs > 10 which might be leaked from parent */
    for (int fd = 11; fd < 1024; fd++) {
        if (fcntl(fd, F_GETFD) >= 0) {
            high_count++;
        }
    }

    return high_count;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("BROKER IPC PROBING");

    int fds = try_enumerate_fds();
    int fd_count = fds & 0xFFFF;
    int fd_max = (fds >> 16) & 0xFFFF;
    TEST("open fd enumeration (info)",
         1,
         "%d fds open (max fd=%d)", fd_count, fd_max);

    int sockets = try_identify_sockets();
    TEST("socket fds found (info)",
         1,
         "%d socket fds", sockets);

    int proc_fd = try_proc_self_fd();
    TEST("/proc/self/fd readable (info)",
         1,
         "%d fd links readable", proc_fd);

    int analysis = try_socket_analysis();
    int unix_count = analysis & 0xFF;
    int inet_count = (analysis >> 8) & 0xFF;
    int other_count = (analysis >> 16) & 0xFF;
    TEST("socket type analysis (info)",
         1,
         "unix=%d inet=%d other=%d", unix_count, inet_count, other_count);

    int peercred = try_peercred_probe();
    TEST("SO_PEERCRED on sockets (info)",
         1,
         "%d sockets with peercred", peercred);

    int ancillary = try_sendmsg_ancillary();
    TEST("sendmsg SCM_RIGHTS on broker fd (info)",
         1,
         ancillary == 1  ? "sent fd (broker accepts ancillary!)" :
         ancillary == -2 ? "SIGSYS" : "no socket or refused");

    int fdinfo = try_fdinfo();
    TEST("/proc/self/fdinfo readable (info)",
         1,
         "%d fdinfo entries readable", fdinfo);

    int high = try_high_fds();
    TEST("high-numbered fds (>10) (info)",
         1,
         high > 0 ? "%d unexpected high fds!" : "none (clean)", high);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
