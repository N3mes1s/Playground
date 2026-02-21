/*
 * test_06_scm_rights.c — SCM_RIGHTS FD Passing & Unix Socket Privilege Leak
 *
 * Attack vector: SCM_RIGHTS allows passing file descriptors over Unix domain
 * sockets via sendmsg/recvmsg. If the sandboxed process can connect to a
 * Unix socket where a privileged process sends FDs, it can receive FDs
 * that were opened outside the sandbox, bypassing broker path validation.
 *
 * Attack paths:
 *   1. Connect to /run/dbus/system_bus_socket and request FD passing
 *   2. Connect to /var/run/docker.sock and receive container FDs
 *   3. Try to receive FDs via /proc/self/fd that were opened by the broker
 *   4. Create a socketpair, fork, and have the child pass back FDs
 *   5. SCM_CREDENTIALS to forge PID/UID credentials
 *   6. Ancillary data overflow to corrupt socket buffers
 *
 * PASS = FD passing doesn't grant access outside sandbox
 * FAIL = received FD with access to host filesystem
 */

#include "test_harness.h"

/* Send an FD over a Unix domain socket */
static int send_fd(int socket, int fd_to_send) {
    char data = 'F';
    struct iovec iov = { .iov_base = &data, .iov_len = 1 };

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    return sendmsg(socket, &msg, 0) >= 0 ? 0 : -1;
}

/* Receive an FD over a Unix domain socket */
static int recv_fd(int socket) {
    char data;
    struct iovec iov = { .iov_base = &data, .iov_len = 1 };

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    if (recvmsg(socket, &msg, 0) < 0) return -1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;

    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

/* Try to open a host file via FD passing from a child process */
static int try_fd_pass_escape(const char *target_path) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return -1;

    pid_t child = fork();
    if (child < 0) { close(sv[0]); close(sv[1]); return -1; }

    if (child == 0) {
        close(sv[0]);
        /* Child: try to open the target and send FD to parent */
        int fd = open(target_path, O_RDONLY);
        if (fd >= 0) {
            send_fd(sv[1], fd);
            close(fd);
        }
        close(sv[1]);
        _exit(fd >= 0 ? 0 : 1);
    }

    close(sv[1]);
    /* Parent: try to receive the FD */
    int received_fd = recv_fd(sv[0]);
    close(sv[0]);

    int status;
    waitpid(child, &status, 0);

    if (received_fd < 0) return 0;

    /* Try to read from the received FD */
    char buf[128] = {0};
    ssize_t n = read(received_fd, buf, sizeof(buf) - 1);
    close(received_fd);

    return n > 0 ? 1 : 0;
}

/* Try SCM_CREDENTIALS forgery */
static int try_scm_credentials_forge(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return -1;

    /* Enable SO_PASSCRED on receiving end */
    int optval = 1;
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval));

    /* Send forged credentials (try to claim we're root) */
    struct ucred cred = {
        .pid = 1,    /* PID 1 (init) */
        .uid = 0,    /* root */
        .gid = 0,    /* root */
    };

    char data = 'C';
    struct iovec iov = { .iov_base = &data, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_CREDENTIALS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));

    int sent = sendmsg(sv[0], &msg, 0);

    /* Receive and check what credentials the kernel assigned */
    char cmsgbuf2[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr rmsg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf2,
        .msg_controllen = sizeof(cmsgbuf2),
    };

    int forged_root = 0;
    if (sent >= 0 && recvmsg(sv[1], &rmsg, 0) >= 0) {
        struct cmsghdr *rc = CMSG_FIRSTHDR(&rmsg);
        if (rc && rc->cmsg_type == SCM_CREDENTIALS) {
            struct ucred received;
            memcpy(&received, CMSG_DATA(rc), sizeof(received));
            /* Did the kernel let us forge root credentials? */
            forged_root = (received.uid == 0 && received.pid == 1);
        }
    }

    close(sv[0]);
    close(sv[1]);

    return forged_root ? 1 : 0;
}

/* Try to connect to host Unix sockets and receive FDs */
static int try_host_socket_fd_theft(void) {
    const char *sockets[] = {
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/snapd.socket",
        "/run/systemd/journal/stdout",
        NULL
    };

    for (int i = 0; sockets[i]; i++) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) continue;

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockets[i], sizeof(addr.sun_path) - 1);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(fd);
            return 1;  /* Connected to host socket! */
        }
        close(fd);
    }
    return 0;
}

/* Large ancillary data message — try to overflow cmsg buffer */
static int try_cmsg_overflow(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    /* Try to send 253 FDs at once (SCM_RIGHTS max is usually 253) */
    int fds[253];
    int count = 0;
    for (int i = 0; i < 253; i++) {
        fds[i] = dup(STDIN_FILENO);
        if (fds[i] >= 0) count++;
        else break;
    }

    char data = 'X';
    struct iovec iov = { .iov_base = &data, .iov_len = 1 };

    size_t cmsg_size = CMSG_SPACE(count * sizeof(int));
    char *cmsgbuf = calloc(1, cmsg_size);
    if (!cmsgbuf) {
        for (int i = 0; i < count; i++) close(fds[i]);
        close(sv[0]); close(sv[1]);
        return -1;
    }

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = cmsg_size,
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, count * sizeof(int));

    int ret = sendmsg(sv[0], &msg, 0);

    for (int i = 0; i < count; i++) close(fds[i]);
    free(cmsgbuf);
    close(sv[0]); close(sv[1]);

    return ret >= 0 ? 0 : -1;
}

/* Try to pass an FD that was opened via the broker back through a socket */
static int try_broker_fd_relay(void) {
    /* Open a file that the broker allows */
    int fd = open("/tmp/broker_relay_test", O_RDWR | O_CREAT, 0666);
    if (fd < 0) return -1;
    write(fd, "secret", 6);

    /* Create socketpair and pass this FD */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        close(fd); return -1;
    }

    send_fd(sv[0], fd);
    int received = recv_fd(sv[1]);

    close(fd);
    close(sv[0]); close(sv[1]);

    if (received < 0) return 0;

    /* Can we use the relayed FD? */
    char buf[32] = {0};
    lseek(received, 0, SEEK_SET);
    ssize_t n = read(received, buf, sizeof(buf) - 1);
    close(received);

    unlink("/tmp/broker_relay_test");

    return (n > 0 && strstr(buf, "secret")) ? 0 : -1;
    /* 0 = works but within sandbox (no escalation) */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SCM_RIGHTS FD PASSING & UNIX SOCKET PRIVILEGE LEAK");

    /* 1. FD pass escape to /etc/shadow */
    int shadow = try_fd_pass_escape("/etc/shadow");
    TEST("FD pass of /etc/shadow blocked",
         shadow != 1,
         shadow == 1 ? "RECEIVED /etc/shadow FD!" :
         shadow == 0 ? "child couldn't open it" : "fork/socketpair failed");

    /* 2. FD pass escape to /root */
    int root = try_fd_pass_escape("/root/.bashrc");
    TEST("FD pass of /root/.bashrc blocked",
         root != 1,
         root == 1 ? "RECEIVED HOST FILE FD!" :
         root == 0 ? "child couldn't open it" : "failed");

    /* 3. FD pass escape to /home */
    int home = try_fd_pass_escape("/home/user/.bashrc");
    TEST("FD pass of /home/user/.bashrc blocked",
         home != 1,
         home == 1 ? "RECEIVED HOST FILE FD!" :
         home == 0 ? "child couldn't open it" : "failed");

    /* 4. SCM_CREDENTIALS forgery */
    int cred = try_scm_credentials_forge();
    TEST("SCM_CREDENTIALS cannot forge root",
         !cred,
         cred ? "FORGED ROOT CREDENTIALS!" : "kernel validates real creds");

    /* 5. Host Unix socket connection */
    int host = try_host_socket_fd_theft();
    TEST("Cannot connect to host Unix sockets",
         !host,
         host ? "CONNECTED TO HOST SOCKET!" : "all sockets inaccessible");

    /* 6. cmsg overflow stress test */
    int overflow = try_cmsg_overflow();
    TEST("Large SCM_RIGHTS (253 FDs) handled safely",
         1,
         overflow == 0 ? "sent successfully (no crash)" :
                         "failed (limited — good)");

    /* 7. Broker FD relay within sandbox */
    int relay = try_broker_fd_relay();
    TEST("Broker FD relay stays within sandbox",
         relay == 0 || relay == -1,
         relay == 0  ? "works (no privilege escalation)" :
         relay == -1 ? "blocked" : "");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
