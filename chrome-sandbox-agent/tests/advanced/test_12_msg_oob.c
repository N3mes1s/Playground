/*
 * test_12_msg_oob.c — MSG_OOB UNIX socket exploit tests (CVE-2025-38236)
 *
 * Jann Horn (Google Project Zero, 2025) discovered a use-after-free in
 * the kernel's MSG_OOB handling for UNIX domain stream sockets. This
 * was exploitable from within Chrome's renderer sandbox on Linux 6.9+
 * to achieve full kernel control.
 *
 * The attack uses send(MSG_OOB) + recv(MSG_OOB) sequences to trigger
 * UAF on socket buffer metadata, then reclaims freed memory with
 * pipe_buffer or msg_msg objects for arbitrary kernel R/W.
 *
 * Tests:
 *  1. MSG_OOB send on UNIX stream socket
 *  2. MSG_OOB recv on UNIX stream socket
 *  3. MSG_OOB + MSG_PEEK combination
 *  4. Rapid OOB send/recv cycling (UAF trigger pattern)
 *  5. MSG_OOB with SCM_RIGHTS (FD passing + OOB)
 *  6. MSG_OOB on socketpair (different codepath)
 *  7. OOB with large inline data
 *  8. MSG_OOB flag in sendmsg/recvmsg
 */
#include "test_harness.h"

/* Test 1: Basic MSG_OOB send on UNIX stream socket */
static int try_oob_send(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    char data = 'X';
    g_got_sigsys = 0;
    ssize_t ret = send(sv[0], &data, 1, MSG_OOB);
    int saved_errno = errno;
    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    if (ret < 0 && saved_errno == EOPNOTSUPP) return 0;  /* OOB not supported */
    if (ret < 0 && saved_errno == EPERM) return 0;  /* Blocked */
    return (ret > 0) ? 1 : 0;
}

/* Test 2: MSG_OOB recv on UNIX stream socket */
static int try_oob_recv(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    char data = 'Y';
    ssize_t sent = send(sv[0], &data, 1, MSG_OOB);
    if (sent <= 0) { close(sv[0]); close(sv[1]); return 0; }

    char buf;
    ssize_t ret = recv(sv[1], &buf, 1, MSG_OOB);
    close(sv[0]);
    close(sv[1]);

    return (ret > 0) ? 1 : 0;
}

/* Test 3: MSG_OOB + MSG_PEEK (part of the CVE trigger sequence) */
static int try_oob_peek(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    char data = 'Z';
    send(sv[0], &data, 1, MSG_OOB);

    char buf;
    ssize_t ret = recv(sv[1], &buf, 1, MSG_OOB | MSG_PEEK);
    close(sv[0]);
    close(sv[1]);

    return (ret > 0) ? 1 : 0;
}

/* Test 4: Rapid OOB cycling — the CVE-2025-38236 trigger pattern.
 * Send multiple OOB bytes, then recv them in a specific order to
 * cause the kernel to free and reuse socket buffer metadata. */
static int try_oob_cycling(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    int oob_works = 0;
    char data, buf;

    /* Phase 1: Send regular data + OOB */
    for (int i = 0; i < 10; i++) {
        data = 'A' + (i % 26);
        if (send(sv[0], &data, 1, 0) <= 0) break;
        data = '0' + (i % 10);
        if (send(sv[0], &data, 1, MSG_OOB) <= 0) break;
        oob_works++;
    }

    /* Phase 2: Drain with alternating OOB/normal recv */
    for (int i = 0; i < 20; i++) {
        int flags = (i % 3 == 0) ? MSG_OOB : 0;
        flags |= (i % 5 == 0) ? MSG_PEEK : 0;
        recv(sv[1], &buf, 1, flags | MSG_DONTWAIT);
    }

    close(sv[0]);
    close(sv[1]);

    return (oob_works > 0) ? 1 : 0;
}

/* Test 5: MSG_OOB + SCM_RIGHTS (FD passing with OOB — unusual combo) */
static int try_oob_scm_rights(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    /* Send an FD via SCM_RIGHTS with MSG_OOB flag */
    int dummy_fd = open("/dev/null", O_RDONLY);
    if (dummy_fd < 0) { close(sv[0]); close(sv[1]); return -1; }

    struct msghdr msg = {0};
    struct iovec iov;
    char data = 'F';
    iov.iov_base = &data;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &dummy_fd, sizeof(int));

    ssize_t ret = sendmsg(sv[0], &msg, MSG_OOB);

    close(dummy_fd);
    close(sv[0]);
    close(sv[1]);

    return (ret > 0) ? 1 : 0;
}

/* Test 6: MSG_OOB on SOCK_SEQPACKET (different internal codepath) */
static int try_oob_seqpacket(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) return -1;

    char data = 'S';
    ssize_t ret = send(sv[0], &data, 1, MSG_OOB);
    close(sv[0]);
    close(sv[1]);

    return (ret > 0) ? 1 : 0;
}

/* Test 7: Large OOB data (triggers different buffer handling) */
static int try_oob_large(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    char buf[4096];
    memset(buf, 'L', sizeof(buf));
    ssize_t ret = send(sv[0], buf, sizeof(buf), MSG_OOB);
    close(sv[0]);
    close(sv[1]);

    return (ret > 0) ? 1 : 0;
}

/* Test 8: sendmsg with MSG_OOB (different API path) */
static int try_sendmsg_oob(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;

    struct msghdr msg = {0};
    struct iovec iov;
    char data = 'M';
    iov.iov_base = &data;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t ret = sendmsg(sv[0], &msg, MSG_OOB);
    close(sv[0]);
    close(sv[1]);

    return (ret > 0) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MSG_OOB UNIX SOCKET UAF (CVE-2025-38236)");

    int oob_send = try_oob_send();
    TEST("MSG_OOB send blocked on UNIX stream",
         oob_send <= 0,
         oob_send == 1  ? "OOB SEND WORKS — CVE-2025-38236 surface exposed!" :
         oob_send == -2 ? "SIGSYS (seccomp killed)" :
         oob_send == 0  ? "blocked (EOPNOTSUPP or EPERM)" : "error");

    int oob_recv = try_oob_recv();
    TEST("MSG_OOB recv blocked on UNIX stream",
         oob_recv <= 0,
         oob_recv == 1 ? "OOB RECV WORKS — can trigger UAF pattern!" :
                         "blocked or OOB send failed");

    int oob_peek = try_oob_peek();
    TEST("MSG_OOB + MSG_PEEK blocked",
         oob_peek <= 0,
         oob_peek == 1 ? "OOB PEEK WORKS — trigger pattern available!" :
                         "blocked");

    int cycling = try_oob_cycling();
    TEST("Rapid OOB cycling controlled",
         cycling <= 0,
         cycling == 1 ? "OOB CYCLING WORKS — UAF trigger pattern available!" :
                        "blocked (OOB not available)");

    int scm_oob = try_oob_scm_rights();
    TEST("MSG_OOB + SCM_RIGHTS controlled",
         scm_oob <= 0,
         scm_oob == 1 ? "OOB + FD PASSING works!" : "blocked");

    int seqpacket = try_oob_seqpacket();
    TEST("MSG_OOB on SEQPACKET controlled",
         seqpacket <= 0,
         seqpacket == 1 ? "OOB on SEQPACKET works!" : "blocked or not supported");

    int large = try_oob_large();
    TEST("Large MSG_OOB data controlled",
         large <= 0,
         large == 1 ? "Large OOB send works!" : "blocked");

    int sendmsg_oob = try_sendmsg_oob();
    TEST("sendmsg(MSG_OOB) controlled",
         sendmsg_oob <= 0,
         sendmsg_oob == 1 ? "sendmsg OOB works!" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
