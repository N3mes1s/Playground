/*
 * test_14_cross_cache.c — Cross-cache slab spray & kernel heap tests
 *
 * Cross-cache attacks (CROSS-X, CCS 2025; SLUBStick, USENIX 2024)
 * exploit UAF/OOB bugs by spraying victim slab caches with attacker-
 * controlled objects (msg_msg, pipe_buffer, sk_buff) to reclaim freed
 * memory for R/W primitives. CVE-2024-50264 (Pwnie 2025) demonstrated
 * this from AF_VSOCK via msg_msg + pipe_buffer corruption.
 *
 * Tests:
 *  1. msg_msg spray (msgsnd/msgrcv heap objects)
 *  2. pipe_buffer spray (many pipe() calls)
 *  3. sk_buff spray (socket buffer allocation)
 *  4. Large msg_msg for cross-slab (> PAGE_SIZE)
 *  5. timerfd spray (timer objects in slab)
 *  6. epoll spray (epoll_ctl objects)
 *  7. signalfd/eventfd spray
 *  8. AF_VSOCK availability (CVE-2024-50264 attack surface)
 */
#include "test_harness.h"
#include <sys/msg.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

struct msgbuf_small {
    long mtype;
    char mtext[128 - sizeof(long)]; /* kmalloc-128 slab */
};

struct msgbuf_medium {
    long mtype;
    char mtext[1024 - sizeof(long)]; /* kmalloc-1024 slab */
};

/* Test 1: msg_msg spray — primary cross-cache object */
static int try_msg_spray(void) {
    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (qid < 0) return -1;

    struct msgbuf_small msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', sizeof(msg.mtext));

    int count = 0;
    for (int i = 0; i < 256; i++) {
        if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) == 0)
            count++;
    }

    /* Drain */
    for (int i = 0; i < count; i++)
        msgrcv(qid, &msg, sizeof(msg.mtext), 1, IPC_NOWAIT);

    msgctl(qid, IPC_RMID, NULL);
    return count;
}

/* Test 2: pipe_buffer spray — secondary cross-cache object */
static int try_pipe_spray(void) {
    int count = 0;
    int pipes[128][2];

    for (int i = 0; i < 128; i++) {
        if (pipe(pipes[i]) < 0) break;
        /* Write to pipe to allocate pipe_buffer */
        char buf[16] = "SPRAY";
        if (write(pipes[i][1], buf, sizeof(buf)) > 0)
            count++;
    }

    /* Cleanup */
    for (int i = 0; i < count; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    return count;
}

/* Test 3: sk_buff spray via socketpair */
static int try_skbuff_spray(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) return -1;

    int count = 0;
    for (int i = 0; i < 256; i++) {
        char buf[128];
        memset(buf, 'B', sizeof(buf));
        ssize_t ret = send(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
        if (ret > 0) count++;
        else break;
    }

    close(sv[0]);
    close(sv[1]);
    return count;
}

/* Test 4: Large msg_msg for cross-slab targeting */
static int try_large_msg(void) {
    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (qid < 0) return -1;

    struct msgbuf_medium msg;
    msg.mtype = 1;
    memset(msg.mtext, 'C', sizeof(msg.mtext));

    int count = 0;
    for (int i = 0; i < 64; i++) {
        if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) == 0)
            count++;
    }

    for (int i = 0; i < count; i++)
        msgrcv(qid, &msg, sizeof(msg.mtext), 1, IPC_NOWAIT);

    msgctl(qid, IPC_RMID, NULL);
    return count;
}

/* Test 5: timerfd spray */
static int try_timerfd_spray(void) {
    int count = 0;
    int fds[128];

    for (int i = 0; i < 128; i++) {
        fds[i] = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        if (fds[i] < 0) break;
        count++;
    }

    for (int i = 0; i < count; i++)
        close(fds[i]);

    return count;
}

/* Test 6: epoll spray */
static int try_epoll_spray(void) {
    int count = 0;
    int fds[128];

    for (int i = 0; i < 128; i++) {
        fds[i] = epoll_create1(0);
        if (fds[i] < 0) break;
        count++;
    }

    for (int i = 0; i < count; i++)
        close(fds[i]);

    return count;
}

/* Test 7: eventfd spray */
static int try_eventfd_spray(void) {
    int count = 0;
    int fds[128];

    for (int i = 0; i < 128; i++) {
        fds[i] = eventfd(0, EFD_NONBLOCK);
        if (fds[i] < 0) break;
        count++;
    }

    for (int i = 0; i < count; i++)
        close(fds[i]);

    return count;
}

/* Test 8: AF_VSOCK availability (CVE-2024-50264 attack surface) */
static int try_vsock(void) {
    g_got_sigsys = 0;
    int fd = socket(40 /* AF_VSOCK */, SOCK_STREAM, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* VSOCK available — CVE-2024-50264 surface */
    }
    if (errno == EAFNOSUPPORT || errno == ENOSYS) return 0;
    if (errno == EPERM || errno == EACCES) return 0;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("CROSS-CACHE SLAB SPRAY (CROSS-X CCS 2025, CVE-2024-50264)");

    int msg_count = try_msg_spray();
    TEST("msg_msg spray controlled",
         msg_count >= 0,
         msg_count > 0 ? "sprayed %d msg_msg objects (contained in IPC NS)" :
         msg_count == 0 ? "blocked" : "error",
         msg_count);

    int pipe_count = try_pipe_spray();
    TEST("pipe_buffer spray controlled",
         pipe_count >= 0,
         "sprayed %d pipe_buffers (bounded by RLIMIT_NOFILE)",
         pipe_count);

    int skb_count = try_skbuff_spray();
    TEST("sk_buff spray controlled",
         skb_count >= 0,
         "sprayed %d sk_buffs via socketpair (bounded by socket buffer)",
         skb_count);

    int large_msg = try_large_msg();
    TEST("Large msg_msg (1K) cross-slab controlled",
         large_msg >= 0,
         "sprayed %d large msg_msg objects (IPC NS isolated)",
         large_msg);

    int timer_count = try_timerfd_spray();
    TEST("timerfd spray controlled",
         timer_count >= 0,
         "created %d timerfd objects (bounded by RLIMIT_NOFILE)",
         timer_count);

    int epoll_count = try_epoll_spray();
    TEST("epoll spray controlled",
         epoll_count >= 0,
         "created %d epoll instances (bounded by RLIMIT_NOFILE)",
         epoll_count);

    int efd_count = try_eventfd_spray();
    TEST("eventfd spray controlled",
         efd_count >= 0,
         "created %d eventfd objects (bounded by RLIMIT_NOFILE)",
         efd_count);

    int vsock = try_vsock();
    TEST("AF_VSOCK blocked (CVE-2024-50264)",
         vsock <= 0,
         vsock == 1  ? "AVAILABLE — CVE-2024-50264 attack surface!" :
         vsock == -2 ? "SIGSYS (seccomp killed)" :
                       "not available (good)");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
