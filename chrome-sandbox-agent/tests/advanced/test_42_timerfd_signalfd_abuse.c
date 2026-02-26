/*
 * test_42_timerfd_signalfd_abuse.c — timerfd/signalfd race and abuse tests
 *
 * timerfd and signalfd are file-descriptor-based notification mechanisms.
 * They can be abused in exploit chains:
 *  - timerfd_create: Precise timing for TOCTOU races
 *  - timerfd + epoll: Event-driven race windows
 *  - signalfd: Intercept SIGSYS to detect seccomp filtering
 *  - signalfd: Intercept SIGCHLD for process monitoring
 *  - eventfd: Cross-thread synchronization for multi-threaded exploits
 *  - epoll_create + many FDs: FD table exhaustion
 *
 * Tests:
 *  1. timerfd_create availability
 *  2. timerfd high-resolution arming (nanosecond precision)
 *  3. signalfd for SIGSYS interception
 *  4. signalfd for SIGCHLD monitoring
 *  5. eventfd creation and signaling
 *  6. epoll_create + FD mass registration
 *  7. timerfd + epoll race primitive
 *  8. Combined timerfd/signalfd/epoll event multiplexing
 */
#include "test_harness.h"
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <poll.h>

/* Test 1: timerfd_create availability */
static int try_timerfd_create(void) {
    g_got_sigsys = 0;
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 2: timerfd high-resolution arming */
static int try_timerfd_highres(void) {
    g_got_sigsys = 0;
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) return 0;

    /* Arm with 1 microsecond interval — exploit-grade precision */
    struct itimerspec its = {
        .it_value    = { .tv_sec = 0, .tv_nsec = 1000 },   /* 1us */
        .it_interval = { .tv_sec = 0, .tv_nsec = 1000 },
    };
    int ret = timerfd_settime(fd, 0, &its, NULL);

    /* Read back and verify */
    struct itimerspec cur;
    timerfd_gettime(fd, &cur);

    /* Wait for a tick */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ready = poll(&pfd, 1, 10 /* ms */);

    close(fd);

    if (g_got_sigsys) return -2;
    if (ret == 0 && ready > 0) return 1; /* High-res timer works */
    if (ret == 0) return 2; /* Armed but no tick yet */
    return 0;
}

/* Test 3: signalfd for SIGSYS interception */
static int try_signalfd_sigsys(void) {
    g_got_sigsys = 0;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);

    /* Block SIGSYS for signalfd (temporarily) */
    sigset_t old;
    sigprocmask(SIG_BLOCK, &mask, &old);

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

    /* Restore signal mask */
    sigprocmask(SIG_SETMASK, &old, NULL);

    if (g_got_sigsys) return -2;
    if (sfd >= 0) {
        close(sfd);
        return 1;
    }
    return 0;
}

/* Test 4: signalfd for SIGCHLD monitoring */
static int try_signalfd_sigchld(void) {
    g_got_sigsys = 0;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    sigset_t old;
    sigprocmask(SIG_BLOCK, &mask, &old);

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0) {
        sigprocmask(SIG_SETMASK, &old, NULL);
        return g_got_sigsys ? -2 : 0;
    }

    /* Fork a child and see if we get notification */
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    if (pid > 0) {
        struct signalfd_siginfo info;
        struct pollfd pfd = { .fd = sfd, .events = POLLIN };
        int ready = poll(&pfd, 1, 100);
        int got_info = 0;
        if (ready > 0) {
            ssize_t n = read(sfd, &info, sizeof(info));
            if (n == sizeof(info) && info.ssi_signo == SIGCHLD) got_info = 1;
        }
        waitpid(pid, NULL, 0);
        close(sfd);
        sigprocmask(SIG_SETMASK, &old, NULL);
        return got_info ? 2 : 1; /* 2 = full monitoring, 1 = fd created */
    }

    close(sfd);
    sigprocmask(SIG_SETMASK, &old, NULL);
    return 0;
}

/* Test 5: eventfd creation and signaling */
static int try_eventfd(void) {
    g_got_sigsys = 0;
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (efd < 0) return 0;

    /* Write and read back */
    uint64_t val = 42;
    ssize_t w = write(efd, &val, sizeof(val));
    uint64_t rval = 0;
    ssize_t r = read(efd, &rval, sizeof(rval));

    close(efd);
    if (w == sizeof(val) && r == sizeof(rval) && rval == 42)
        return 1;
    return 0;
}

/* Test 6: epoll_create + FD mass registration */
static int try_epoll_mass(void) {
    g_got_sigsys = 0;
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (epfd < 0) return 0;

    /* Create many pipe FDs and register them */
    int count = 0;
    int pipes[200]; /* 100 pipe pairs */
    memset(pipes, -1, sizeof(pipes));

    for (int i = 0; i < 100; i++) {
        int pipefd[2];
        if (pipe2(pipefd, O_CLOEXEC) != 0) break;
        pipes[i*2] = pipefd[0];
        pipes[i*2+1] = pipefd[1];

        struct epoll_event ev = { .events = EPOLLIN, .data.fd = pipefd[0] };
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0)
            count++;
    }

    /* Cleanup */
    for (int i = 0; i < 200; i++)
        if (pipes[i] >= 0) close(pipes[i]);
    close(epfd);

    return count; /* How many we registered */
}

/* Test 7: timerfd + epoll race primitive */
static int try_timerfd_epoll_race(void) {
    g_got_sigsys = 0;
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) return 0;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { close(tfd); return 0; }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = tfd };
    epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);

    /* Arm timer for 100us — tight race window */
    struct itimerspec its = {
        .it_value = { .tv_sec = 0, .tv_nsec = 100000 }, /* 100us */
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
    };
    timerfd_settime(tfd, 0, &its, NULL);

    /* Wait for timer event */
    struct epoll_event events[1];
    int n = epoll_wait(epfd, events, 1, 10);

    close(tfd);
    close(epfd);

    if (g_got_sigsys) return -2;
    return (n > 0) ? 1 : 0;
}

/* Test 8: Combined event multiplexing */
static int try_event_multiplex(void) {
    g_got_sigsys = 0;

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    int epfd = epoll_create1(EPOLL_CLOEXEC);

    if (tfd < 0 || efd < 0 || epfd < 0) {
        if (tfd >= 0) close(tfd);
        if (efd >= 0) close(efd);
        if (epfd >= 0) close(epfd);
        return 0;
    }

    /* Register both on epoll */
    struct epoll_event ev1 = { .events = EPOLLIN, .data.fd = tfd };
    struct epoll_event ev2 = { .events = EPOLLIN, .data.fd = efd };
    epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev1);
    epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev2);

    /* Arm timer and signal eventfd */
    struct itimerspec its = {
        .it_value = { .tv_sec = 0, .tv_nsec = 1000000 }, /* 1ms */
    };
    timerfd_settime(tfd, 0, &its, NULL);

    uint64_t val = 1;
    write(efd, &val, sizeof(val));

    /* Wait for events */
    struct epoll_event events[2];
    int n = epoll_wait(epfd, events, 2, 10);

    close(tfd);
    close(efd);
    close(epfd);

    if (g_got_sigsys) return -2;
    return n; /* Number of events received */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("TIMERFD/SIGNALFD/EVENTFD ABUSE");

    int tfd = try_timerfd_create();
    TEST("timerfd_create (info — race primitive)",
         1,
         tfd == 1  ? "available (exploit timing primitive)" :
         tfd == -2 ? "SIGSYS" : "blocked");

    int highres = try_timerfd_highres();
    TEST("timerfd 1us precision (info)",
         1,
         highres == 1 ? "1us timer fires (TOCTOU race grade)" :
         highres == 2 ? "armed but no tick" :
         highres == -2 ? "SIGSYS" : "blocked");

    int sigsys_fd = try_signalfd_sigsys();
    TEST("signalfd(SIGSYS) (info — seccomp detection)",
         1,
         sigsys_fd == 1  ? "available (can detect seccomp filtering)" :
         sigsys_fd == -2 ? "SIGSYS" : "blocked");

    int sigchld = try_signalfd_sigchld();
    TEST("signalfd(SIGCHLD) child monitoring (info)",
         1,
         sigchld == 2 ? "full monitoring (child exit reported)" :
         sigchld == 1 ? "fd created" :
         sigchld == -2 ? "SIGSYS" : "blocked");

    int evfd = try_eventfd();
    TEST("eventfd (info — sync primitive)",
         1,
         evfd == 1  ? "available (cross-thread sync)" :
         evfd == -2 ? "SIGSYS" : "blocked");

    int epoll_mass = try_epoll_mass();
    TEST("epoll mass FD registration (info)",
         1,
         "%d pipe FDs registered on epoll", epoll_mass);

    int race = try_timerfd_epoll_race();
    TEST("timerfd+epoll race primitive (info)",
         1,
         race == 1  ? "100us race window achieved" :
         race == -2 ? "SIGSYS" : "no event");

    int mux = try_event_multiplex();
    TEST("event multiplexing (info)",
         1,
         mux >= 2 ? "multi-source events work (%d sources)" :
         mux == 1 ? "partial event delivery" :
         mux == -2 ? "SIGSYS" : "no events", mux);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
