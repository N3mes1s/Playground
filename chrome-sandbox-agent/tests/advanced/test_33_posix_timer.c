/*
 * test_33_posix_timer.c — POSIX timer race surface tests (CVE-2025-38352)
 *
 * CVE-2025-38352: UAF in handle_posix_cpu_timers() during zombie transition.
 * The race occurs when a thread exits while its CPU timer is being processed.
 * From sandbox: timer_create + rapid thread exit = potential UAF trigger.
 *
 * Also tests related timer attack surfaces:
 *  - timer_create with various clock IDs
 *  - timer_settime with aggressive intervals
 *  - timerfd_create (eventfd-based timers)
 *  - setitimer (classic interval timers)
 *  - clock_nanosleep (precision timing)
 *
 * Tests:
 *  1. timer_create CLOCK_REALTIME
 *  2. timer_create CLOCK_THREAD_CPUTIME_ID
 *  3. timer_settime aggressive interval
 *  4. timerfd_create
 *  5. setitimer (ITIMER_REAL)
 *  6. clock_nanosleep (precision)
 *  7. timer + thread exit race surface
 *  8. multiple timers resource exhaustion
 */
#include "test_harness.h"

#ifndef __NR_timer_create
#define __NR_timer_create 222
#endif
#ifndef __NR_timer_settime
#define __NR_timer_settime 223
#endif
#ifndef __NR_timer_delete
#define __NR_timer_delete 226
#endif
#ifndef __NR_timerfd_create
#define __NR_timerfd_create 283
#endif
#ifndef __NR_timerfd_settime
#define __NR_timerfd_settime 286
#endif

/* Test 1: timer_create CLOCK_REALTIME */
static int try_timer_create_realtime(void) {
    g_got_sigsys = 0;
    timer_t tid;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;

    int ret = timer_create(CLOCK_REALTIME, &sev, &tid);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        timer_delete(tid);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 2: timer_create CLOCK_THREAD_CPUTIME_ID (CVE-2025-38352 surface) */
static int try_timer_create_cputime(void) {
    g_got_sigsys = 0;
    timer_t tid;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;

    int ret = timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &tid);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        timer_delete(tid);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 3: timer_settime with aggressive interval */
static int try_timer_aggressive(void) {
    g_got_sigsys = 0;
    timer_t tid;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_NONE;

    if (timer_create(CLOCK_REALTIME, &sev, &tid) != 0) return 0;

    struct itimerspec its;
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 1000; /* 1 microsecond */
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 1000;

    int ret = timer_settime(tid, 0, &its, NULL);
    timer_delete(tid);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 4: timerfd_create */
static int try_timerfd_create(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_timerfd_create, CLOCK_MONOTONIC, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 5: setitimer (ITIMER_REAL) */
static int try_setitimer(void) {
    g_got_sigsys = 0;
    struct itimerval itv;
    memset(&itv, 0, sizeof(itv));
    itv.it_value.tv_sec = 10;
    itv.it_value.tv_usec = 0;

    int ret = setitimer(ITIMER_REAL, &itv, NULL);

    /* Disarm */
    memset(&itv, 0, sizeof(itv));
    setitimer(ITIMER_REAL, &itv, NULL);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 6: clock_nanosleep precision */
static int try_clock_nanosleep(void) {
    g_got_sigsys = 0;
    struct timespec ts = {0, 1000}; /* 1 microsecond */

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int ret = clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t2);

    if (g_got_sigsys) return -2;
    if (ret == 0) {
        long us = timespec_diff_us(&t1, &t2);
        return (int)us;
    }
    return 0;
}

/* Test 7: timer + thread exit race surface (CVE-2025-38352 pattern) */
static int try_timer_thread_race(void) {
    /* Create CPU timer, then exit quickly — race window in kernel */
    g_got_sigsys = 0;

    pid_t pid = fork();
    if (pid == 0) {
        timer_t tid;
        struct sigevent sev;
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_NONE;

        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &tid) != 0)
            _exit(0);

        struct itimerspec its;
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = 1; /* Immediate */
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 1;

        timer_settime(tid, 0, &its, NULL);
        /* Race: timer fires during exit */
        _exit(99);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);
    if (g_got_sigsys) return -2;

    return (WIFEXITED(status) && WEXITSTATUS(status) == 99) ? 1 : 0;
}

/* Test 8: multiple timers resource exhaustion */
static int try_timer_exhaustion(void) {
    g_got_sigsys = 0;
    int count = 0;
    timer_t tids[128];

    for (int i = 0; i < 128; i++) {
        struct sigevent sev;
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_NONE;

        if (timer_create(CLOCK_REALTIME, &sev, &tids[i]) != 0)
            break;
        count++;
    }

    /* Cleanup */
    for (int i = 0; i < count; i++)
        timer_delete(tids[i]);

    if (g_got_sigsys) return -2;
    return count;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("POSIX TIMER RACE SURFACE (CVE-2025-38352)");

    int rt = try_timer_create_realtime();
    TEST("timer_create CLOCK_REALTIME (info)",
         1, /* timers are essential for many applications */
         rt == 1  ? "available (widely needed)" :
         rt == -2 ? "SIGSYS" :
         rt == -1 ? "ENOSYS" : "blocked");

    int cpu = try_timer_create_cputime();
    TEST("timer_create CLOCK_THREAD_CPUTIME_ID (info)",
         1,
         cpu == 1  ? "available (CVE-2025-38352 surface)" :
         cpu == -2 ? "SIGSYS" :
         cpu == -1 ? "ENOSYS" : "blocked");

    int aggressive = try_timer_aggressive();
    TEST("timer_settime 1us interval (info)",
         1,
         aggressive == 1  ? "set (aggressive interval)" :
         aggressive == -2 ? "SIGSYS" : "blocked");

    int tfd = try_timerfd_create();
    TEST("timerfd_create (info)",
         1,
         tfd == 1  ? "available (event loop timer)" :
         tfd == -2 ? "SIGSYS" :
         tfd == -1 ? "ENOSYS" : "blocked");

    int sit = try_setitimer();
    TEST("setitimer ITIMER_REAL (info)",
         1,
         sit == 1  ? "available" :
         sit == -2 ? "SIGSYS" : "blocked");

    int ns = try_clock_nanosleep();
    TEST("clock_nanosleep precision (info)",
         1,
         ns > 0 ? "slept %d us" : "blocked", ns);

    int race = try_timer_thread_race();
    TEST("timer+thread exit race surface (info)",
         1,
         race == 1  ? "race surface available (CVE-2025-38352)" :
         race == -2 ? "SIGSYS" : "timer creation failed");

    int exhaust = try_timer_exhaustion();
    TEST("timer resource limit (info)",
         1,
         "created %d timers before limit", exhaust);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
