/*
 * test_harness.h — Minimal test harness for sandbox bypass tests.
 *
 * Each test file includes this header and implements:
 *   int main(void) { ... }
 *
 * Compile each test:
 *   gcc -O2 -static -o test_XX_name test_XX_name.c
 *
 * Run inside sandbox:
 *   sandbox-run ./test_XX_name
 *
 * PASS = attack was BLOCKED  (sandbox held)
 * FAIL = attack SUCCEEDED    (sandbox broken)
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ── Colors ──────────────────────────────────────────────── */
#define RED    "\033[91m"
#define GREEN  "\033[92m"
#define YELLOW "\033[93m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

/* ── Counters ────────────────────────────────────────────── */
static int g_pass = 0;
static int g_fail = 0;
static int g_total = 0;

/* ── SIGSYS handler (seccomp TRAP won't kill us) ─────────── */
static volatile sig_atomic_t g_got_sigsys = 0;

static void sigsys_handler(int sig) {
    (void)sig;
    g_got_sigsys = 1;
}

static void install_sigsys_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigsys_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGSYS, &sa, NULL);
}

/* ── Test functions ───────────────────────────────────────── */
__attribute__((unused))
static void test_pass(const char *name, const char *detail) {
    g_pass++; g_total++;
    printf("  [" GREEN "PASS" RESET "] %s", name);
    if (detail && detail[0]) printf(" — %s", detail);
    printf("\n");
}

__attribute__((unused))
static void test_fail(const char *name, const char *detail) {
    g_fail++; g_total++;
    printf("  [" RED "FAIL" RESET "] %s", name);
    if (detail && detail[0]) printf(" — %s", detail);
    printf("\n");
}

__attribute__((unused))
static void test_check(const char *name, int cond, const char *detail) {
    if (cond) test_pass(name, detail);
    else      test_fail(name, detail);
}

/* Convenience: test_check with printf-formatted detail */
__attribute__((format(printf, 3, 4), unused))
static void test_checkf(const char *name, int cond, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    test_check(name, cond, buf);
}

/* Keep TEST macro for simple cases with literal format strings */
#define TEST(name, cond, detail, ...) do {                       \
    char _detail_buf[512];                                        \
    snprintf(_detail_buf, sizeof(_detail_buf),                    \
             detail, ##__VA_ARGS__);                              \
    test_check(name, cond, _detail_buf);                          \
} while(0)

/* ── Summary ──────────────────────────────────────────────── */
#define PRINT_HEADER(title) do {                                 \
    printf("\n" BOLD "═══ %s ═══" RESET "\n", title);             \
} while(0)

#define PRINT_SUMMARY() do {                                     \
    printf("\n" BOLD "─────────────────────────────────" RESET    \
           "\n");                                                  \
    printf(BOLD "Result: %d/%d passed", g_pass, g_total);         \
    if (g_fail) printf(", " RED "%d FAILED" RESET, g_fail);      \
    else        printf(", " GREEN "ALL HELD" RESET);              \
    printf(RESET "\n\n");                                         \
} while(0)

/* ── Helpers ──────────────────────────────────────────────── */
static ssize_t read_file(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n > 0) buf[n] = '\0';
    else buf[0] = '\0';
    return n;
}

static inline long timespec_diff_us(struct timespec *a, struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000000L +
           (b->tv_nsec - a->tv_nsec) / 1000L;
}

#endif /* TEST_HARNESS_H */
