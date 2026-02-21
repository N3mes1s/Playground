/*
 * test_29_fanotify_inotify.c — filesystem notification attack surface tests
 *
 * fanotify (Linux 2.6.37+) and inotify provide filesystem event monitoring.
 * fanotify_init() requires CAP_SYS_ADMIN and can intercept file access
 * system-wide, making it a powerful attack primitive:
 *  - Content scanning (read all files as they're opened)
 *  - TOCTOU attacks (modify files between check and use)
 *  - FAN_OPEN_PERM: block/allow file opens (DoS or data interception)
 *
 * inotify is less dangerous (per-inode, no content access) but still
 * enables information leaks about filesystem activity.
 *
 * Tests:
 *  1. fanotify_init() availability
 *  2. inotify_init() availability
 *  3. inotify_add_watch on /tmp
 *  4. inotify_add_watch on /proc
 *  5. inotify resource exhaustion (/proc/sys/fs/inotify limits)
 *  6. dnotify (fcntl F_NOTIFY) legacy interface
 *  7. fanotify_mark() on mount
 *  8. /proc/sys/fs/inotify readable
 */
#include "test_harness.h"
#include <sys/inotify.h>

#ifndef __NR_fanotify_init
#define __NR_fanotify_init 300
#endif
#ifndef __NR_fanotify_mark
#define __NR_fanotify_mark 301
#endif

/* fanotify flags */
#ifndef FAN_CLASS_CONTENT
#define FAN_CLASS_CONTENT     0x04
#endif
#ifndef FAN_CLASS_NOTIF
#define FAN_CLASS_NOTIF       0x00
#endif
#ifndef FAN_CLOEXEC
#define FAN_CLOEXEC           0x01
#endif
#ifndef FAN_MARK_ADD
#define FAN_MARK_ADD          0x01
#endif
#ifndef FAN_MARK_MOUNT
#define FAN_MARK_MOUNT        0x10
#endif
#ifndef FAN_OPEN
#define FAN_OPEN              0x20
#endif
#ifndef FAN_ACCESS
#define FAN_ACCESS            0x01
#endif

/* Test 1: fanotify_init — full filesystem monitoring */
static int try_fanotify_init(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_fanotify_init, FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* fanotify initialized! */
    }
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 2: inotify_init — per-inode monitoring */
static int try_inotify_init(void) {
    g_got_sigsys = 0;
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* inotify available */
    }
    return 0;
}

/* Test 3: inotify_add_watch on /tmp */
static int try_inotify_watch_tmp(void) {
    g_got_sigsys = 0;
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return 0;

    int wd = inotify_add_watch(fd, "/tmp", IN_CREATE | IN_DELETE | IN_MODIFY);
    close(fd);

    if (g_got_sigsys) return -2;
    return (wd >= 0) ? 1 : 0;
}

/* Test 4: inotify_add_watch on /proc */
static int try_inotify_watch_proc(void) {
    g_got_sigsys = 0;
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return 0;

    int wd = inotify_add_watch(fd, "/proc", IN_CREATE | IN_DELETE);
    close(fd);

    if (g_got_sigsys) return -2;
    return (wd >= 0) ? 1 : 0;
}

/* Test 5: inotify resource limits */
static int try_inotify_limits(void) {
    char buf[64];
    ssize_t n;

    /* Check max_user_instances */
    n = read_file("/proc/sys/fs/inotify/max_user_instances", buf, sizeof(buf));
    if (n <= 0) return 0;

    int max_instances = atoi(buf);

    /* Check max_user_watches */
    n = read_file("/proc/sys/fs/inotify/max_user_watches", buf, sizeof(buf));
    if (n <= 0) return max_instances > 0 ? 1 : 0;

    int max_watches = atoi(buf);
    return (max_instances > 0 || max_watches > 0) ? 1 : 0;
}

/* Test 6: dnotify — legacy directory notification via fcntl */
static int try_dnotify(void) {
    g_got_sigsys = 0;
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return 0;

    /* F_NOTIFY = F_SETLEASE + ... on some systems */
    /* DN_MODIFY = 0x02, DN_CREATE = 0x04 */
    int ret = fcntl(fd, 1026 /* F_NOTIFY */, 0x02 | 0x04 /* DN_MODIFY|DN_CREATE */);
    close(fd);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 7: fanotify_mark on mount point */
static int try_fanotify_mark(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_fanotify_init, FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
    if (g_got_sigsys || fd < 0) return 0;

    long ret = syscall(__NR_fanotify_mark, fd,
                       FAN_MARK_ADD | FAN_MARK_MOUNT,
                       FAN_OPEN | FAN_ACCESS,
                       AT_FDCWD, "/");
    close(fd);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 8: /proc/sys/fs/inotify readable (limits info) */
static int try_proc_inotify_info(void) {
    char buf[256];
    int readable = 0;

    if (read_file("/proc/sys/fs/inotify/max_user_instances", buf, sizeof(buf)) > 0)
        readable++;
    if (read_file("/proc/sys/fs/inotify/max_user_watches", buf, sizeof(buf)) > 0)
        readable++;
    if (read_file("/proc/sys/fs/inotify/max_queued_events", buf, sizeof(buf)) > 0)
        readable++;

    return readable;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("FANOTIFY / INOTIFY FILESYSTEM MONITORING ATTACKS");

    int fanotify = try_fanotify_init();
    TEST("fanotify_init blocked",
         fanotify <= 0,
         fanotify == 1  ? "INITIALIZED — system-wide file monitoring!" :
         fanotify == -2 ? "SIGSYS" :
         fanotify == -1 ? "ENOSYS" : "blocked (needs CAP_SYS_ADMIN)");

    int inotify = try_inotify_init();
    TEST("inotify_init (info)",
         1, /* inotify is widely used — info only */
         inotify == 1  ? "available (expected)" :
         inotify == -2 ? "SIGSYS" : "blocked");

    int watch_tmp = try_inotify_watch_tmp();
    TEST("inotify watch /tmp (info)",
         1,
         watch_tmp == 1  ? "watching (expected)" :
         watch_tmp == -2 ? "SIGSYS" : "blocked");

    /* In our own PID namespace, /proc only shows our own processes.
     * inotify on /proc is low risk since it's namespace-isolated. */
    int watch_proc = try_inotify_watch_proc();
    TEST("inotify watch /proc (info — own PID NS)",
         1,
         watch_proc == 1  ? "watching (own PID NS — limited)" :
         watch_proc == -2 ? "SIGSYS" : "blocked");

    int limits = try_inotify_limits();
    TEST("inotify limits readable (info)",
         1,
         limits ? "limits readable" : "not readable");

    int dnotify = try_dnotify();
    TEST("dnotify (F_NOTIFY) blocked",
         dnotify <= 0,
         dnotify == 1  ? "F_NOTIFY works — legacy directory monitoring!" :
         dnotify == -2 ? "SIGSYS" : "blocked");

    int fanotify_mark = try_fanotify_mark();
    TEST("fanotify_mark blocked",
         fanotify_mark <= 0,
         fanotify_mark == 1  ? "MARKED — mount-wide monitoring!" :
         fanotify_mark == -2 ? "SIGSYS" : "blocked");

    int proc_info = try_proc_inotify_info();
    TEST("/proc/sys/fs/inotify (info)",
         1,
         proc_info > 0 ? "%d limit files readable" : "not readable",
         proc_info);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
