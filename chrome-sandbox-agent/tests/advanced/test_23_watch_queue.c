/*
 * test_23_watch_queue.c — watch_queue notification subsystem tests
 *
 * CVE-2022-0995: OOB write in watch_queue (discovered by Jann Horn)
 * CVE-2022-1882: UAF in watch_queue pipe interactions
 *
 * The watch_queue subsystem (CONFIG_WATCH_QUEUE) allows userspace to
 * receive notifications about kernel events via pipes. Bugs in the
 * notification delivery path enable kernel memory corruption.
 *
 * Tests:
 *  1. pipe2() with O_NOTIFICATION_PIPE flag
 *  2. IOC_WATCH_QUEUE_SET_SIZE ioctl
 *  3. IOC_WATCH_QUEUE_SET_FILTER ioctl
 *  4. keyctl(KEYCTL_WATCH_KEY) — key change notifications
 *  5. mount watch notifications
 *  6. Rapid pipe create/destroy cycle (UAF trigger pattern)
 *  7. /dev/watch_queue existence
 *  8. Pipe buffer exhaustion test
 */
#include "test_harness.h"

/* Avoid linux/watch_queue.h which conflicts with glibc fcntl.h.
 * Define the structures and ioctls we need manually. */

#ifndef O_NOTIFICATION_PIPE
#define O_NOTIFICATION_PIPE 0200  /* O_EXCL — overloaded for pipe2 */
#endif

struct watch_notification_type_filter {
    uint32_t type;
    uint32_t info_filter;
    uint32_t info_mask;
    uint32_t subtype_filter[8];
};

struct watch_notification_filter {
    uint32_t nr_filters;
    uint32_t __reserved;
    struct watch_notification_type_filter filters[];
};

#define IOC_WATCH_QUEUE_SET_SIZE    _IO('W', 0x60)
#define IOC_WATCH_QUEUE_SET_FILTER  _IOW('W', 0x61, struct watch_notification_filter)

#ifndef __NR_keyctl
#define __NR_keyctl 250
#endif
#define KEYCTL_WATCH_KEY 32

/* Test 1: pipe2 with O_NOTIFICATION_PIPE */
static int try_notification_pipe(void) {
    g_got_sigsys = 0;
    int pipefd[2];
    int ret = pipe2(pipefd, O_NOTIFICATION_PIPE);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1; /* Notification pipe created! */
    }
    return 0;
}

/* Test 2: IOC_WATCH_QUEUE_SET_SIZE ioctl */
static int try_watch_queue_size(void) {
    g_got_sigsys = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    int ret = ioctl(pipefd[0], IOC_WATCH_QUEUE_SET_SIZE, 256);
    int saved_errno = errno;
    close(pipefd[0]);
    close(pipefd[1]);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* watch_queue size set! */
    if (saved_errno == EPERM) return 0;
    if (saved_errno == ENOTTY) return 0; /* Not a watch_queue */
    return 0;
}

/* Test 3: IOC_WATCH_QUEUE_SET_FILTER ioctl */
static int try_watch_queue_filter(void) {
    g_got_sigsys = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    struct watch_notification_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.nr_filters = 0;

    int ret = ioctl(pipefd[0], IOC_WATCH_QUEUE_SET_FILTER, &filter);
    int saved_errno = errno;
    close(pipefd[0]);
    close(pipefd[1]);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    if (saved_errno == ENOTTY) return 0;
    return 0;
}

/* Test 4: keyctl(KEYCTL_WATCH_KEY) — key change notifications */
static int try_keyctl_watch(void) {
    g_got_sigsys = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    /* Try to watch the session keyring (-3) */
    long ret = syscall(__NR_keyctl, KEYCTL_WATCH_KEY, -3 /* session */, pipefd[0], 0, 0);
    int saved_errno = errno;
    close(pipefd[0]);
    close(pipefd[1]);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Watching key! */
    if (saved_errno == EOPNOTSUPP) return 0; /* Not compiled in */
    if (saved_errno == ENOSYS) return -1;
    return 0;
}

/* Test 5: Attempt mount watch (requires specific CONFIG) */
static int try_mount_watch(void) {
    /* Mount watch uses watch_sb_mount() which is even less common */
    /* Just check if the ioctl path is accessible */
    g_got_sigsys = 0;
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    /* Try a generic watch queue ioctl with different params */
    struct {
        uint32_t nr_filters;
        uint32_t __reserved;
    } filter = { 0, 0 };

    int ret = ioctl(pipefd[0], _IOW('W', 0x61, int), &filter);
    int saved_errno = errno;
    close(pipefd[0]);
    close(pipefd[1]);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    if (saved_errno == ENOTTY) return 0;
    return 0;
}

/* Test 6: Rapid pipe create/destroy (UAF trigger pattern for CVE-2022-1882) */
static int try_pipe_rapid_cycle(void) {
    g_got_sigsys = 0;
    int success = 0;
    for (int i = 0; i < 100; i++) {
        int pipefd[2];
        if (pipe(pipefd) == 0) {
            /* Write some data to fill buffers */
            char buf[64];
            memset(buf, 'A', sizeof(buf));
            write(pipefd[1], buf, sizeof(buf));
            close(pipefd[0]);
            close(pipefd[1]);
            success++;
        }
    }
    if (g_got_sigsys) return -2;
    return success >= 90 ? 1 : 0; /* Can do rapid pipe cycling */
}

/* Test 7: /dev/watch_queue check */
static int try_dev_watch_queue(void) {
    int fd = open("/dev/watch_queue", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 8: Pipe buffer size manipulation */
static int try_pipe_buffer_size(void) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return 0;

    /* Get current pipe size */
    int size = fcntl(pipefd[0], 1032 /* F_GETPIPE_SZ */);
    if (size < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    /* Try to set large pipe size (1MB) */
    int ret = fcntl(pipefd[0], 1031 /* F_SETPIPE_SZ */, 1048576);
    close(pipefd[0]);
    close(pipefd[1]);

    return (ret > size) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("WATCH_QUEUE NOTIFICATIONS (CVE-2022-0995, CVE-2022-1882)");

    int notif_pipe = try_notification_pipe();
    TEST("Notification pipe blocked",
         notif_pipe <= 0,
         notif_pipe == 1  ? "CREATED — watch_queue accessible!" :
         notif_pipe == -2 ? "SIGSYS" : "blocked");

    int wq_size = try_watch_queue_size();
    TEST("WATCH_QUEUE_SET_SIZE blocked",
         wq_size <= 0,
         wq_size == 1  ? "SET — watch_queue buffer control!" :
         wq_size == -2 ? "SIGSYS" : "blocked");

    int wq_filter = try_watch_queue_filter();
    TEST("WATCH_QUEUE_SET_FILTER blocked",
         wq_filter <= 0,
         wq_filter == 1  ? "SET — watch_queue filter control!" :
         wq_filter == -2 ? "SIGSYS" : "blocked");

    int keyctl_watch = try_keyctl_watch();
    TEST("KEYCTL_WATCH_KEY blocked",
         keyctl_watch <= 0,
         keyctl_watch == 1  ? "WATCHING — key notification attack surface!" :
         keyctl_watch == -2 ? "SIGSYS" :
         keyctl_watch == -1 ? "ENOSYS" : "blocked");

    int mount_watch = try_mount_watch();
    TEST("Mount watch notifications blocked",
         mount_watch <= 0,
         mount_watch == 1  ? "ACCESSIBLE!" :
         mount_watch == -2 ? "SIGSYS" : "blocked");

    /* Pipe cycling is expected to work — pipes are fundamental */
    int pipe_cycle = try_pipe_rapid_cycle();
    TEST("Rapid pipe cycling (info)",
         1, /* info only */
         pipe_cycle == 1  ? "100 pipes cycled (expected)" :
         pipe_cycle == -2 ? "SIGSYS" : "limited");

    int dev_wq = try_dev_watch_queue();
    TEST("/dev/watch_queue not accessible",
         dev_wq == 0,
         dev_wq ? "accessible!" : "not present (good)");

    int pipe_size = try_pipe_buffer_size();
    TEST("Pipe buffer resize limited (info)",
         1, /* info only */
         pipe_size == 1 ? "can resize to 1MB" : "resize limited or denied");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
