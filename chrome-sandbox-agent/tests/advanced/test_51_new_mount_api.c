/*
 * test_51_new_mount_api.c — New filesystem mount API attack surface
 *
 * Linux 5.2+ introduced a multi-step mount API replacing mount(2):
 *   fsopen() → fsconfig() → fsmount() → move_mount()
 *
 * CVE-2022-0185 demonstrated a heap overflow in legacy_parse_param()
 * triggered via fsconfig(), leading to container escape. The new API
 * was flagged as dangerous by Linus Torvalds and Andy Lutomirski.
 *
 * These 6 syscalls may not be blocked if the seccomp filter predates
 * their addition to the kernel.
 *
 * Tests:
 *  1. fsopen() syscall
 *  2. fsconfig() syscall
 *  3. fsmount() syscall
 *  4. move_mount() syscall
 *  5. open_tree() syscall
 *  6. mount_setattr() syscall
 *  7. fsopen("tmpfs") — common exploit target
 *  8. fsopen("proc") — procfs remount attempt
 */
#include "test_harness.h"

#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif
#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif
#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif
#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif

/* fsconfig commands */
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6

/* Test 1: fsopen() */
static int try_fsopen(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_fsopen, "tmpfs", 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 2: fsconfig() — needs an fs context fd */
static int try_fsconfig(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_fsopen, "tmpfs", 0);
    if (fd < 0) return g_got_sigsys ? -2 : 0;

    g_got_sigsys = 0;
    /* Try to configure a mount option */
    int ret = syscall(__NR_fsconfig, fd, FSCONFIG_SET_STRING, "size", "1M", 0);
    int result;

    if (g_got_sigsys) result = -2;
    else if (ret == 0) result = 1;
    else result = 0;

    close(fd);
    return result;
}

/* Test 3: fsmount() */
static int try_fsmount(void) {
    g_got_sigsys = 0;
    int fsfd = syscall(__NR_fsopen, "tmpfs", 0);
    if (fsfd < 0) return g_got_sigsys ? -2 : 0;

    /* Configure and create */
    syscall(__NR_fsconfig, fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);

    g_got_sigsys = 0;
    int mntfd = syscall(__NR_fsmount, fsfd, 0, 0);
    int result;

    if (g_got_sigsys) result = -2;
    else if (mntfd >= 0) {
        close(mntfd);
        result = 1;
    }
    else result = 0;

    close(fsfd);
    return result;
}

/* Test 4: move_mount() */
static int try_move_mount(void) {
    g_got_sigsys = 0;
    /* Try to move a mount — will likely fail without a valid source */
    int ret = syscall(__NR_move_mount, AT_FDCWD, "/tmp", AT_FDCWD, "/tmp/test_mount", 0);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0; /* Other errors (EINVAL, ENOENT) = syscall exists but args invalid */
}

/* Test 5: open_tree() */
static int try_open_tree(void) {
    g_got_sigsys = 0;
    /* OPEN_TREE_CLONE = 1 */
    int fd = syscall(__NR_open_tree, AT_FDCWD, "/", 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 6: mount_setattr() */
static int try_mount_setattr(void) {
    g_got_sigsys = 0;
    /* struct mount_attr { __u64 attr_set; __u64 attr_clr; __u64 propagation;
     *                      __u64 userns_fd; } */
    struct {
        uint64_t attr_set;
        uint64_t attr_clr;
        uint64_t propagation;
        uint64_t userns_fd;
    } attr;
    memset(&attr, 0, sizeof(attr));

    int ret = syscall(__NR_mount_setattr, AT_FDCWD, "/", 0, &attr, sizeof(attr));
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 7: fsopen("tmpfs") — common exploit target */
static int try_fsopen_tmpfs(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_fsopen, "tmpfs", 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        /* Try full creation chain */
        syscall(__NR_fsconfig, fd, FSCONFIG_SET_STRING, "size", "4096", 0);
        int ret = syscall(__NR_fsconfig, fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
        close(fd);
        return (ret == 0) ? 2 : 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 8: fsopen("proc") — procfs attack */
static int try_fsopen_proc(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_fsopen, "proc", 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NEW MOUNT API (CVE-2022-0185 SURFACE)");

    int fsop = try_fsopen();
    TEST("fsopen() blocked",
         fsop <= 0,
         fsop == 1  ? "OPENED — filesystem context created!" :
         fsop == -2 ? "SIGSYS" :
         fsop == -1 ? "ENOSYS" : "blocked");

    int fscfg = try_fsconfig();
    TEST("fsconfig() blocked",
         fscfg <= 0,
         fscfg == 1  ? "CONFIGURED — mount options set!" :
         fscfg == -2 ? "SIGSYS" : "blocked");

    int fsmnt = try_fsmount();
    TEST("fsmount() blocked",
         fsmnt <= 0,
         fsmnt == 1  ? "MOUNTED — filesystem mounted via new API!" :
         fsmnt == -2 ? "SIGSYS" : "blocked");

    int movmnt = try_move_mount();
    TEST("move_mount() blocked",
         movmnt <= 0,
         movmnt == 1  ? "MOVED — mount point relocated!" :
         movmnt == -2 ? "SIGSYS" :
         movmnt == -1 ? "ENOSYS" : "blocked");

    int optree = try_open_tree();
    TEST("open_tree() blocked",
         optree <= 0,
         optree == 1  ? "OPENED — mount tree fd!" :
         optree == -2 ? "SIGSYS" :
         optree == -1 ? "ENOSYS" : "blocked");

    int mattr = try_mount_setattr();
    TEST("mount_setattr() blocked",
         mattr <= 0,
         mattr == 1  ? "SET — mount attributes changed!" :
         mattr == -2 ? "SIGSYS" :
         mattr == -1 ? "ENOSYS" : "blocked");

    int tmpfs = try_fsopen_tmpfs();
    TEST("fsopen(tmpfs) + create blocked",
         tmpfs <= 0,
         tmpfs == 2  ? "CREATED — full tmpfs mount chain!" :
         tmpfs == 1  ? "OPENED — tmpfs context!" :
         tmpfs == -2 ? "SIGSYS" :
         tmpfs == -1 ? "ENOSYS" : "blocked");

    int proc = try_fsopen_proc();
    TEST("fsopen(proc) blocked",
         proc <= 0,
         proc == 1  ? "OPENED — procfs mount context!" :
         proc == -2 ? "SIGSYS" :
         proc == -1 ? "ENOSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
