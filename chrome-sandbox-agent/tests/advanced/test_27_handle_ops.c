/*
 * test_27_handle_ops.c — name_to_handle_at / open_by_handle_at tests
 *
 * CVE-2015-1334 demonstrated that open_by_handle_at() can bypass
 * container filesystem restrictions because file handles are
 * system-wide identifiers. If an attacker gets a file handle from
 * inside a container, they can open files on the host filesystem.
 *
 * Requires CAP_DAC_READ_SEARCH for open_by_handle_at, but
 * name_to_handle_at works without privileges and leaks inode info.
 *
 * Also tests:
 *  - readlink on /proc/self/exe (binary path leak)
 *  - /proc/self/root traversal
 *  - AT_EMPTY_PATH tricks
 *  - fstatat/openat with crafted paths
 *
 * Tests:
 *  1. name_to_handle_at (inode info leak)
 *  2. open_by_handle_at (filesystem bypass)
 *  3. /proc/self/exe readlink
 *  4. /proc/self/root symlink
 *  5. openat with AT_EMPTY_PATH
 *  6. readlinkat on /proc/self/fd entries
 *  7. linkat across directories
 *  8. O_PATH fd + fchdir escape
 */
#include "test_harness.h"
#include <linux/types.h>

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

struct file_handle_buf {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[MAX_HANDLE_SZ];
};

#ifndef __NR_name_to_handle_at
#define __NR_name_to_handle_at 303
#endif
#ifndef __NR_open_by_handle_at
#define __NR_open_by_handle_at 304
#endif

/* Test 1: name_to_handle_at — get file handle (inode info leak) */
static int try_name_to_handle(void) {
    g_got_sigsys = 0;
    struct file_handle_buf fh;
    fh.handle_bytes = MAX_HANDLE_SZ;
    int mount_id;

    long ret = syscall(__NR_name_to_handle_at, AT_FDCWD, "/",
                       &fh, &mount_id, 0);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Got file handle! */
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    if (errno == EOPNOTSUPP) return 0; /* Filesystem doesn't support */
    return 0;
}

/* Test 2: open_by_handle_at — open file via handle */
static int try_open_by_handle(void) {
    g_got_sigsys = 0;
    /* First get a handle */
    struct file_handle_buf fh;
    fh.handle_bytes = MAX_HANDLE_SZ;
    int mount_id;

    long ret = syscall(__NR_name_to_handle_at, AT_FDCWD, "/",
                       &fh, &mount_id, 0);
    if (g_got_sigsys || ret < 0) return 0;

    /* Now try to open it */
    int mount_fd = open("/", O_RDONLY);
    if (mount_fd < 0) return 0;

    int fd = syscall(__NR_open_by_handle_at, mount_fd,
                     &fh, O_RDONLY);
    close(mount_fd);

    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* Opened by handle — filesystem bypass! */
    }
    if (errno == EPERM) return 0; /* Needs CAP_DAC_READ_SEARCH */
    return 0;
}

/* Test 3: /proc/self/exe readlink — binary path leak */
static int try_proc_self_exe(void) {
    char buf[256];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        return 1; /* Path leaked */
    }
    return 0;
}

/* Test 4: /proc/self/root symlink — root filesystem access */
static int try_proc_self_root(void) {
    /* /proc/self/root points to the process's root directory.
     * Inside a chroot/mount NS, this reveals the mount point. */
    char buf[256];
    ssize_t len = readlink("/proc/self/root", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        /* If it's just "/" that's normal */
        if (strcmp(buf, "/") == 0) return 1; /* Normal root */
        return 2; /* Different root — interesting! */
    }

    /* Try to open via /proc/self/root/../../../etc/passwd */
    int fd = open("/proc/self/root/../../../etc/passwd", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 3; /* Path traversal via /proc/self/root! */
    }
    return 0;
}

/* Test 5: openat with AT_EMPTY_PATH */
static int try_openat_empty_path(void) {
    g_got_sigsys = 0;
    /* Open a directory fd */
    int dir_fd = open("/", O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) return 0;

    /* openat with empty path and AT_EMPTY_PATH re-opens the fd */
    int fd = openat(dir_fd, "", O_RDONLY | AT_EMPTY_PATH);
    close(dir_fd);

    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* AT_EMPTY_PATH works */
    }
    return 0;
}

/* Test 6: readlinkat on /proc/self/fd entries */
static int try_readlinkat_fd(void) {
    /* Check how many fds leak path information */
    int leaks = 0;
    char link_path[64], target[256];

    for (int fd = 0; fd < 20; fd++) {
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            /* Check if it reveals host paths */
            if (strstr(target, "/host") || strstr(target, "/root") ||
                (target[0] == '/' && !strstr(target, "pipe:") &&
                 !strstr(target, "socket:") && !strstr(target, "anon_inode:")))
                leaks++;
        }
    }
    return leaks;
}

/* Test 7: linkat across directories */
static int try_linkat(void) {
    g_got_sigsys = 0;
    /* Try to create a hard link — would bypass path restrictions */
    int ret = linkat(AT_FDCWD, "/proc/self/exe",
                     AT_FDCWD, "/tmp/link_test_exe", AT_SYMLINK_FOLLOW);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        unlink("/tmp/link_test_exe");
        return 1; /* Created hard link! */
    }
    return 0;
}

/* Test 8: O_PATH fd + fchdir escape */
static int try_opath_fchdir(void) {
    /* Open / with O_PATH (bypasses some permission checks) */
    int fd = open("/", O_PATH | O_DIRECTORY);
    if (fd < 0) return 0;

    /* fchdir to it */
    int ret = fchdir(fd);
    close(fd);

    return (ret == 0) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("FILESYSTEM HANDLE BYPASS (CVE-2015-1334, path leaks)");

    int nth = try_name_to_handle();
    TEST("name_to_handle_at blocked",
         nth <= 0,
         nth == 1  ? "GOT HANDLE — inode info leak!" :
         nth == -2 ? "SIGSYS" :
         nth == -1 ? "ENOSYS" : "blocked");

    int obh = try_open_by_handle();
    TEST("open_by_handle_at blocked",
         obh <= 0,
         obh == 1  ? "OPENED — filesystem bypass!" :
         obh == -2 ? "SIGSYS" : "blocked (needs CAP_DAC_READ_SEARCH)");

    /* /proc/self/exe readlink is expected in own PID NS */
    int exe_link = try_proc_self_exe();
    TEST("/proc/self/exe readlink (info)",
         1,
         exe_link ? "readable (expected in own NS)" : "blocked");

    int root_link = try_proc_self_root();
    TEST("/proc/self/root traversal blocked",
         root_link <= 1,
         root_link == 3 ? "PATH TRAVERSAL via /proc/self/root!" :
         root_link == 2 ? "non-standard root (interesting)" :
         root_link == 1 ? "normal root" : "blocked");

    int at_empty = try_openat_empty_path();
    TEST("openat AT_EMPTY_PATH (info)",
         1,
         at_empty == 1  ? "works (fd re-open)" :
         at_empty == -2 ? "SIGSYS" : "blocked");

    int fd_leaks = try_readlinkat_fd();
    TEST("FD path leaks minimal",
         fd_leaks <= 2,
         fd_leaks > 2 ? "%d fds leak paths!" :
         fd_leaks > 0 ? "%d fds show paths (expected)" :
                        "no path leaks",
         fd_leaks);

    int linkat_res = try_linkat();
    TEST("linkat blocked",
         linkat_res <= 0,
         linkat_res == 1  ? "HARD LINK CREATED — path bypass!" :
         linkat_res == -2 ? "SIGSYS" : "blocked");

    int opath = try_opath_fchdir();
    TEST("O_PATH + fchdir (info)",
         1,
         opath ? "works (expected)" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
