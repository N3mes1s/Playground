/*
 * test_38_fuse_access.c — FUSE access probe tests
 *
 * FUSE (Filesystem in Userspace) is a powerful primitive for exploit chains:
 *  - Replaces userfaultfd as a race stabilizer (since uffd restrictions)
 *  - Allows a userspace process to serve filesystem requests
 *  - A sandboxed process with /dev/fuse can stall any thread doing
 *    file I/O on the FUSE mount, creating deterministic race windows
 *  - Used in: Dirty Pagetable exploits, DirtyCred, SLUBStick
 *
 * Also tests:
 *  - fusermount availability
 *  - /sys/fs/fuse accessible
 *  - /dev/fuse device access
 *  - mount() syscall (for FUSE mount)
 *
 * Tests:
 *  1. /dev/fuse device accessible
 *  2. open /dev/fuse
 *  3. mount() syscall availability
 *  4. fusermount binary accessible
 *  5. /sys/fs/fuse readable
 *  6. /proc/filesystems FUSE entry
 *  7. FUSE_DEV_IOC_CLONE ioctl
 *  8. pivot_root/chroot availability
 */
#include "test_harness.h"

#ifndef FUSE_DEV_IOC_CLONE
#define FUSE_DEV_IOC_CLONE _IOR(229, 0, uint32_t)
#endif

/* Test 1: /dev/fuse device accessible */
static int try_dev_fuse_stat(void) {
    struct stat st;
    int ret = stat("/dev/fuse", &st);
    if (ret == 0 && S_ISCHR(st.st_mode)) return 1;
    return 0;
}

/* Test 2: open /dev/fuse */
static int try_dev_fuse_open(void) {
    g_got_sigsys = 0;
    int fd = open("/dev/fuse", O_RDWR);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 3: mount() syscall availability */
static int try_mount(void) {
    g_got_sigsys = 0;
    /* Try mounting tmpfs (will likely fail with EPERM) */
    int ret = mount("none", "/tmp", "tmpfs", 0, "");
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        /* Unlikely but undo */
        umount("/tmp");
        return 1;
    }
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 4: fusermount binary accessible */
static int try_fusermount(void) {
    /* Check common paths */
    const char *paths[] = {
        "/bin/fusermount",
        "/usr/bin/fusermount",
        "/bin/fusermount3",
        "/usr/bin/fusermount3",
    };

    for (int i = 0; i < 4; i++) {
        if (access(paths[i], X_OK) == 0) return 1;
    }
    return 0;
}

/* Test 5: /sys/fs/fuse readable */
static int try_sys_fuse(void) {
    char buf[256];
    int readable = 0;

    if (read_file("/sys/fs/fuse/connections/waiting", buf, sizeof(buf)) > 0)
        readable++;

    /* Try to list /sys/fs/fuse */
    DIR *d = opendir("/sys/fs/fuse");
    if (d) {
        readable++;
        closedir(d);
    }

    return readable;
}

/* Test 6: /proc/filesystems FUSE entry */
static int try_proc_filesystems(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/filesystems", buf, sizeof(buf));
    if (n <= 0) return 0;

    /* Look for fuse entries */
    int found = 0;
    if (strstr(buf, "fuse")) found |= 1;
    if (strstr(buf, "fuseblk")) found |= 2;
    if (strstr(buf, "fusectl")) found |= 4;

    return found;
}

/* Test 7: FUSE_DEV_IOC_CLONE ioctl */
static int try_fuse_clone(void) {
    g_got_sigsys = 0;
    int fd = open("/dev/fuse", O_RDWR);
    if (fd < 0) return 0;

    uint32_t clone_fd = 0;
    int ret = ioctl(fd, FUSE_DEV_IOC_CLONE, &clone_fd);
    close(fd);

    if (g_got_sigsys) return -2;
    if (ret == 0 && clone_fd > 0) {
        close(clone_fd);
        return 1;
    }
    return 0;
}

/* Test 8: pivot_root / chroot availability */
static int try_chroot(void) {
    g_got_sigsys = 0;
    int ret = chroot("/tmp");
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        /* Undo — chroot back */
        (void)!chroot("/");
        return 1;
    }
    if (errno == EPERM) return 0;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("FUSE ACCESS PROBE (RACE STABILIZER)");

    int fuse_stat = try_dev_fuse_stat();
    TEST("/dev/fuse exists (info)",
         1,
         fuse_stat ? "/dev/fuse present" : "not found");

    int fuse_open = try_dev_fuse_open();
    TEST("/dev/fuse open blocked",
         fuse_open <= 0,
         fuse_open == 1  ? "OPENED — FUSE accessible (race stabilizer)!" :
         fuse_open == -2 ? "SIGSYS" : "blocked");

    int mnt = try_mount();
    TEST("mount() blocked",
         mnt <= 0,
         mnt == 1  ? "MOUNTED — filesystem mount from sandbox!" :
         mnt == -2 ? "SIGSYS" :
         mnt == -1 ? "ENOSYS" : "blocked (EPERM)");

    int fusermount = try_fusermount();
    TEST("fusermount binary blocked",
         fusermount <= 0,
         fusermount == 1 ? "FOUND — fusermount executable!" : "not found");

    int sys_fuse = try_sys_fuse();
    TEST("/sys/fs/fuse readable (info)",
         1,
         sys_fuse > 0 ? "%d entries readable" : "not readable", sys_fuse);

    int proc_fs = try_proc_filesystems();
    TEST("/proc/filesystems FUSE (info)",
         1,
         proc_fs & 1 ? "fuse registered" :
         "no fuse in /proc/filesystems");

    int fuse_clone = try_fuse_clone();
    TEST("FUSE_DEV_IOC_CLONE blocked",
         fuse_clone <= 0,
         fuse_clone == 1  ? "CLONED — FUSE device duplication!" :
         fuse_clone == -2 ? "SIGSYS" : "blocked");

    int chrt = try_chroot();
    TEST("chroot blocked",
         chrt <= 0,
         chrt == 1  ? "CHROOTED — filesystem escape possible!" :
         chrt == -2 ? "SIGSYS" : "blocked (EPERM)");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
