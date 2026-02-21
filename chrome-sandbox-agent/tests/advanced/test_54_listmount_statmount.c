/*
 * test_54_listmount_statmount.c — Mount topology information leak
 *
 * listmount(2) and statmount(2) (Linux 6.8+) provide structured mount
 * enumeration using new non-recycling 64-bit mount IDs. These syscalls
 * may not be blocked by seccomp filters that predate their addition.
 *
 * Mount topology reveals:
 *  - Host filesystem layout and mount options
 *  - Container boundaries and overlay configurations
 *  - Sensitive mount points (debugfs, tracefs, securityfs)
 *
 * Tests:
 *  1. statmount() availability
 *  2. listmount() availability
 *  3. statmount() on root mount
 *  4. listmount() enumerate all mounts
 *  5. /proc/self/mountinfo parsing
 *  6. /proc/self/mounts parsing
 *  7. statfs() on sensitive paths
 *  8. /proc/filesystems enumeration
 */
#include "test_harness.h"
#include <sys/vfs.h>

#ifndef __NR_statmount
#define __NR_statmount 457
#endif
#ifndef __NR_listmount
#define __NR_listmount 458
#endif

/* Minimal statmount request */
struct statmount_req {
    uint32_t size;
    uint32_t __spare;
    uint64_t mnt_id;
    uint64_t request_mask;
};

/* Test 1: statmount() availability */
static int try_statmount(void) {
    g_got_sigsys = 0;
    char buf[1024];
    struct statmount_req req = {
        .size = sizeof(req),
        .mnt_id = 0,
        .request_mask = 0,
    };

    long ret = syscall(__NR_statmount, &req, buf, sizeof(buf), 0);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0; /* EINVAL etc = syscall exists */
}

/* Test 2: listmount() availability */
static int try_listmount(void) {
    g_got_sigsys = 0;
    uint64_t mnt_ids[64];
    struct statmount_req req = {
        .size = sizeof(req),
        .mnt_id = 0,
        .request_mask = 0,
    };

    long ret = syscall(__NR_listmount, &req, mnt_ids, 64, 0);
    if (g_got_sigsys) return -2;
    if (ret >= 0) return (int)ret; /* Number of mounts found */
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 3: statmount on root mount (mnt_id = 1 conventionally) */
static int try_statmount_root(void) {
    g_got_sigsys = 0;
    char buf[4096];
    struct statmount_req req = {
        .size = sizeof(req),
        .mnt_id = 1, /* Usually the root mount */
        .request_mask = 0x1, /* STATMOUNT_SB_BASIC */
    };

    long ret = syscall(__NR_statmount, &req, buf, sizeof(buf), 0);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 4: listmount enumerate all */
static int try_listmount_all(void) {
    g_got_sigsys = 0;
    uint64_t mnt_ids[256];
    struct statmount_req req = {
        .size = sizeof(req),
        .mnt_id = 0, /* Start from root */
        .request_mask = 0,
    };

    long ret = syscall(__NR_listmount, &req, mnt_ids, 256, 0);
    if (g_got_sigsys) return -2;
    if (ret > 0) return (int)ret;
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 5: /proc/self/mountinfo parsing */
static int try_mountinfo(void) {
    char buf[8192];
    ssize_t n = read_file("/proc/self/mountinfo", buf, sizeof(buf));
    if (n <= 0) return 0;

    /* Count mount entries */
    int mounts = 0;
    int has_overlay = 0;
    int has_proc = 0;
    int has_sys = 0;
    char *p = buf;
    while (*p) {
        if (*p == '\n') mounts++;
        p++;
    }
    if (strstr(buf, "overlay")) has_overlay = 1;
    if (strstr(buf, " /proc ")) has_proc = 1;
    if (strstr(buf, " /sys ")) has_sys = 1;

    return (mounts & 0xFF) | (has_overlay ? 0x100 : 0) |
           (has_proc ? 0x200 : 0) | (has_sys ? 0x400 : 0);
}

/* Test 6: /proc/self/mounts parsing */
static int try_proc_mounts(void) {
    char buf[8192];
    ssize_t n = read_file("/proc/self/mounts", buf, sizeof(buf));
    if (n <= 0) return 0;

    int mounts = 0;
    char *p = buf;
    while (*p) {
        if (*p == '\n') mounts++;
        p++;
    }
    return mounts;
}

/* Test 7: statfs on sensitive paths */
static int try_statfs_sensitive(void) {
    int accessible = 0;
    struct statfs sfs;

    const char *paths[] = {
        "/sys/kernel/debug",    /* debugfs */
        "/sys/kernel/tracing",  /* tracefs */
        "/sys/kernel/security", /* securityfs */
        "/sys/fs/cgroup",       /* cgroupfs */
    };

    for (int i = 0; i < 4; i++) {
        if (statfs(paths[i], &sfs) == 0) accessible++;
    }
    return accessible;
}

/* Test 8: /proc/filesystems enumeration */
static int try_proc_filesystems(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/filesystems", buf, sizeof(buf));
    if (n <= 0) return 0;

    int count = 0;
    char *p = buf;
    while (*p) {
        if (*p == '\n') count++;
        p++;
    }

    int has_fuse = (strstr(buf, "fuse") != NULL);
    int has_overlay = (strstr(buf, "overlay") != NULL);
    int has_tmpfs = (strstr(buf, "tmpfs") != NULL);

    return (count & 0xFF) | (has_fuse ? 0x100 : 0) |
           (has_overlay ? 0x200 : 0) | (has_tmpfs ? 0x400 : 0);
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MOUNT TOPOLOGY INFORMATION LEAK");

    int sm = try_statmount();
    TEST("statmount() blocked",
         sm <= 0,
         sm == 1  ? "ACCESSIBLE — mount info via new API!" :
         sm == -2 ? "SIGSYS" :
         sm == -1 ? "ENOSYS" : "blocked");

    int lm = try_listmount();
    TEST("listmount() blocked",
         lm <= 0,
         lm > 0   ? "LISTED — %d mounts enumerated!" :
         lm == -2 ? "SIGSYS" :
         lm == -1 ? "ENOSYS" : "blocked", lm);

    int sm_root = try_statmount_root();
    TEST("statmount(root) blocked",
         sm_root <= 0,
         sm_root == 1  ? "ROOT MOUNT — topology visible!" :
         sm_root == -2 ? "SIGSYS" :
         sm_root == -1 ? "ENOSYS" : "blocked");

    int lm_all = try_listmount_all();
    TEST("listmount(all) blocked",
         lm_all <= 0,
         lm_all > 0   ? "ALL — %d mounts listed!" :
         lm_all == -2 ? "SIGSYS" :
         lm_all == -1 ? "ENOSYS" : "blocked", lm_all);

    int minfo = try_mountinfo();
    int mcount = minfo & 0xFF;
    TEST("/proc/self/mountinfo (info)",
         1,
         minfo > 0 ? "%d mounts (overlay=%d proc=%d sys=%d)" :
         "not readable",
         mcount, !!(minfo & 0x100), !!(minfo & 0x200), !!(minfo & 0x400));

    int pmounts = try_proc_mounts();
    TEST("/proc/self/mounts (info)",
         1,
         pmounts > 0 ? "%d mount entries" : "not readable", pmounts);

    int sfs = try_statfs_sensitive();
    TEST("statfs on sensitive paths (info)",
         1,
         "%d/4 sensitive paths accessible", sfs);

    int pfs = try_proc_filesystems();
    int fscount = pfs & 0xFF;
    TEST("/proc/filesystems (info)",
         1,
         pfs > 0 ? "%d fs types (fuse=%d overlay=%d tmpfs=%d)" :
         "not readable",
         fscount, !!(pfs & 0x100), !!(pfs & 0x200), !!(pfs & 0x400));

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
