/*
 * test_15_cgroup_escape.c — cgroup-based container escape tests
 *
 * The cgroup release_agent attack (Unit42, 2024) escapes containers by:
 *  1. Mounting cgroupfs (needs CAP_SYS_ADMIN)
 *  2. Writing to release_agent (executed by host kernel as root)
 *  3. Triggering the agent by killing a process in the cgroup
 * CVE-2022-0492 made this easier by bypassing permission checks.
 *
 * Tests:
 *  1. Mount cgroupfs (v1)
 *  2. Mount cgroup2 (v2)
 *  3. Access host cgroup release_agent
 *  4. Write to notify_on_release
 *  5. Read /proc/1/cgroup (host cgroup info)
 *  6. unshare(CLONE_NEWCGROUP) for new cgroup namespace
 *  7. /sys/fs/cgroup access
 *  8. /proc/self/cgroup info leak
 */
#include "test_harness.h"

/* Test 1: Mount cgroup v1 filesystem */
static int try_mount_cgroupv1(void) {
    mkdir("/tmp/cgrp_test", 0755);
    int ret = mount("cgroup", "/tmp/cgrp_test", "cgroup",
                    MS_NOSUID | MS_NODEV | MS_NOEXEC, "memory");
    if (ret == 0) {
        umount("/tmp/cgrp_test");
        rmdir("/tmp/cgrp_test");
        return 1; /* Mounted! */
    }
    rmdir("/tmp/cgrp_test");
    return 0;
}

/* Test 2: Mount cgroup v2 filesystem */
static int try_mount_cgroup2(void) {
    mkdir("/tmp/cgrp2_test", 0755);
    int ret = mount("cgroup2", "/tmp/cgrp2_test", "cgroup2",
                    MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    if (ret == 0) {
        umount("/tmp/cgrp2_test");
        rmdir("/tmp/cgrp2_test");
        return 1;
    }
    rmdir("/tmp/cgrp2_test");
    return 0;
}

/* Test 3: Access host cgroup release_agent */
static int try_release_agent(void) {
    /* Try common cgroup v1 release_agent paths */
    const char *paths[] = {
        "/sys/fs/cgroup/memory/release_agent",
        "/sys/fs/cgroup/cpu/release_agent",
        "/sys/fs/cgroup/pids/release_agent",
        "/sys/fs/cgroup/release_agent",
    };

    for (int i = 0; i < 4; i++) {
        int fd = open(paths[i], O_WRONLY);
        if (fd >= 0) {
            close(fd);
            return 1; /* Can write release_agent! */
        }
        fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
            return 2; /* Can read (info leak) */
        }
    }
    return 0;
}

/* Test 4: Write to notify_on_release */
static int try_notify_on_release(void) {
    const char *paths[] = {
        "/sys/fs/cgroup/memory/notify_on_release",
        "/sys/fs/cgroup/cpu/notify_on_release",
        "/sys/fs/cgroup/pids/notify_on_release",
    };

    for (int i = 0; i < 3; i++) {
        int fd = open(paths[i], O_WRONLY);
        if (fd >= 0) {
            close(fd);
            return 1;
        }
    }
    return 0;
}

/* Test 5: Read /proc/1/cgroup — reveals host cgroup structure */
static int try_proc1_cgroup(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/1/cgroup", buf, sizeof(buf));
    if (n > 0) return 1; /* Readable */
    return 0;
}

/* Test 6: unshare(CLONE_NEWCGROUP) */
static int try_unshare_cgroup(void) {
    g_got_sigsys = 0;
    int ret = unshare(0x02000000 /* CLONE_NEWCGROUP */);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* New cgroup NS! */
    return 0;
}

/* Test 7: /sys/fs/cgroup accessibility */
static int try_sysfs_cgroup(void) {
    int fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 8: /proc/self/cgroup info */
static int try_proc_self_cgroup(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/cgroup", buf, sizeof(buf));
    if (n > 0) {
        /* Check if it reveals host cgroup paths */
        if (strstr(buf, "docker") || strstr(buf, "kubepods") ||
            strstr(buf, "system.slice"))
            return 2; /* Host cgroup structure leaked */
        return 1; /* Readable but contained */
    }
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("CGROUP CONTAINER ESCAPE (CVE-2022-0492, Unit42 2024)");

    int cgv1 = try_mount_cgroupv1();
    TEST("cgroup v1 mount blocked",
         cgv1 == 0,
         cgv1 ? "MOUNTED — release_agent escape possible!" : "blocked");

    int cgv2 = try_mount_cgroup2();
    TEST("cgroup v2 mount blocked",
         cgv2 == 0,
         cgv2 ? "MOUNTED — cgroup2 access!" : "blocked");

    int release = try_release_agent();
    TEST("release_agent not writable",
         release <= 0,
         release == 1 ? "WRITABLE — can execute host commands!" :
         release == 2 ? "readable (info leak)" : "blocked");

    int notify = try_notify_on_release();
    TEST("notify_on_release not writable",
         notify == 0,
         notify ? "WRITABLE — can trigger release_agent!" : "blocked");

    /* In PID namespace, we ARE PID 1 — reading own cgroup is expected */
    int proc1_cg = try_proc1_cgroup();
    TEST("/proc/1/cgroup contained (own PID NS)",
         1, /* info only — we are PID 1 */
         proc1_cg ? "readable (own NS — expected)" : "blocked");

    int unshare_cg = try_unshare_cgroup();
    TEST("unshare(CLONE_NEWCGROUP) blocked",
         unshare_cg <= 0,
         unshare_cg == 1  ? "NEW CGROUP NS created!" :
         unshare_cg == -2 ? "SIGSYS" : "blocked");

    int sysfs_cg = try_sysfs_cgroup();
    TEST("/sys/fs/cgroup not accessible",
         sysfs_cg == 0,
         sysfs_cg ? "accessible (cgroup info exposed)" : "blocked");

    int self_cg = try_proc_self_cgroup();
    TEST("/proc/self/cgroup contained",
         self_cg <= 1,
         self_cg == 2 ? "HOST CGROUP STRUCTURE LEAKED!" :
         self_cg == 1 ? "readable (contained)" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
