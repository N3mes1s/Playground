/*
 * test_18_procfs_race.c — procfs race & symlink attacks (runc 2025)
 *
 * CVE-2025-52881: runc procfs race allows container confinement bypass.
 * CVE-2025-31133: /dev/null → procfs symlink tricks runc into bind-
 * mounting sensitive host procfs files read-write.
 * CVE-2025-52565: /dev/console symlink variant.
 *
 * The core issue: privileged processes resolve /proc paths that an
 * attacker can race to swap via symlinks or mount manipulation.
 *
 * Tests:
 *  1. /proc/sysrq-trigger writability
 *  2. /proc/sys/kernel/core_pattern writability
 *  3. /proc/sys/kernel/modprobe writability
 *  4. /proc/sys/kernel/hotplug writability
 *  5. /proc/sys/vm/overcommit_memory writability
 *  6. /proc/kcore readability
 *  7. Symlink to procfs target from /tmp
 *  8. /proc/self/root traversal outside sandbox
 */
#include "test_harness.h"

/* Try writing to a procfs path */
static int try_write_procfs(const char *path) {
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        close(fd);
        return 1; /* Writable! */
    }
    return 0;
}

/* Try reading a procfs path */
static int try_read_procfs(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 1: /proc/sysrq-trigger — can crash/reboot host */
static int try_sysrq(void) {
    return try_write_procfs("/proc/sysrq-trigger");
}

/* Test 2: /proc/sys/kernel/core_pattern — command injection on crash */
static int try_core_pattern(void) {
    /* Write check */
    int wr = try_write_procfs("/proc/sys/kernel/core_pattern");
    if (wr) return 2; /* Writable — can inject commands! */
    /* Read check */
    int rd = try_read_procfs("/proc/sys/kernel/core_pattern");
    if (rd) return 1; /* Readable — info leak */
    return 0;
}

/* Test 3: /proc/sys/kernel/modprobe — module autoload hijack */
static int try_modprobe(void) {
    return try_write_procfs("/proc/sys/kernel/modprobe");
}

/* Test 4: /proc/sys/kernel/hotplug — uevent handler hijack */
static int try_hotplug(void) {
    return try_write_procfs("/proc/sys/kernel/hotplug");
}

/* Test 5: /proc/sys/vm/overcommit_memory — resource control */
static int try_overcommit(void) {
    return try_write_procfs("/proc/sys/vm/overcommit_memory");
}

/* Test 6: /proc/kcore — raw kernel memory */
static int try_kcore(void) {
    int fd = open("/proc/kcore", O_RDONLY);
    if (fd >= 0) {
        /* Try to actually read something */
        char buf[16];
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);
        return (n > 0) ? 2 : 1; /* 2=readable, 1=opened */
    }
    return 0;
}

/* Test 7: Symlink to procfs — the runc attack pattern.
 * Create a symlink in /tmp pointing to a procfs target,
 * then check if following the symlink reaches the target. */
static int try_procfs_symlink(void) {
    const char *targets[] = {
        "/proc/sys/kernel/core_pattern",
        "/proc/sysrq-trigger",
        "/proc/sys/kernel/modprobe",
    };

    int reached = 0;
    for (int i = 0; i < 3; i++) {
        char link_path[64];
        snprintf(link_path, sizeof(link_path), "/tmp/procfs_link_%d", i);
        unlink(link_path);
        if (symlink(targets[i], link_path) < 0) continue;

        int fd = open(link_path, O_RDONLY);
        if (fd >= 0) {
            reached++;
            close(fd);
        }
        unlink(link_path);
    }
    return reached;
}

/* Test 8: /proc/self/root traversal */
static int try_proc_self_root_escape(void) {
    /* /proc/self/root should point to / within our chroot/mount NS */
    char buf[4096];
    ssize_t n = readlink("/proc/self/root", buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* Try accessing host-only paths via /proc/self/root */
    const char *host_paths[] = {
        "/proc/self/root/../../../etc/shadow",
        "/proc/self/root/etc/shadow",
        "/proc/self/root/root/.bashrc",
    };

    for (int i = 0; i < 3; i++) {
        int fd = open(host_paths[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
            return 1; /* Escaped via /proc/self/root! */
        }
    }
    return 0; /* Contained */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("PROCFS RACE & SYMLINK ATTACKS (runc CVE-2025-52881)");

    int sysrq = try_sysrq();
    TEST("/proc/sysrq-trigger not writable",
         sysrq == 0,
         sysrq ? "WRITABLE — can crash/reboot host!" : "blocked");

    int core = try_core_pattern();
    TEST("/proc/sys/kernel/core_pattern protected",
         core <= 0,
         core == 2 ? "WRITABLE — command injection on crash!" :
         core == 1 ? "readable (info)" : "blocked");

    int modprobe = try_modprobe();
    TEST("/proc/sys/kernel/modprobe not writable",
         modprobe == 0,
         modprobe ? "WRITABLE — can hijack module autoload!" : "blocked");

    int hotplug = try_hotplug();
    TEST("/proc/sys/kernel/hotplug not writable",
         hotplug == 0,
         hotplug ? "WRITABLE — can hijack uevent handler!" : "blocked");

    int overcommit = try_overcommit();
    TEST("/proc/sys/vm/overcommit_memory not writable",
         overcommit == 0,
         overcommit ? "WRITABLE — can control host memory policy!" : "blocked");

    int kcore = try_kcore();
    TEST("/proc/kcore not accessible",
         kcore == 0,
         kcore == 2 ? "READABLE — raw kernel memory accessible!" :
         kcore == 1 ? "opened but unreadable" : "blocked");

    int symlink_reach = try_procfs_symlink();
    TEST("Procfs symlink targets blocked",
         symlink_reach == 0,
         symlink_reach > 0 ? "%d procfs targets reachable via symlink!" :
                             "all blocked",
         symlink_reach);

    int root_escape = try_proc_self_root_escape();
    TEST("/proc/self/root stays in sandbox",
         root_escape == 0,
         root_escape ? "ESCAPED via /proc/self/root!" : "contained");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
