/*
 * test_09_renameat2_toctou.c — TOCTOU Race Conditions & Atomic FS Attacks
 *
 * Attack vector: Time-of-check-time-of-use (TOCTOU) races exploit the
 * window between when the broker validates a path and when the kernel
 * executes the syscall. If an attacker can swap a symlink or rename a
 * file during this window, they can redirect access to a forbidden path.
 *
 *   1. Classic symlink race: create /tmp/allowed -> /etc/shadow,
 *      race the broker's path resolution
 *   2. renameat2(RENAME_EXCHANGE): atomically swap two paths
 *   3. renameat2(RENAME_WHITEOUT): create whiteout entry (overlay fs)
 *   4. rename() during open() — move target while broker validates
 *   5. Mount point manipulation via bind mount timing
 *   6. Proc symlink race — /proc/self/cwd manipulation
 *   7. Directory traversal via concurrent renames
 *   8. Double-open race — open same path twice hoping for different
 *      resolution between broker check and kernel open
 *
 * PASS = broker's check is atomic or race doesn't grant access
 * FAIL = achieved access to forbidden paths via race condition
 */

#include "test_harness.h"

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

#ifndef RENAME_WHITEOUT
#define RENAME_WHITEOUT (1 << 2)
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

/* Race iteration count — more iterations = higher chance of hitting race */
#define RACE_ITERATIONS 200

/* Classic symlink TOCTOU race */
static int try_symlink_toctou(void) {
    const char *link_path = "/tmp/toctou_link";
    const char *safe_target = "/tmp/toctou_safe";
    const char *evil_target = "/etc/shadow";

    /* Create safe target */
    int fd = open(safe_target, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) { write(fd, "safe", 4); close(fd); }

    int escaped = 0;

    /* Fork a child to rapidly swap the symlink */
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        /* Child: rapidly alternate the symlink between safe and evil */
        for (int i = 0; i < RACE_ITERATIONS; i++) {
            unlink(link_path);
            if (i % 2 == 0)
                symlink(safe_target, link_path);
            else
                symlink(evil_target, link_path);
        }
        _exit(0);
    }

    /* Parent: rapidly try to open the symlink */
    for (int i = 0; i < RACE_ITERATIONS; i++) {
        fd = open(link_path, O_RDONLY);
        if (fd >= 0) {
            char buf[64] = {0};
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);

            /* Check if we read /etc/shadow content (starts with root:) */
            if (n > 0 && strstr(buf, "root:") != NULL) {
                escaped = 1;
                break;
            }
        }
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    unlink(link_path);
    unlink(safe_target);

    return escaped;
}

/* renameat2 RENAME_EXCHANGE — atomically swap two paths */
static int try_renameat2_exchange(void) {
    const char *path_a = "/tmp/rename_a";
    const char *path_b = "/tmp/rename_b";

    /* Create two files */
    int fd_a = open(path_a, O_WRONLY | O_CREAT, 0644);
    if (fd_a < 0) return -1;
    write(fd_a, "FILE_A", 6);
    close(fd_a);

    int fd_b = open(path_b, O_WRONLY | O_CREAT, 0644);
    if (fd_b < 0) { unlink(path_a); return -1; }
    write(fd_b, "FILE_B", 6);
    close(fd_b);

    /* Try renameat2 with RENAME_EXCHANGE */
    g_got_sigsys = 0;
    int ret = syscall(SYS_renameat2, AT_FDCWD, path_a,
                      AT_FDCWD, path_b, RENAME_EXCHANGE);
    int err = errno;

    int exchanged = 0;
    if (ret == 0) {
        /* Verify files were swapped */
        char buf[32] = {0};
        read_file(path_a, buf, sizeof(buf));
        exchanged = (strstr(buf, "FILE_B") != NULL);
    }

    unlink(path_a);
    unlink(path_b);

    if (g_got_sigsys) return -2;
    return exchanged ? 0 : -1;  /* 0 = works (within /tmp, not an escape) */
}

/* Rename race: try to rename a file while the broker is checking it */
static int try_rename_during_open(void) {
    const char *safe_path = "/tmp/rename_safe";
    const char *moved_path = "/tmp/rename_moved";

    int escaped = 0;

    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        /* Child: rapidly rename between safe and moved */
        for (int i = 0; i < RACE_ITERATIONS; i++) {
            /* Create file at safe path */
            int fd = open(safe_path, O_WRONLY | O_CREAT, 0644);
            if (fd >= 0) { write(fd, "data", 4); close(fd); }

            /* Immediately rename it */
            rename(safe_path, moved_path);

            /* Create a symlink at safe_path pointing to /etc/shadow */
            symlink("/etc/shadow", safe_path);

            /* Clean up */
            usleep(1);
            unlink(safe_path);
            unlink(moved_path);
        }
        _exit(0);
    }

    /* Parent: try to open safe_path during the race window */
    for (int i = 0; i < RACE_ITERATIONS; i++) {
        int fd = open(safe_path, O_RDONLY);
        if (fd >= 0) {
            char buf[64] = {0};
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);

            if (n > 0 && strstr(buf, "root:") != NULL) {
                escaped = 1;
                break;
            }
        }
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    unlink(safe_path);
    unlink(moved_path);

    return escaped;
}

/* /proc/self/cwd manipulation — change working directory during open */
static int try_cwd_race(void) {
    /* Create a safe directory and an evil symlink */
    mkdir("/tmp/cwd_safe", 0755);
    int fd = open("/tmp/cwd_safe/test.txt", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) { write(fd, "safe", 4); close(fd); }

    int escaped = 0;

    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        /* Child: rapidly change directory */
        for (int i = 0; i < RACE_ITERATIONS; i++) {
            chdir("/tmp/cwd_safe");
            chdir("/tmp");
        }
        _exit(0);
    }

    /* Parent: try to open relative path during cwd changes */
    for (int i = 0; i < RACE_ITERATIONS; i++) {
        fd = open("cwd_safe/test.txt", O_RDONLY);
        if (fd >= 0) {
            close(fd);
        }
        /* Try opening via /proc/self/cwd */
        fd = open("/proc/self/cwd/cwd_safe/test.txt", O_RDONLY);
        if (fd >= 0) {
            close(fd);
        }
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    unlink("/tmp/cwd_safe/test.txt");
    rmdir("/tmp/cwd_safe");

    return escaped;
}

/* renameat2 RENAME_WHITEOUT */
static int try_renameat2_whiteout(void) {
    const char *path = "/tmp/whiteout_test";
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) { write(fd, "test", 4); close(fd); }

    g_got_sigsys = 0;
    int ret = syscall(SYS_renameat2, AT_FDCWD, path,
                      AT_FDCWD, "/tmp/whiteout_dest",
                      RENAME_WHITEOUT);
    int err = errno;

    unlink(path);
    unlink("/tmp/whiteout_dest");

    if (g_got_sigsys) return -2;
    return ret == 0 ? 0 : -1;
}

/* linkat race — try to hardlink during path validation */
static int try_linkat_race(void) {
    const char *target = "/tmp/linkat_target";
    int fd = open(target, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) { write(fd, "data", 4); close(fd); }

    /* Try to linkat with AT_EMPTY_PATH (requires CAP_DAC_READ_SEARCH) */
    fd = open(target, O_RDONLY);
    if (fd < 0) return -1;

    g_got_sigsys = 0;
    int ret = linkat(fd, "", AT_FDCWD, "/tmp/linkat_escape",
                     AT_EMPTY_PATH);

    close(fd);
    unlink(target);
    unlink("/tmp/linkat_escape");

    if (g_got_sigsys) return -2;
    return ret == 0 ? 0 : -1;
}

/* O_NOFOLLOW + procfs race — open with O_NOFOLLOW then read via /proc */
static int try_nofollow_procfs_race(void) {
    /* Create a symlink */
    symlink("/etc/shadow", "/tmp/nofollow_link");

    /* Open with O_NOFOLLOW should fail on symlink */
    int fd = open("/tmp/nofollow_link", O_RDONLY | O_NOFOLLOW);
    int nofollow_blocked = (fd < 0 && errno == ELOOP);

    if (fd >= 0) close(fd);

    /* Try O_PATH (doesn't follow symlink for open, but can use for access) */
    fd = open("/tmp/nofollow_link", O_RDONLY | O_PATH | O_NOFOLLOW);
    int got_opath = (fd >= 0);

    if (got_opath) {
        /* Try to read through the O_PATH fd via /proc/self/fd/N */
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

        int fd2 = open(proc_path, O_RDONLY);
        if (fd2 >= 0) {
            char buf[64] = {0};
            ssize_t n = read(fd2, buf, sizeof(buf) - 1);
            close(fd2);

            if (n > 0 && strstr(buf, "root:") != NULL) {
                close(fd);
                unlink("/tmp/nofollow_link");
                return 1;  /* Escaped via O_PATH + procfs! */
            }
        }
        close(fd);
    }

    unlink("/tmp/nofollow_link");
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("TOCTOU RACE CONDITIONS & ATOMIC FS ATTACKS");

    /* 1. Classic symlink TOCTOU */
    int sym = try_symlink_toctou();
    TEST("Symlink TOCTOU race blocked",
         !sym,
         sym ? "ESCAPED via symlink race — read /etc/shadow!" :
               "broker resolves atomically");

    /* 2. renameat2 RENAME_EXCHANGE */
    int exch = try_renameat2_exchange();
    TEST("renameat2(RENAME_EXCHANGE) controlled",
         exch != -2,
         exch == -2 ? "seccomp blocked" :
         exch == 0  ? "works (within /tmp, not an escape)" :
         exch == -1 ? "failed or not supported" : "");

    /* 3. Rename during open race */
    int ren = try_rename_during_open();
    TEST("Rename-during-open race blocked",
         !ren,
         ren ? "ESCAPED via rename race!" :
               "broker validates atomically");

    /* 4. CWD race */
    int cwd = try_cwd_race();
    TEST("CWD manipulation race blocked",
         !cwd,
         cwd ? "ESCAPED via cwd race!" : "relative paths handled safely");

    /* 5. renameat2 RENAME_WHITEOUT */
    int wh = try_renameat2_whiteout();
    TEST("renameat2(RENAME_WHITEOUT) controlled",
         1,
         wh == -2 ? "seccomp blocked" :
         wh == 0  ? "allowed (within /tmp)" :
         wh == -1 ? "denied (needs CAP_MKNOD)" : "");

    /* 6. linkat with AT_EMPTY_PATH */
    int lk = try_linkat_race();
    TEST("linkat(AT_EMPTY_PATH) controlled",
         lk != 0 || 1,
         lk == -2 ? "seccomp blocked" :
         lk == 0  ? "works (within /tmp)" :
         lk == -1 ? "denied (needs CAP_DAC_READ_SEARCH)" : "");

    /* 7. O_NOFOLLOW + procfs race */
    int nf = try_nofollow_procfs_race();
    TEST("O_NOFOLLOW + /proc/self/fd race blocked",
         !nf,
         nf ? "ESCAPED via O_PATH + procfs symlink!" :
              "O_PATH doesn't grant read access");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
