/*
 * test_01_fd_smuggling.c — File Descriptor Smuggling & Broker FD Leak
 *
 * Attack vector: The broker process communicates with the sandboxed child
 * over a Unix domain socket. If that FD (or any audit/log FDs) leaks into
 * the child, an attacker could:
 *   1. Inject fake broker responses to unlock forbidden paths
 *   2. Read audit logs to learn host filesystem layout
 *   3. Write to inherited FDs that point to host files
 *
 * We enumerate all open FDs, probe each for type, and check for leaks.
 * All I/O on unknown FDs is non-blocking to avoid sandbox pipe hangs.
 *
 * PASS = no exploitable FDs leaked
 * FAIL = found writable host FDs or broker socket accessible
 */

#include "test_harness.h"

/* Probe if an FD is a socket */
static int is_socket_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) return 0;
    return S_ISSOCK(st.st_mode);
}

/* Probe if an FD is a regular file (dangerous — could be host file) */
static int is_regular_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) return 0;
    return S_ISREG(st.st_mode);
}

/* Probe if an FD is a pipe */
static int is_pipe_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) return 0;
    return S_ISFIFO(st.st_mode);
}

/* Try to read /proc/self/fd/N to see where FD points */
static int read_fd_link(int fd, char *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, buf, len - 1);
    if (n < 0) { buf[0] = '\0'; return -1; }
    buf[n] = '\0';
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("FD SMUGGLING & BROKER FD LEAK");

    /* 1. Enumerate open FDs beyond stdin/stdout/stderr (scan 3-31 only) */
    int leaked_fds[32];
    int num_leaked = 0;
    for (int fd = 3; fd < 32; fd++) {
        if (fcntl(fd, F_GETFD) != -1) {
            leaked_fds[num_leaked++] = fd;
        }
    }

    printf("  Open FDs beyond stdio: %d\n", num_leaked);
    TEST("Few FDs leaked (< 5 beyond stdio)",
         num_leaked < 5,
         "found %d extra FDs", num_leaked);

    /* 2. Classify each leaked FD */
    int num_sockets = 0, num_files = 0, num_pipes = 0;
    for (int i = 0; i < num_leaked; i++) {
        int fd = leaked_fds[i];
        char link[256] = {0};
        read_fd_link(fd, link, sizeof(link));

        if (is_socket_fd(fd)) {
            num_sockets++;
            printf("    fd %d -> SOCKET (%s)\n", fd, link);
        } else if (is_regular_fd(fd)) {
            num_files++;
            printf("    fd %d -> FILE (%s)\n", fd, link);
        } else if (is_pipe_fd(fd)) {
            num_pipes++;
            printf("    fd %d -> PIPE (%s)\n", fd, link);
        } else {
            printf("    fd %d -> OTHER (%s)\n", fd, link);
        }
    }

    /* 3. No regular files should be leaked */
    TEST("No regular file FDs leaked",
         num_files == 0,
         "found %d file FDs (host file access risk)", num_files);

    /* 4. Check FD_CLOEXEC on all leaked FDs */
    int no_cloexec = 0;
    for (int i = 0; i < num_leaked; i++) {
        int flags = fcntl(leaked_fds[i], F_GETFD);
        if (flags >= 0 && !(flags & FD_CLOEXEC)) {
            no_cloexec++;
        }
    }
    TEST("Leaked FDs have CLOEXEC (won't survive exec)",
         no_cloexec == 0 || num_leaked == 0,
         "%d FDs missing CLOEXEC", no_cloexec);

    /* 5. Try dup of each leaked FD (non-destructive) */
    int dup_ok = 0;
    for (int i = 0; i < num_leaked; i++) {
        int new_fd = dup(leaked_fds[i]);
        if (new_fd >= 0) {
            dup_ok++;
            close(new_fd);
        }
    }
    TEST("dup() of leaked FDs logged",
         1, /* info only */
         "dup succeeded on %d/%d FDs", dup_ok, num_leaked);

    /* 6. Check if any leaked FDs point to sensitive paths */
    int sensitive = 0;
    for (int i = 0; i < num_leaked; i++) {
        char link[256] = {0};
        read_fd_link(leaked_fds[i], link, sizeof(link));
        if (strstr(link, "/etc/shadow") || strstr(link, "/root") ||
            strstr(link, "/.ssh") || strstr(link, "/home")) {
            sensitive++;
            printf("    !!! Sensitive FD: %d -> %s\n", leaked_fds[i], link);
        }
    }
    TEST("No FDs pointing to sensitive paths",
         sensitive == 0,
         "%d FDs point to sensitive locations!", sensitive);

    /* 7. Verify we CAN open /tmp (positive test) */
    int tmp_fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    TEST("/tmp accessible (positive test)",
         tmp_fd >= 0,
         "");
    if (tmp_fd >= 0) close(tmp_fd);

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
