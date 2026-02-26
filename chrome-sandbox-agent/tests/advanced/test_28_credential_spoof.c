/*
 * test_28_credential_spoof.c — Unix socket credential spoofing tests
 *
 * SCM_CREDENTIALS allows sending process credentials over UNIX sockets.
 * SO_PEERCRED reveals the peer's credentials (PID, UID, GID).
 * In user namespaces, the kernel may report mapped credentials that
 * differ from the actual host credentials, enabling:
 *  - Spoofing UID/GID to appear as root to listening services
 *  - Tricking D-Bus, systemd, or other credential-checking services
 *  - PID spoofing in PID namespaces
 *
 * DirtyCred (CCS 2022, USENIX 2023): Swaps kernel credential structures
 * during file operations to escalate privileges. Uses the file credential
 * mechanism rather than socket credentials.
 *
 * Tests:
 *  1. SO_PEERCRED reveals credentials
 *  2. SCM_CREDENTIALS send (credential passing)
 *  3. SO_PASSCRED enable
 *  4. Credential values in user namespace
 *  5. Abstract socket credential check
 *  6. socketpair credential leak
 *  7. /proc/self/status uid/gid info
 *  8. DirtyCred surface: open + fstat race
 */
#include "test_harness.h"

/* Test 1: SO_PEERCRED on socketpair */
static int try_peercred(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 0;

    struct ucred cred;
    socklen_t len = sizeof(cred);
    int ret = getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &cred, &len);

    close(sv[0]); close(sv[1]);

    if (ret == 0) {
        /* Check what credentials are reported */
        if (cred.uid == 0) return 2; /* Reports as root! */
        return 1; /* Credentials accessible */
    }
    return 0;
}

/* Test 2: SCM_CREDENTIALS send */
static int try_scm_credentials_send(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 0;

    /* Enable credential passing */
    int one = 1;
    setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));

    /* Send credentials */
    struct ucred cred;
    cred.pid = getpid();
    cred.uid = getuid();
    cred.gid = getgid();

    struct msghdr msg = {0};
    struct iovec iov;
    char data = 'C';
    iov.iov_base = &data;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsg_buf[CMSG_SPACE(sizeof(struct ucred))];
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_CREDENTIALS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));

    ssize_t ret = sendmsg(sv[0], &msg, 0);

    close(sv[0]); close(sv[1]);

    return (ret > 0) ? 1 : 0;
}

/* Test 3: SO_PASSCRED enable */
static int try_passcred(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 0;

    int one = 1;
    int ret = setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));

    close(sv[0]); close(sv[1]);

    return (ret == 0) ? 1 : 0;
}

/* Test 4: Credential values in user namespace */
static int try_ns_credentials(void) {
    struct ucred cred;
    pid_t pid = getpid();
    uid_t uid = getuid();
    gid_t gid = getgid();

    /* In user NS, we might appear as root (uid 0) */
    int result = 0;
    if (uid == 0) result |= 1; /* Appears as root */
    if (gid == 0) result |= 2; /* Root group */
    if (pid == 1) result |= 4; /* PID 1 (init in PID NS) */

    (void)cred; /* Suppress unused warning */

    return result;
}

/* Test 5: Abstract socket with credential check */
static int try_abstract_socket_cred(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* Abstract socket (first byte is \0) */
    snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,
             "cred_test_%d", getpid());

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 0;
    }

    listen(fd, 1);

    /* Connect from a child and check credentials */
    pid_t pid = fork();
    if (pid == 0) {
        int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
        connect(cfd, (struct sockaddr *)&addr, sizeof(addr));
        close(cfd);
        _exit(0);
    }
    if (pid < 0) { close(fd); return 0; }

    int afd = accept(fd, NULL, NULL);
    if (afd >= 0) {
        struct ucred peer;
        socklen_t len = sizeof(peer);
        if (getsockopt(afd, SOL_SOCKET, SO_PEERCRED, &peer, &len) == 0) {
            close(afd);
            close(fd);
            waitpid(pid, NULL, 0);
            return 1; /* Got peer credentials */
        }
        close(afd);
    }

    close(fd);
    waitpid(pid, NULL, 0);
    return 0;
}

/* Test 6: socketpair credential leak */
static int try_socketpair_cred_leak(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 0;

    struct ucred cred;
    socklen_t len = sizeof(cred);

    int ret = getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &cred, &len);
    close(sv[0]); close(sv[1]);

    if (ret != 0) return 0;

    /* Check if credentials reveal useful information */
    if (cred.pid > 0 && cred.uid >= 0) return 1;
    return 0;
}

/* Test 7: /proc/self/status uid/gid info */
static int try_proc_status_ids(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/status", buf, sizeof(buf));
    if (n <= 0) return 0;

    /* Check Uid/Gid lines */
    char *uid_line = strstr(buf, "Uid:");
    if (uid_line) {
        int real, eff, saved, fs;
        if (sscanf(uid_line + 4, "%d %d %d %d", &real, &eff, &saved, &fs) == 4) {
            /* Check if any are 0 (root) */
            if (real == 0 || eff == 0) return 2; /* Appears as root */
            return 1; /* Status readable */
        }
    }
    return 0;
}

/* Test 8: DirtyCred surface — open race condition probe */
static int try_dirtycred_surface(void) {
    /* DirtyCred exploits swap struct cred/struct file during
     * concurrent open() + fstat() operations. Test if the
     * racing pattern is possible. */
    int fd1 = open("/proc/self/status", O_RDONLY);
    if (fd1 < 0) return 0;

    struct stat st1, st2;
    if (fstat(fd1, &st1) < 0) { close(fd1); return 0; }

    /* Open another file quickly */
    int fd2 = open("/proc/self/maps", O_RDONLY);
    if (fd2 >= 0) {
        fstat(fd2, &st2);
        close(fd2);
    }

    close(fd1);

    /* If both opens worked, the racing surface exists */
    return (fd2 >= 0) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("CREDENTIAL SPOOFING & DIRTYCRED (CCS 2022)");

    int peercred = try_peercred();
    TEST("SO_PEERCRED reveals credentials (info)",
         1,
         peercred == 2 ? "reports as UID 0 (user NS root)" :
         peercred == 1 ? "credentials accessible" : "not available");

    int scm_cred = try_scm_credentials_send();
    TEST("SCM_CREDENTIALS send (info)",
         1,
         scm_cred ? "can send credentials" : "blocked");

    int passcred = try_passcred();
    TEST("SO_PASSCRED enable (info)",
         1,
         passcred ? "enabled" : "blocked");

    int ns_creds = try_ns_credentials();
    TEST("User NS credential mapping (info)",
         1,
         ns_creds & 1 ? "appears as UID 0 (user NS)" :
                        "non-root UID");

    int abstract_cred = try_abstract_socket_cred();
    TEST("Abstract socket credential check (info)",
         1,
         abstract_cred ? "peer creds available" : "not available");

    int sp_leak = try_socketpair_cred_leak();
    TEST("Socketpair credential leak (info)",
         1,
         sp_leak ? "credentials leaked via socketpair" : "not available");

    int proc_ids = try_proc_status_ids();
    TEST("/proc/self/status UID check (info)",
         1,
         proc_ids == 2 ? "reports as root (user NS)" :
         proc_ids == 1 ? "readable" : "blocked");

    int dirtycred = try_dirtycred_surface();
    TEST("DirtyCred race surface (info)",
         1,
         dirtycred ? "concurrent open() possible (expected)" : "limited");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
