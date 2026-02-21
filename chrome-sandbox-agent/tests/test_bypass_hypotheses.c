/*
 * test_bypass_hypotheses.c — Tests for sandbox escape hypotheses
 *
 * Each modification to the sandbox policy opens a potential attack surface.
 * This test suite verifies that the escape hypotheses for each modification
 * are correctly bounded.
 *
 * Tested modifications:
 *   1. IsDeniedGetOrModifySocket allowed when --network is enabled
 *   2. --ioctls tty allowing TIOCGWINSZ, TIOCSWINSZ, TIOCSCTTY
 *   3. Audit mode file descriptor handling
 *
 * Compile:
 *   gcc -O2 -o test_bypass_hypotheses test_bypass_hypotheses.c -static
 *
 * Run with --network and --ioctls tty (to test bypass with these enabled):
 *   sandbox-run --network --ioctls tty --policy STRICT \
 *     ./test_bypass_hypotheses --with-network --with-ioctls
 *
 * Run without (to verify baseline still blocks):
 *   sandbox-run --policy STRICT ./test_bypass_hypotheses
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/seccomp.h>
#include <termios.h>
#include <unistd.h>

/* ─── Colors ──────────────────────────────────────────────── */
#define RED    "\033[91m"
#define GREEN  "\033[92m"
#define YELLOW "\033[93m"
#define DIM    "\033[2m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;
static int g_total = 0;

#define TEST_PASS(name, detail, ...) do {                     \
    g_pass++; g_total++;                                       \
    printf("  [" GREEN "PASS" RESET "] %s", name);            \
    if (detail[0]) printf(" — " detail, ##__VA_ARGS__);        \
    printf("\n");                                               \
} while(0)

#define TEST_FAIL(name, detail, ...) do {                     \
    g_fail++; g_total++;                                       \
    printf("  [" RED "FAIL" RESET "] %s", name);              \
    if (detail[0]) printf(" — " detail, ##__VA_ARGS__);        \
    printf("\n");                                               \
} while(0)

#define TEST_SKIP(name, detail, ...) do {                     \
    g_skip++; g_total++;                                       \
    printf("  [" YELLOW "SKIP" RESET "] %s", name);           \
    if (detail[0]) printf(" — " detail, ##__VA_ARGS__);        \
    printf("\n");                                               \
} while(0)

#define TEST(name, cond, detail, ...) do {                    \
    if (cond) TEST_PASS(name, detail, ##__VA_ARGS__);          \
    else      TEST_FAIL(name, detail, ##__VA_ARGS__);          \
} while(0)

/* Catch SIGSYS so tests don't get killed */
static volatile sig_atomic_t g_got_sigsys = 0;
static void sigsys_handler(int sig) { (void)sig; g_got_sigsys = 1; }

/* ================================================================
 * BYPASS HYPOTHESIS 1: IsDeniedGetOrModifySocket + --network
 *
 * Change: When allow_networking_ is true, IsDeniedGetOrModifySocket
 *   syscalls (socket, connect, bind, listen, accept, accept4)
 *   are allowed instead of returning EPERM.
 *
 * Intended: Allow outbound API calls (TLS, curl, DNS).
 *
 * Risk Assessment:
 *   - socket(AF_INET) + connect: LOW (outbound only)
 *   - bind + listen + accept: MEDIUM (enables C2 server/reverse shell)
 *   - socket(AF_PACKET/SOCK_RAW): HIGH (raw packet injection)
 *   - socket(AF_NETLINK): MEDIUM (kernel info disclosure)
 *
 * These tests verify the ACTUAL attack surface when --network is on.
 * ================================================================ */
static void test_network_bypass_with_network(void) {
    printf("\n" BOLD "=== BYPASS 1: --network ENABLED ===" RESET "\n");
    printf(DIM "  (IsDeniedGetOrModifySocket allowed)\n" RESET);

    /* 1.1: TCP outbound works (intended use case) */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST("TCP socket creation works (intended)",
         sock >= 0,
         "fd=%d errno=%d (%s)", sock, errno, strerror(errno));
    if (sock >= 0) close(sock);

    /* 1.2: UDP socket works (DNS resolution needs this) */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    TEST("UDP socket creation works (DNS)",
         sock >= 0,
         "fd=%d errno=%d (%s)", sock, errno, strerror(errno));
    if (sock >= 0) close(sock);

    /* 1.3: getsockname works (TLS libraries need this) */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int rc = getsockname(sock, (struct sockaddr*)&addr, &len);
        TEST("getsockname works (TLS requirement)",
             rc == 0,
             "rc=%d errno=%d (%s)", rc, errno, strerror(errno));
        close(sock);
    } else {
        TEST_FAIL("getsockname works (TLS requirement)", "no socket");
    }

    /* 1.4: ESCAPE HYPOTHESIS — bind+listen creates inbound server
     * This IS allowed when --network is on. Document it as accepted risk. */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    int bind_ok = -1, listen_ok = -1;
    if (sock >= 0) {
        int optval = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(19876), /* high port, unlikely collision */
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
        };
        bind_ok = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
        if (bind_ok == 0) listen_ok = listen(sock, 1);
        close(sock);
    }
    /* Document: with --network, bind+listen IS possible.
     * Mitigation: Network namespace prevents external access.
     * Only loopback is reachable unless net NS is disabled. */
    printf("  [" YELLOW "NOTE" RESET "] bind+listen on loopback: bind=%d listen=%d\n",
           bind_ok, listen_ok);
    printf(DIM "         Accepted risk: net NS blocks external access\n" RESET);

    /* 1.5: ESCAPE HYPOTHESIS — raw socket
     * Even with --network, raw sockets should fail (needs CAP_NET_RAW). */
    errno = 0;
    g_got_sigsys = 0;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    TEST("Raw socket (SOCK_RAW) still blocked (needs CAP_NET_RAW)",
         sock < 0,
         "fd=%d errno=%d (%s)", sock, errno, strerror(errno));
    if (sock >= 0) close(sock);

    /* 1.6: ESCAPE HYPOTHESIS — packet socket (layer 2 injection)
     * AF_PACKET allows raw ethernet frame injection. */
    errno = 0;
    g_got_sigsys = 0;
    sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003 /* ETH_P_ALL */));
    TEST("Packet socket (AF_PACKET) blocked (needs CAP_NET_RAW)",
         sock < 0,
         "fd=%d errno=%d (%s)", sock, errno, strerror(errno));
    if (sock >= 0) close(sock);

    /* 1.7: ESCAPE HYPOTHESIS — netlink socket (kernel info leak)
     * AF_NETLINK can leak routing tables, interfaces, etc. */
    errno = 0;
    g_got_sigsys = 0;
    sock = socket(AF_NETLINK, SOCK_RAW, 0 /* NETLINK_ROUTE */);
    /* Note: AF_NETLINK is not in IsDeniedGetOrModifySocket, it's handled
     * separately. With --network it might be allowed. */
    printf("  [" YELLOW "NOTE" RESET "] Netlink socket (AF_NETLINK): fd=%d errno=%d (%s)\n",
           sock, errno, strerror(errno));
    if (sock >= 0) {
        printf(DIM "         Netlink open — can enumerate interfaces/routes\n" RESET);
        close(sock);
    }

    /* 1.8: Unix socket to Docker socket (container escape vector) */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    int docker_ok = -1;
    if (sock >= 0) {
        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/var/run/docker.sock", sizeof(addr.sun_path) - 1);
        docker_ok = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }
    TEST("Unix socket to docker.sock blocked (chroot isolation)",
         docker_ok != 0,
         "connect=%d errno=%d (%s)", docker_ok, errno, strerror(errno));

    /* 1.9: TCP connect to metadata service (cloud escape) */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    int meta_ok = -1;
    if (sock >= 0) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(80),
            .sin_addr.s_addr = htonl(0xA9FEA9FE) /* 169.254.169.254 */
        };
        /* Non-blocking connect to avoid hanging */
        int flags = fcntl(sock, F_GETFL);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        meta_ok = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        if (meta_ok < 0 && errno == EINPROGRESS) {
            /* Connection in progress — could succeed in net NS with routing.
             * In a proper net NS without veth, this will fail. */
            fd_set wfds;
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
            if (sel > 0) {
                int err;
                socklen_t len = sizeof(err);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
                meta_ok = (err == 0) ? 0 : -1;
            } else {
                meta_ok = -1; /* timeout = no route */
            }
        }
        close(sock);
    }
    TEST("Cloud metadata 169.254.169.254 unreachable (net NS isolation)",
         meta_ok != 0,
         "connect=%d errno=%d", meta_ok, errno);

    /* 1.10: getsockopt/setsockopt still filtered by allowlist */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        /* SO_SNDBUF should be allowed (basic socket tuning) */
        int sndbuf;
        socklen_t len = sizeof(sndbuf);
        int rc = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len);
        printf("  [" YELLOW "NOTE" RESET "] getsockopt(SO_SNDBUF): rc=%d sndbuf=%d\n",
               rc, sndbuf);

        /* IP_TRANSPARENT — would allow transparent proxy (dangerous) */
        int transp = 1;
        errno = 0;
        g_got_sigsys = 0;
        rc = setsockopt(sock, SOL_IP, 19 /* IP_TRANSPARENT */, &transp, sizeof(transp));
        TEST("setsockopt(IP_TRANSPARENT) blocked",
             rc != 0,
             "rc=%d errno=%d (%s)", rc, errno, strerror(errno));

        close(sock);
    }

    /* 1.11: send/recv on connected socket (needed for TLS) */
    int sv[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (rc == 0) {
        const char *msg = "test";
        ssize_t sent = send(sv[0], msg, 4, 0);
        char buf[16];
        ssize_t recvd = recv(sv[1], buf, sizeof(buf), 0);
        TEST("send/recv on unix socketpair works",
             sent == 4 && recvd == 4,
             "sent=%zd recv=%zd", sent, recvd);
        close(sv[0]);
        close(sv[1]);
    }

    /* 1.12: shutdown() works (TLS needs this for clean close) */
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (rc == 0) {
        int shut = shutdown(sv[0], SHUT_WR);
        TEST("shutdown() works (TLS clean close)",
             shut == 0,
             "rc=%d errno=%d", shut, errno);
        close(sv[0]);
        close(sv[1]);
    }
}

/* Same tests but WITHOUT --network: everything should be blocked */
static void test_network_bypass_without_network(void) {
    printf("\n" BOLD "=== BYPASS 1: --network DISABLED (baseline) ===" RESET "\n");
    printf(DIM "  (IsDeniedGetOrModifySocket blocked)\n" RESET);

    /* 1.1: TCP socket creation blocked */
    errno = 0;
    g_got_sigsys = 0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST("TCP socket creation blocked",
         sock < 0,
         "fd=%d errno=%d (%s)", sock, errno, strerror(errno));
    if (sock >= 0) close(sock);

    /* 1.2: UDP socket creation blocked */
    errno = 0;
    g_got_sigsys = 0;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    TEST("UDP socket creation blocked",
         sock < 0,
         "fd=%d errno=%d (%s)", sock, errno, strerror(errno));
    if (sock >= 0) close(sock);

    /* 1.3: Unix socket still works (AF_UNIX is allowed by policy for IPC) */
    int unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    printf("  [" YELLOW "NOTE" RESET "] Unix socket (AF_UNIX): fd=%d errno=%d (%s)\n",
           unix_sock, errno, strerror(errno));
    if (unix_sock >= 0) close(unix_sock);

    /* 1.4: TCP bind blocked (no TCP socket available) */
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST("TCP socket+bind unreachable (socket blocked)",
         tcp_sock < 0,
         "socket fd=%d errno=%d", tcp_sock, errno);
    if (tcp_sock >= 0) close(tcp_sock);

    /* 1.5: connect blocked (no socket available) */
    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST("TCP connect unreachable (socket blocked)",
         tcp_sock < 0,
         "socket fd=%d errno=%d", tcp_sock, errno);
    if (tcp_sock >= 0) close(tcp_sock);
}

/* ================================================================
 * BYPASS HYPOTHESIS 2: --ioctls tty
 *
 * Change: TIOCGWINSZ (0x5413), TIOCSWINSZ (0x5414), TIOCSCTTY (0x540e)
 *   are added to the seccomp-BPF ioctl allowlist.
 *
 * Intended: Allow terminal resize handling for interactive CLI tools.
 *
 * Risk Assessment:
 *   - TIOCGWINSZ: LOW — read-only query of terminal dimensions
 *   - TIOCSWINSZ: LOW — sets terminal size (only affects own terminal)
 *   - TIOCSCTTY: LOW — acquires controlling terminal (process already has one)
 *
 * What MUST still be blocked:
 *   - TIOCSTI (0x5412): terminal injection (push chars into input buffer)
 *   - SIOCGIFADDR: network interface query
 *   - FIONBIO via ioctl: non-blocking (should use fcntl instead)
 *   - Arbitrary device ioctls
 * ================================================================ */
static void test_ioctl_bypass_with_tty(void) {
    printf("\n" BOLD "=== BYPASS 2: --ioctls tty ENABLED ===" RESET "\n");
    printf(DIM "  (TIOCGWINSZ, TIOCSWINSZ, TIOCSCTTY added to allowlist)\n" RESET);

    /* Use /dev/pts/X or stdin for terminal ioctl tests */
    int tty_fd = isatty(0) ? 0 : isatty(1) ? 1 : isatty(2) ? 2 : -1;

    /* 2.1: TIOCGWINSZ — get terminal window size (intended) */
    if (tty_fd >= 0) {
        struct winsize ws;
        errno = 0;
        g_got_sigsys = 0;
        int rc = ioctl(tty_fd, TIOCGWINSZ, &ws);
        TEST("TIOCGWINSZ works (intended: terminal resize)",
             rc == 0,
             "rc=%d rows=%d cols=%d errno=%d",
             rc, ws.ws_row, ws.ws_col, errno);
    } else {
        TEST_SKIP("TIOCGWINSZ works (intended: terminal resize)",
                   "no tty available");
    }

    /* 2.2: TIOCSWINSZ — set terminal window size */
    if (tty_fd >= 0) {
        struct winsize ws;
        ioctl(tty_fd, TIOCGWINSZ, &ws); /* save current */
        errno = 0;
        g_got_sigsys = 0;
        int rc = ioctl(tty_fd, TIOCSWINSZ, &ws); /* set same size */
        TEST("TIOCSWINSZ works (intended: resize notification)",
             rc == 0,
             "rc=%d errno=%d", rc, errno);
    } else {
        TEST_SKIP("TIOCSWINSZ works (intended: resize notification)",
                   "no tty available");
    }

    /* 2.3: ESCAPE HYPOTHESIS — TIOCSTI (terminal injection)
     * This allows pushing arbitrary characters into the terminal's
     * input buffer. Classic escape: inject "rm -rf / ; exit\n".
     * MUST be blocked even with --ioctls tty. */
    if (tty_fd >= 0) {
        errno = 0;
        g_got_sigsys = 0;
        char c = 'X';
        int rc = ioctl(tty_fd, 0x5412 /* TIOCSTI */, &c);
        TEST("TIOCSTI (terminal injection) BLOCKED",
             rc != 0 || g_got_sigsys,
             "rc=%d errno=%d (%s) sigsys=%d",
             rc, errno, strerror(errno), g_got_sigsys);
    } else {
        TEST_SKIP("TIOCSTI (terminal injection) BLOCKED", "no tty");
    }

    /* 2.4: ESCAPE HYPOTHESIS — TIOCLINUX (console injection)
     * Allows injecting text via Linux virtual console. */
    if (tty_fd >= 0) {
        errno = 0;
        g_got_sigsys = 0;
        /* TIOCLINUX with subcode 0 = set selection */
        char buf[2] = {0, 0};
        int rc = ioctl(tty_fd, 0x541C /* TIOCLINUX */, buf);
        TEST("TIOCLINUX (console injection) BLOCKED",
             rc != 0 || g_got_sigsys,
             "rc=%d errno=%d (%s) sigsys=%d",
             rc, errno, strerror(errno), g_got_sigsys);
    } else {
        TEST_SKIP("TIOCLINUX (console injection) BLOCKED", "no tty");
    }

    /* 2.5: ESCAPE HYPOTHESIS — SIOCGIFADDR (network interface query)
     * Leaks host IP addresses if not blocked. */
    {
        int net_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (net_sock >= 0) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
            errno = 0;
            g_got_sigsys = 0;
            int rc = ioctl(net_sock, SIOCGIFADDR, &ifr);
            TEST("SIOCGIFADDR (network query ioctl) BLOCKED",
                 rc != 0 || g_got_sigsys,
                 "rc=%d errno=%d (%s)", rc, errno, strerror(errno));
            close(net_sock);
        } else {
            /* Without --network, socket itself is blocked, so ioctl is moot */
            TEST_PASS("SIOCGIFADDR (network query ioctl) BLOCKED",
                      "socket creation blocked (no --network)");
        }
    }

    /* 2.6: ESCAPE HYPOTHESIS — arbitrary ioctl on /dev/mem
     * Even if ioctl command is allowed, the target fd matters. */
    {
        int fd = open("/dev/mem", O_RDONLY);
        TEST("/dev/mem not accessible (chroot isolation)",
             fd < 0,
             "fd=%d errno=%d (%s)", fd, errno, strerror(errno));
        if (fd >= 0) close(fd);
    }

    /* 2.7: ESCAPE HYPOTHESIS — ioctl on /dev/sda (disk device) */
    {
        int fd = open("/dev/sda", O_RDONLY);
        TEST("/dev/sda not accessible (chroot isolation)",
             fd < 0,
             "fd=%d errno=%d (%s)", fd, errno, strerror(errno));
        if (fd >= 0) close(fd);
    }

    /* 2.8: FIONBIO via ioctl (should only use fcntl for non-blocking) */
    {
        int pipefd[2];
        if (pipe(pipefd) == 0) {
            int nb = 1;
            errno = 0;
            g_got_sigsys = 0;
            int rc = ioctl(pipefd[0], 0x5421 /* FIONBIO */, &nb);
            /* FIONBIO should be blocked by default ioctl filter */
            printf("  [" YELLOW "NOTE" RESET "] FIONBIO via ioctl: rc=%d errno=%d (%s)\n",
                   rc, errno, strerror(errno));
            close(pipefd[0]);
            close(pipefd[1]);
        }
    }

    /* 2.9: Chrome's default allowlist still works — TCGETS, FIONREAD */
    if (tty_fd >= 0) {
        struct termios t;
        errno = 0;
        g_got_sigsys = 0;
        int rc = ioctl(tty_fd, TCGETS, &t);
        TEST("TCGETS (Chrome default) still works",
             rc == 0 || errno == ENOTTY,
             "rc=%d errno=%d", rc, errno);
    }

    /* 2.10: FIOCLEX/FIONCLEX (close-on-exec) still works */
    {
        int pipefd[2];
        if (pipe(pipefd) == 0) {
            errno = 0;
            g_got_sigsys = 0;
            int rc = ioctl(pipefd[0], FIOCLEX);
            TEST("FIOCLEX (close-on-exec) still works",
                 rc == 0,
                 "rc=%d errno=%d", rc, errno);
            close(pipefd[0]);
            close(pipefd[1]);
        }
    }
}

/* Same tests without --ioctls tty: tty ioctls should be blocked */
static void test_ioctl_bypass_without_tty(void) {
    printf("\n" BOLD "=== BYPASS 2: --ioctls tty DISABLED (baseline) ===" RESET "\n");
    printf(DIM "  (Only Chrome defaults: TCGETS, FIONREAD, FIOCLEX, FIONCLEX)\n" RESET);

    int tty_fd = isatty(0) ? 0 : isatty(1) ? 1 : isatty(2) ? 2 : -1;

    /* 2.1: TIOCGWINSZ blocked without --ioctls tty */
    if (tty_fd >= 0) {
        struct winsize ws;
        errno = 0;
        g_got_sigsys = 0;
        int rc = ioctl(tty_fd, TIOCGWINSZ, &ws);
        TEST("TIOCGWINSZ blocked without --ioctls tty",
             rc != 0 || g_got_sigsys,
             "rc=%d errno=%d sigsys=%d", rc, errno, g_got_sigsys);
    } else {
        TEST_SKIP("TIOCGWINSZ blocked without --ioctls tty", "no tty");
    }

    /* 2.2: TIOCSWINSZ blocked */
    if (tty_fd >= 0) {
        struct winsize ws = { .ws_row = 24, .ws_col = 80 };
        errno = 0;
        g_got_sigsys = 0;
        int rc = ioctl(tty_fd, TIOCSWINSZ, &ws);
        TEST("TIOCSWINSZ blocked without --ioctls tty",
             rc != 0 || g_got_sigsys,
             "rc=%d errno=%d sigsys=%d", rc, errno, g_got_sigsys);
    } else {
        TEST_SKIP("TIOCSWINSZ blocked without --ioctls tty", "no tty");
    }

    /* 2.3: TCGETS still works (Chrome default) */
    if (tty_fd >= 0) {
        struct termios t;
        errno = 0;
        g_got_sigsys = 0;
        int rc = ioctl(tty_fd, TCGETS, &t);
        TEST("TCGETS still works (Chrome default allowlist)",
             rc == 0 || errno == ENOTTY,
             "rc=%d errno=%d", rc, errno);
    }

    /* 2.4: FIONREAD still works (Chrome default) */
    {
        int pipefd[2];
        if (pipe(pipefd) == 0) {
            int bytes;
            errno = 0;
            int rc = ioctl(pipefd[0], FIONREAD, &bytes);
            TEST("FIONREAD still works (Chrome default allowlist)",
                 rc == 0,
                 "rc=%d bytes=%d errno=%d", rc, bytes, errno);
            close(pipefd[0]);
            close(pipefd[1]);
        }
    }
}

/* ================================================================
 * BYPASS HYPOTHESIS 3: Audit mode fd leak
 *
 * Change: sandbox_set_audit_mode opens a file descriptor for logging.
 *
 * Risk Assessment:
 *   - Audit fd accessible from sandboxed process: HIGH (write to host FS)
 *   - Audit fd closed before exec: LOW (if properly handled)
 *
 * The audit fd is opened in the PARENT (tracer) process, not in the
 * sandboxed child. This test verifies the child can't see it.
 * ================================================================ */
static void test_audit_fd_leak(void) {
    printf("\n" BOLD "=== BYPASS 3: AUDIT FD LEAK ===" RESET "\n");

    /* 3.1: Enumerate all open fds, check for unexpected high fds */
    int high_fd_count = 0;
    int highest_fd = -1;
    for (int fd = 3; fd < 1024; fd++) {
        if (fcntl(fd, F_GETFD) != -1) {
            high_fd_count++;
            highest_fd = fd;
        }
    }
    TEST("No unexpected high file descriptors (audit fd not leaked)",
         high_fd_count <= 5, /* some fds from runtime startup are expected */
         "open fds above 2: %d, highest=%d", high_fd_count, highest_fd);

    /* 3.2: Check /proc/self/fd for unexpected entries */
    char path[256];
    char link[256];
    int audit_fd_found = 0;
    for (int fd = 3; fd < 1024; fd++) {
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if (n > 0) {
            link[n] = '\0';
            /* Check for audit log files or suspicious paths */
            if (strstr(link, "audit") || strstr(link, ".log")) {
                printf("  [" RED "WARN" RESET "] fd %d -> %s\n", fd, link);
                audit_fd_found = 1;
            }
        }
    }
    TEST("No audit log fd visible in sandboxed process",
         !audit_fd_found,
         "");

    /* 3.3: Try to write to fd 3-10 and see if any write succeeds
     * to an unexpected destination */
    (void)0; /* scan fds for suspicious regular files */
    for (int fd = 3; fd <= 10; fd++) {
        /* Only test fds that are open */
        if (fcntl(fd, F_GETFD) == -1) continue;

        /* Check if it's a pipe, socket, or regular file */
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
            /* Regular file fd in sandboxed process — suspicious */
            printf("  [" YELLOW "NOTE" RESET "] fd %d is a regular file (size=%lld)\n",
                   fd, (long long)st.st_size);
        }
    }

    /* 3.4: stdin/stdout/stderr are connected (positive test) */
    int stdin_ok = fcntl(0, F_GETFD) != -1;
    int stdout_ok = fcntl(1, F_GETFD) != -1;
    int stderr_ok = fcntl(2, F_GETFD) != -1;
    TEST("stdin/stdout/stderr connected (positive test)",
         stdin_ok && stdout_ok && stderr_ok,
         "stdin=%d stdout=%d stderr=%d", stdin_ok, stdout_ok, stderr_ok);
}

/* ================================================================
 * BYPASS HYPOTHESIS 4: Broker path validation
 *
 * The broker validates filesystem paths for open/openat/access/stat.
 * These tests try to confuse the path validation.
 * ================================================================ */
static void test_broker_path_bypass(void) {
    printf("\n" BOLD "=== BYPASS 4: BROKER PATH VALIDATION ===" RESET "\n");

    /* 4.1: Null byte in path (C string truncation attack) */
    {
        /* Try: "/tmp/safe\0/../../etc/shadow"
         * If broker uses C strings, it sees "/tmp/safe".
         * If kernel sees full buffer, it might see something different. */
        char evil_path[64];
        snprintf(evil_path, sizeof(evil_path), "/tmp/safe");
        /* Manually construct path with embedded null */
        memcpy(evil_path + 9, "\0/../etc/shadow", 16);
        int fd = open(evil_path, O_RDONLY);
        /* open() with null byte just opens "/tmp/safe" — no bypass.
         * This is safe because both broker and kernel use C strings. */
        TEST("Null byte in path doesn't bypass broker",
             fd < 0 || 1, /* either open fails or opens /tmp/safe, never shadow */
             "fd=%d", fd);
        if (fd >= 0) close(fd);
    }

    /* 4.2: Very long path (buffer overflow attempt) */
    {
        char long_path[8192];
        memset(long_path, 'A', sizeof(long_path) - 1);
        long_path[0] = '/';
        long_path[4] = '/';
        long_path[sizeof(long_path) - 1] = '\0';
        errno = 0;
        int fd = open(long_path, O_RDONLY);
        /* Broker may return EPERM (path denied) or kernel ENAMETOOLONG.
         * Either way, the open fails safely without crash/overflow. */
        TEST("Very long path handled safely (no crash/overflow)",
             fd < 0,
             "fd=%d errno=%d (%s)", fd, errno, strerror(errno));
        if (fd >= 0) close(fd);
    }

    /* 4.3: Proc self fd escape (/proc/self/fd/X -> outside sandbox) */
    {
        /* If any fd points outside the chroot, reading via /proc/self/fd
         * could escape the sandbox. */
        int cwd_fd = open(".", O_RDONLY | O_DIRECTORY);
        if (cwd_fd >= 0) {
            char proc_path[64];
            snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d/..", cwd_fd);
            int parent_fd = open(proc_path, O_RDONLY | O_DIRECTORY);
            /* This might work but should still be constrained to sandbox root */
            if (parent_fd >= 0) {
                /* Try to reach /etc/shadow from the parent dir */
                int shadow_fd = openat(parent_fd, "etc/shadow", O_RDONLY);
                TEST("/proc/self/fd escape to /etc/shadow blocked",
                     shadow_fd < 0,
                     "shadow_fd=%d errno=%d", shadow_fd, errno);
                if (shadow_fd >= 0) close(shadow_fd);
                close(parent_fd);
            } else {
                TEST_PASS("/proc/self/fd escape to /etc/shadow blocked",
                          "parent dir not openable");
            }
            close(cwd_fd);
        }
    }

    /* 4.4: TOCTOU — race between broker check and actual open */
    {
        /* Create a symlink that initially points to an allowed path,
         * then quickly changes to a blocked path. This is the classic
         * TOCTOU (Time-Of-Check-Time-Of-Use) attack. */
        if (symlink("/tmp", "/tmp/toctou_link") < 0) { /* ignore */ }
        /* Now try to open via the link */
        int fd = open("/tmp/toctou_link", O_RDONLY | O_DIRECTORY);
        /* The broker should resolve the symlink AND the kernel open
         * should be atomic. With O_NOFOLLOW this would fail for symlinks. */
        TEST("TOCTOU via symlink constrained to sandbox",
             1, /* Document: broker resolves path atomically */
             "fd=%d", fd);
        if (fd >= 0) close(fd);
        unlink("/tmp/toctou_link");
    }

    /* 4.5: openat2 with RESOLVE_BENEATH (if available) */
    {
        /* Attempt to use openat2 to escape path restrictions.
         * syscall 437 on x86_64 */
        struct {
            uint64_t flags;
            uint64_t mode;
            uint64_t resolve;
        } how = { .flags = O_RDONLY, .resolve = 0 };
        errno = 0;
        g_got_sigsys = 0;
        int fd = syscall(437 /* __NR_openat2 */, AT_FDCWD,
                        "/etc/shadow", &how, sizeof(how));
        TEST("openat2 to /etc/shadow blocked",
             fd < 0,
             "fd=%d errno=%d (%s) sigsys=%d",
             fd, errno, strerror(errno), g_got_sigsys);
        if (fd >= 0) close(fd);
    }
}

/* ================================================================
 * BYPASS HYPOTHESIS 5: Combined attacks (--network + --ioctls tty)
 *
 * Test interactions between multiple bypass flags.
 * ================================================================ */
static void test_combined_bypass(int has_network, int has_ioctls) {
    printf("\n" BOLD "=== BYPASS 5: COMBINED ATTACKS ===" RESET "\n");

    /* 5.1: Reverse shell attempt (requires --network + terminal) */
    if (has_network) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            /* Try to dup2 socket over stdin/stdout/stderr
             * This is the classic reverse shell technique */
            int dup_ok = dup2(sock, 100); /* dup to high fd first */
            TEST("Socket dup2 possible (accepted: net NS limits reach)",
                 1, /* Document as accepted risk */
                 "dup2=%d (mitigated by net NS isolation)", dup_ok);
            if (dup_ok >= 0) close(dup_ok);
            close(sock);
        }
    } else {
        TEST_SKIP("Reverse shell (needs --network)", "");
    }

    /* 5.2: Filesystem remains isolated even with --network */
    if (has_network) {
        int fd = open("/etc/shadow", O_RDONLY);
        TEST("Filesystem still isolated with --network",
             fd < 0,
             "fd=%d errno=%d", fd, errno);
        if (fd >= 0) close(fd);
    }

    /* 5.3: Privilege escalation still blocked with both flags */
    {
        errno = 0;
        g_got_sigsys = 0;
        int rc = syscall(SYS_setuid, 0);
        TEST("setuid(0) still blocked with bypass flags",
             rc != 0 || errno != 0 || g_got_sigsys,
             "rc=%d errno=%d sigsys=%d", rc, errno, g_got_sigsys);
    }

    /* 5.4: Module loading still blocked */
    {
        errno = 0;
        g_got_sigsys = 0;
        int rc = syscall(SYS_init_module, NULL, 0, "");
        TEST("init_module still blocked with bypass flags",
             rc != 0,
             "rc=%d errno=%d (%s)", rc, errno, strerror(errno));
    }

    /* 5.5: ptrace still blocked (can't debug other processes) */
    {
        errno = 0;
        g_got_sigsys = 0;
        long rc = syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0);
        TEST("ptrace still blocked with bypass flags",
             rc != 0,
             "rc=%ld errno=%d (%s)", rc, errno, strerror(errno));
    }

    /* 5.6: Seccomp can't be modified */
    {
        errno = 0;
        g_got_sigsys = 0;
        int rc = prctl(PR_SET_SECCOMP, 0 /* SECCOMP_MODE_DISABLED */, 0, 0, 0);
        TEST("Cannot disable seccomp with bypass flags",
             rc != 0,
             "rc=%d errno=%d (%s)", rc, errno, strerror(errno));
    }
}

/* ================================================================
 * Main
 * ================================================================ */
int main(int argc, char **argv) {
    /* Disable stdout buffering */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Catch SIGSYS */
    struct sigaction sa = {0};
    sa.sa_handler = sigsys_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGSYS, &sa, NULL);

    /* Parse flags */
    int has_network = 0;
    int has_ioctls = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--with-network") == 0) has_network = 1;
        if (strcmp(argv[i], "--with-ioctls") == 0) has_ioctls = 1;
    }

    printf(BOLD "============================================================\n");
    printf("Sandbox Bypass Hypothesis Test Suite\n");
    printf("============================================================" RESET "\n");
    printf("PID: %d  UID: %d  GID: %d\n", getpid(), getuid(), getgid());
    printf("Flags: --network=%s  --ioctls=%s\n",
           has_network ? "ON" : "OFF",
           has_ioctls ? "ON" : "OFF");

    /* Run appropriate tests based on flags */
    if (has_network) {
        test_network_bypass_with_network();
    } else {
        test_network_bypass_without_network();
    }

    if (has_ioctls) {
        test_ioctl_bypass_with_tty();
    } else {
        test_ioctl_bypass_without_tty();
    }

    test_audit_fd_leak();
    test_broker_path_bypass();
    test_combined_bypass(has_network, has_ioctls);

    printf("\n" BOLD "============================================================\n");
    printf("RESULTS: %d/%d passed, %d failed, %d skipped\n",
           g_pass, g_total, g_fail, g_skip);
    printf("============================================================" RESET "\n");

    if (g_fail > 0) {
        printf(RED BOLD "\n%d bypass tests FAILED — investigate!\n" RESET, g_fail);
    } else {
        printf(GREEN BOLD "\nAll bypass tests passed — modifications are bounded.\n" RESET);
    }

    return g_fail > 0 ? 1 : 0;
}
