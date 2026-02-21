/*
 * test_37_socket_options.c — SO_PEEK_OFF and socket option audit
 *
 * SO_PEEK_OFF is explicitly allowed in Chrome's baseline_policy.cc and was
 * part of the CVE-2025-38236 exploit chain. This test audits which socket
 * options are accessible from the sandbox.
 *
 * Key socket options for exploit chains:
 *  - SO_PEEK_OFF: arbitrary offset peek into socket buffer
 *  - SO_SNDBUF/SO_RCVBUF: control kernel buffer sizes (heap spray)
 *  - SO_PRIORITY: needs CAP_NET_ADMIN for high values
 *  - SO_BINDTODEVICE: network namespace escape
 *  - SO_ATTACH_FILTER: BPF on socket (cBPF code execution)
 *  - SO_REUSEADDR/SO_REUSEPORT: socket hijacking
 *  - TCP_REPAIR: TCP state manipulation (needs CAP_NET_ADMIN)
 *
 * Tests:
 *  1. SO_PEEK_OFF (CVE-2025-38236 primitive)
 *  2. SO_SNDBUF/SO_RCVBUF size manipulation
 *  3. SO_ATTACH_FILTER (cBPF on socket)
 *  4. SO_REUSEADDR/SO_REUSEPORT
 *  5. SO_PRIORITY
 *  6. SO_BINDTODEVICE
 *  7. SO_KEEPALIVE and TCP options
 *  8. IP_OPTIONS / IPV6 options
 */
#include "test_harness.h"

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF 42
#endif

/* Test 1: SO_PEEK_OFF */
static int try_so_peek_off(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    int val = 0;
    int ret = setsockopt(sv[0], SOL_SOCKET, SO_PEEK_OFF, &val, sizeof(val));

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 2: SO_SNDBUF/SO_RCVBUF size manipulation */
static int try_buf_size(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    /* Try to set a large send buffer */
    int big_buf = 4 * 1024 * 1024; /* 4MB */
    int ret1 = setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big_buf, sizeof(big_buf));
    int ret2 = setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &big_buf, sizeof(big_buf));

    /* Read back actual size */
    int actual = 0;
    socklen_t len = sizeof(actual);
    getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &actual, &len);

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return (ret1 == 0 || ret2 == 0) ? actual : 0;
}

/* Test 3: SO_ATTACH_FILTER (cBPF on socket) */
static int try_attach_filter(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    /* Simple BPF: accept all */
    struct sock_filter filter[] = {
        { 0x06, 0, 0, 0x00040000 }, /* ret 256K — accept */
    };
    struct sock_fprog prog = {
        .len = 1,
        .filter = filter,
    };

    int ret = setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 4: SO_REUSEADDR/SO_REUSEPORT */
static int try_reuse_opts(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    int val = 1;
    int ret1 = setsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    int ret2 = setsockopt(sv[0], SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return ((ret1 == 0) ? 1 : 0) | ((ret2 == 0) ? 2 : 0);
}

/* Test 5: SO_PRIORITY */
static int try_so_priority(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    /* High priority needs CAP_NET_ADMIN */
    int val = 7; /* TC_PRIO_CONTROL */
    int ret = setsockopt(sv[0], SOL_SOCKET, SO_PRIORITY, &val, sizeof(val));

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 6: SO_BINDTODEVICE */
static int try_bindtodevice(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    const char *dev = "lo";
    int ret = setsockopt(sv[0], SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev) + 1);

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 7: SO_KEEPALIVE and TCP options */
static int try_keepalive(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    int val = 1;
    int ret1 = setsockopt(sv[0], SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));

    /* Try SO_LINGER */
    struct linger ling = {1, 5};
    int ret2 = setsockopt(sv[0], SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return ((ret1 == 0) ? 1 : 0) | ((ret2 == 0) ? 2 : 0);
}

/* Test 8: IP-level socket options (need AF_INET socket) */
static int try_ip_options(void) {
    g_got_sigsys = 0;
    /* Try to create AF_INET socket — may be blocked */
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_got_sigsys) return -2;
    if (sock < 0) return 0; /* AF_INET blocked — good */

    /* Try IP_OPTIONS */
    char opts[4] = {0};
    int ret = setsockopt(sock, IPPROTO_IP, IP_OPTIONS, opts, sizeof(opts));

    close(sock);
    return (ret == 0) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SOCKET OPTION AUDIT (CVE-2025-38236)");

    int peek = try_so_peek_off();
    TEST("SO_PEEK_OFF (info — CVE-2025-38236 primitive)",
         1, /* SO_PEEK_OFF is widely allowed */
         peek == 1  ? "available (Chrome allows — exploit primitive)" :
         peek == -2 ? "SIGSYS" : "not available");

    int bufsz = try_buf_size();
    TEST("SO_SNDBUF/SO_RCVBUF (info)",
         1,
         bufsz > 0 ? "set to %d bytes (heap spray sizing)" :
         bufsz == -2 ? "SIGSYS" : "blocked", bufsz);

    int bpf = try_attach_filter();
    TEST("SO_ATTACH_FILTER blocked",
         bpf <= 0,
         bpf == 1  ? "ATTACHED — cBPF on socket!" :
         bpf == -2 ? "SIGSYS" : "blocked");

    int reuse = try_reuse_opts();
    TEST("SO_REUSEADDR/REUSEPORT (info)",
         1,
         reuse == 3 ? "both available" :
         reuse == 1 ? "REUSEADDR only" :
         reuse == 2 ? "REUSEPORT only" : "neither");

    int prio = try_so_priority();
    TEST("SO_PRIORITY high value (info)",
         1,
         prio == 1  ? "set (may need CAP_NET_ADMIN for >6)" :
         prio == -2 ? "SIGSYS" : "blocked");

    int bind_dev = try_bindtodevice();
    TEST("SO_BINDTODEVICE blocked",
         bind_dev <= 0,
         bind_dev == 1  ? "BOUND — device binding without CAP_NET_RAW!" :
         bind_dev == -2 ? "SIGSYS" : "blocked (needs CAP_NET_RAW)");

    int keepalive = try_keepalive();
    TEST("SO_KEEPALIVE/SO_LINGER (info)",
         1,
         keepalive == 3 ? "both available" :
         keepalive == 1 ? "keepalive only" :
         keepalive == 2 ? "linger only" : "neither");

    int ip = try_ip_options();
    TEST("AF_INET + IP_OPTIONS blocked",
         ip <= 0,
         ip == 1  ? "IP_OPTIONS set — IP header manipulation!" :
         ip == -2 ? "SIGSYS" : "blocked (no AF_INET socket)");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
