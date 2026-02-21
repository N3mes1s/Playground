/*
 * test_48_network_raw.c — Raw socket, packet socket, and netlink access tests
 *
 * Raw network access from a sandbox is critical for:
 *  - AF_PACKET: Raw L2 frame injection/sniffing (ARP spoofing, etc.)
 *  - SOCK_RAW: Raw IP socket (ICMP, custom protocols)
 *  - AF_NETLINK NETLINK_KOBJECT_UEVENT: Device hotplug event injection
 *  - AF_NETLINK NETLINK_ROUTE: Routing table manipulation
 *  - AF_NETLINK NETLINK_AUDIT: Audit system manipulation
 *  - AF_NETLINK NETLINK_CONNECTOR: Kernel connector interface
 *  - SO_MARK: Packet marking for netfilter bypass
 *  - IP_TRANSPARENT: Transparent proxy setup
 *
 * Tests:
 *  1. AF_PACKET socket creation
 *  2. AF_INET SOCK_RAW (IPPROTO_ICMP)
 *  3. AF_NETLINK NETLINK_KOBJECT_UEVENT
 *  4. AF_NETLINK NETLINK_ROUTE
 *  5. AF_NETLINK NETLINK_AUDIT
 *  6. SO_MARK on socket
 *  7. IP_TRANSPARENT on socket
 *  8. AF_INET6 raw socket
 */
#include "test_harness.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifndef NETLINK_CONNECTOR
#define NETLINK_CONNECTOR 11
#endif
#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT 15
#endif
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef SO_MARK
#define SO_MARK 36
#endif

/* Test 1: AF_PACKET socket creation */
static int try_af_packet(void) {
    g_got_sigsys = 0;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003 /* ETH_P_ALL */));
    if (g_got_sigsys) return -2;
    if (sock >= 0) {
        close(sock);
        return 1; /* Raw packet access! */
    }
    if (errno == EPERM) return 0;
    if (errno == EACCES) return 0;
    return 0;
}

/* Test 2: AF_INET SOCK_RAW (IPPROTO_ICMP) */
static int try_raw_icmp(void) {
    g_got_sigsys = 0;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (g_got_sigsys) return -2;
    if (sock >= 0) {
        close(sock);
        return 1; /* Raw ICMP socket! */
    }
    if (errno == EPERM) return 0;
    if (errno == EACCES) return 0;
    return 0;
}

/* Test 3: AF_NETLINK NETLINK_KOBJECT_UEVENT */
static int try_netlink_uevent(void) {
    g_got_sigsys = 0;
    int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (g_got_sigsys) return -2;
    if (sock >= 0) {
        /* Try to bind to listen for uevents */
        struct sockaddr_nl addr = {
            .nl_family = AF_NETLINK,
            .nl_groups = 1, /* Kernel events */
        };
        int bound = (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);
        close(sock);
        return bound ? 2 : 1; /* 2 = bound to events, 1 = socket created */
    }
    return 0;
}

/* Test 4: AF_NETLINK NETLINK_ROUTE */
static int try_netlink_route(void) {
    g_got_sigsys = 0;
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (g_got_sigsys) return -2;
    if (sock >= 0) {
        /* Try to get routing table */
        struct {
            struct nlmsghdr nlh;
            struct rtmsg rtm;
        } req;
        memset(&req, 0, sizeof(req));
        req.nlh.nlmsg_len = sizeof(req);
        req.nlh.nlmsg_type = RTM_GETROUTE;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.rtm.rtm_family = AF_INET;

        struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
        ssize_t sent = sendto(sock, &req, sizeof(req), 0,
                             (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
        return (sent > 0) ? 2 : 1; /* 2 = queried routes, 1 = socket only */
    }
    return 0;
}

/* Test 5: AF_NETLINK NETLINK_AUDIT */
static int try_netlink_audit(void) {
    g_got_sigsys = 0;
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
    if (g_got_sigsys) return -2;
    if (sock >= 0) {
        close(sock);
        return 1; /* Audit netlink socket! */
    }
    return 0;
}

/* Test 6: SO_MARK on socket */
static int try_so_mark(void) {
    g_got_sigsys = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 0;

    int mark = 0x1337;
    int ret = setsockopt(sv[0], SOL_SOCKET, SO_MARK, &mark, sizeof(mark));

    close(sv[0]);
    close(sv[1]);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 7: IP_TRANSPARENT */
static int try_ip_transparent(void) {
    g_got_sigsys = 0;
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_got_sigsys) return -2;
    if (sock < 0) return 0;

    int val = 1;
    int ret = setsockopt(sock, SOL_IP, IP_TRANSPARENT, &val, sizeof(val));

    close(sock);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 8: AF_INET6 raw socket */
static int try_raw_ipv6(void) {
    g_got_sigsys = 0;
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (g_got_sigsys) return -2;
    if (sock >= 0) {
        close(sock);
        return 1; /* Raw ICMPv6 socket! */
    }
    if (errno == EPERM) return 0;
    if (errno == EACCES) return 0;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("RAW NETWORK & NETLINK ACCESS");

    int packet = try_af_packet();
    TEST("AF_PACKET socket blocked",
         packet <= 0,
         packet == 1  ? "CREATED — raw L2 frame access!" :
         packet == -2 ? "SIGSYS" : "blocked");

    int raw = try_raw_icmp();
    TEST("AF_INET SOCK_RAW (ICMP) blocked",
         raw <= 0,
         raw == 1  ? "CREATED — raw ICMP socket!" :
         raw == -2 ? "SIGSYS" : "blocked");

    int uevent = try_netlink_uevent();
    TEST("NETLINK_KOBJECT_UEVENT blocked",
         uevent <= 0,
         uevent == 2  ? "BOUND — device event injection!" :
         uevent == 1  ? "CREATED — uevent socket (not bound)" :
         uevent == -2 ? "SIGSYS" : "blocked");

    int route = try_netlink_route();
    TEST("NETLINK_ROUTE (info)",
         1,
         route == 2  ? "queried routing table" :
         route == 1  ? "socket created" :
         route == -2 ? "SIGSYS" : "blocked");

    int audit = try_netlink_audit();
    TEST("NETLINK_AUDIT blocked",
         audit <= 0,
         audit == 1  ? "CREATED — audit system access!" :
         audit == -2 ? "SIGSYS" : "blocked");

    int mark = try_so_mark();
    TEST("SO_MARK blocked",
         mark <= 0,
         mark == 1  ? "SET — packet marking (netfilter bypass)!" :
         mark == -2 ? "SIGSYS" : "blocked (needs CAP_NET_ADMIN)");

    int transp = try_ip_transparent();
    TEST("IP_TRANSPARENT blocked",
         transp <= 0,
         transp == 1  ? "SET — transparent proxy from sandbox!" :
         transp == -2 ? "SIGSYS" : "blocked");

    int ipv6 = try_raw_ipv6();
    TEST("AF_INET6 SOCK_RAW blocked",
         ipv6 <= 0,
         ipv6 == 1  ? "CREATED — raw IPv6 socket!" :
         ipv6 == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
