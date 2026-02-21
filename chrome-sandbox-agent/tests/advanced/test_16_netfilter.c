/*
 * test_16_netfilter.c — Netfilter/nftables kernel LPE vector tests
 *
 * Netfilter has been a goldmine for kernel LPE:
 *  - CVE-2024-1086: nf_tables UAF (99.4% success, v5.14-v6.6)
 *  - CVE-2024-26809: nft_pipapo double-free (no CAP_NET_ADMIN needed)
 *  - CVE-2023-32233: nf_tables batch UAF
 *  - CVE-2022-2586: nftables cross-table UAF
 *  - CVE-2021-22555: netfilter heap OOB write
 *
 * These bugs allow unprivileged LPE by creating nftables rules via
 * netlink sockets. The sandbox must block nfnetlink access.
 *
 * Tests:
 *  1. NETLINK_NETFILTER socket creation
 *  2. NETLINK_NFLOG socket
 *  3. NETLINK_ROUTE socket (for namespace manipulation)
 *  4. Raw netlink message to nf_tables
 *  5. AF_NETLINK with various protocols
 *  6. nft table creation attempt
 *  7. iptables socket (SOCK_RAW + IPPROTO_RAW)
 *  8. /proc/net/nf_conntrack access
 */
#include "test_harness.h"
#include <linux/netlink.h>

#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif
#ifndef NETLINK_NFLOG
#define NETLINK_NFLOG 5
#endif

/* Test 1: NETLINK_NETFILTER socket — the primary nftables attack surface */
static int try_nfnetlink(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* nfnetlink available — nftables LPE possible */
    }
    return 0;
}

/* Test 2: NETLINK_NFLOG socket */
static int try_nflog(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 3: NETLINK_ROUTE socket (used for network namespace escape) */
static int try_netlink_route(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 4: Try various AF_NETLINK protocols */
static int try_netlink_protocols(void) {
    int available = 0;
    /* Dangerous netlink protocols */
    int protocols[] = {
        0,  /* NETLINK_ROUTE */
        4,  /* NETLINK_FIREWALL */
        5,  /* NETLINK_NFLOG */
        6,  /* NETLINK_XFRM */
        7,  /* NETLINK_SELINUX */
        9,  /* NETLINK_AUDIT */
        11, /* NETLINK_FIB_LOOKUP */
        12, /* NETLINK_NETFILTER */
        13, /* NETLINK_IP6_FW */
        14, /* NETLINK_DNRTMSG */
        15, /* NETLINK_KOBJECT_UEVENT */
        16, /* NETLINK_GENERIC */
    };

    for (int i = 0; i < 12; i++) {
        int fd = socket(AF_NETLINK, SOCK_RAW, protocols[i]);
        if (fd >= 0) {
            available++;
            close(fd);
        }
    }
    return available;
}

/* Test 5: Raw nfnetlink message (simulated nftables batch) */
static int try_nftables_batch(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (fd < 0) return 0;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    int ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    close(fd);

    return (ret == 0) ? 1 : 0;
}

/* Test 6: SOCK_RAW + IPPROTO_RAW (iptables control) */
static int try_raw_socket(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 7: /proc/net/nf_conntrack */
static int try_nf_conntrack(void) {
    int fd = open("/proc/net/nf_conntrack", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 8: NETLINK_GENERIC socket (used for some nftables operations) */
static int try_netlink_generic(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW, 16 /* NETLINK_GENERIC */);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NETFILTER/NFTABLES KERNEL LPE (CVE-2024-1086, CVE-2024-26809)");

    int nfnl = try_nfnetlink();
    TEST("NETLINK_NETFILTER blocked",
         nfnl <= 0,
         nfnl == 1  ? "AVAILABLE — nftables LPE possible!" :
         nfnl == -2 ? "SIGSYS (seccomp)" : "blocked");

    int nflog = try_nflog();
    TEST("NETLINK_NFLOG blocked",
         nflog <= 0,
         nflog == 1  ? "AVAILABLE — netfilter log access!" :
         nflog == -2 ? "SIGSYS" : "blocked");

    int nlroute = try_netlink_route();
    TEST("NETLINK_ROUTE blocked",
         nlroute <= 0,
         nlroute == 1  ? "AVAILABLE — network namespace manipulation!" :
         nlroute == -2 ? "SIGSYS" : "blocked");

    int nlprotos = try_netlink_protocols();
    TEST("Netlink protocols restricted",
         nlprotos <= 0,
         nlprotos > 0 ? "%d netlink protocols available!" : "all blocked",
         nlprotos);

    int nft_batch = try_nftables_batch();
    TEST("nftables batch operations blocked",
         nft_batch == 0,
         nft_batch ? "BOUND — can send nftables commands!" : "blocked");

    int raw = try_raw_socket();
    TEST("SOCK_RAW blocked",
         raw <= 0,
         raw == 1  ? "RAW SOCKET AVAILABLE — needs CAP_NET_RAW!" :
         raw == -2 ? "SIGSYS" : "blocked");

    int conntrack = try_nf_conntrack();
    TEST("/proc/net/nf_conntrack blocked",
         conntrack == 0,
         conntrack ? "readable (connection tracking info leak)" : "blocked");

    int nlgeneric = try_netlink_generic();
    TEST("NETLINK_GENERIC blocked",
         nlgeneric <= 0,
         nlgeneric == 1  ? "AVAILABLE — generic netlink access!" :
         nlgeneric == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
