/*
 * test_67_nftables_netlink.c — Netlink-based kernel manipulation
 *
 * Netlink sockets provide a direct interface to kernel subsystems.
 * CVE-2024-1086 (nf_tables UAF, CVSS 7.8) used NETLINK_NETFILTER
 * from a user namespace. This tests various netlink families:
 *
 * - NETLINK_AUDIT: Audit system manipulation
 * - NETLINK_CONNECTOR: Kernel connector events
 * - NETLINK_CRYPTO: Crypto subsystem info
 * - NETLINK_GENERIC: Generic netlink (nl80211, etc)
 * - NETLINK_SELINUX: SELinux events
 * - NETLINK_XFRM: IPsec/XFRM manipulation
 * - NETLINK_SOCK_DIAG: Socket diagnostics
 * - NETLINK_NETFILTER: nf_tables exploitation surface
 *
 * Tests:
 *  1. NETLINK_AUDIT socket
 *  2. NETLINK_CONNECTOR socket
 *  3. NETLINK_CRYPTO socket
 *  4. NETLINK_GENERIC socket
 *  5. NETLINK_SELINUX socket
 *  6. NETLINK_XFRM socket
 *  7. NETLINK_SOCK_DIAG socket
 *  8. NETLINK_NETFILTER nf_tables message
 */
#include "test_harness.h"
#include <linux/netlink.h>

/* Netlink families that might not be in headers */
#ifndef NETLINK_AUDIT
#define NETLINK_AUDIT 9
#endif
#ifndef NETLINK_CONNECTOR
#define NETLINK_CONNECTOR 11
#endif
#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif
#ifndef NETLINK_CRYPTO
#define NETLINK_CRYPTO 21
#endif
#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif
#ifndef NETLINK_SELINUX
#define NETLINK_SELINUX 7
#endif
#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif
#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif

static int test_netlink_family(int family, const char *name,
                               const char *danger) {
    g_got_sigsys = 0;
    int sock = socket(AF_NETLINK, SOCK_RAW, family);
    int blocked = (sock < 0 || g_got_sigsys);
    if (sock >= 0) close(sock);

    char test_name[128];
    snprintf(test_name, sizeof(test_name), "NETLINK_%s blocked", name);

    TEST(test_name, blocked,
         blocked ? "blocked" : danger);
    return blocked;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NETLINK KERNEL INTERFACE ATTACK SURFACE");

    /* Test 1: NETLINK_AUDIT — audit system control */
    test_netlink_family(NETLINK_AUDIT, "AUDIT",
                        "AUDIT — audit system accessible from sandbox!");

    /* Test 2: NETLINK_CONNECTOR — kernel events */
    test_netlink_family(NETLINK_CONNECTOR, "CONNECTOR",
                        "CONNECTOR — kernel events accessible!");

    /* Test 3: NETLINK_CRYPTO — crypto subsystem */
    test_netlink_family(NETLINK_CRYPTO, "CRYPTO",
                        "CRYPTO — crypto subsystem accessible!");

    /* Test 4: NETLINK_GENERIC — generic netlink */
    test_netlink_family(NETLINK_GENERIC, "GENERIC",
                        "GENERIC — generic netlink accessible!");

    /* Test 5: NETLINK_SELINUX — SELinux events */
    test_netlink_family(NETLINK_SELINUX, "SELINUX",
                        "SELINUX — SELinux events accessible!");

    /* Test 6: NETLINK_XFRM — IPsec/XFRM */
    test_netlink_family(NETLINK_XFRM, "XFRM",
                        "XFRM — IPsec accessible from sandbox!");

    /* Test 7: NETLINK_SOCK_DIAG — socket diagnostics */
    test_netlink_family(NETLINK_SOCK_DIAG, "SOCK_DIAG",
                        "SOCK_DIAG — socket diagnostics accessible!");

    /* Test 8: NETLINK_NETFILTER with nf_tables message */
    {
        g_got_sigsys = 0;
        int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
        int blocked = (sock < 0 || g_got_sigsys);

        if (sock >= 0) {
            /* Try binding to nf_tables subsystem */
            struct sockaddr_nl addr;
            memset(&addr, 0, sizeof(addr));
            addr.nl_family = AF_NETLINK;
            addr.nl_groups = 0;
            addr.nl_pid = 0;

            int bound = (bind(sock, (struct sockaddr *)&addr,
                              sizeof(addr)) == 0);

            if (bound) {
                /* Try sending an nf_tables batch begin message */
                struct {
                    struct nlmsghdr nlh;
                    /* nfgenmsg */
                    uint8_t nfgen_family;
                    uint8_t version;
                    uint16_t res_id;
                } msg;
                memset(&msg, 0, sizeof(msg));
                msg.nlh.nlmsg_len = sizeof(msg);
                msg.nlh.nlmsg_type = 0x10; /* NFNL_MSG_BATCH_BEGIN */
                msg.nlh.nlmsg_flags = 0x301; /* NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK */
                msg.nlh.nlmsg_seq = 1;
                msg.nfgen_family = 2; /* AF_INET */

                struct sockaddr_nl dst;
                memset(&dst, 0, sizeof(dst));
                dst.nl_family = AF_NETLINK;

                struct iovec iov = { .iov_base = &msg, .iov_len = sizeof(msg) };
                struct msghdr msghdr;
                memset(&msghdr, 0, sizeof(msghdr));
                msghdr.msg_name = &dst;
                msghdr.msg_namelen = sizeof(dst);
                msghdr.msg_iov = &iov;
                msghdr.msg_iovlen = 1;

                ssize_t sent = sendmsg(sock, &msghdr, 0);
                if (sent > 0) blocked = 0;
            }
            close(sock);
        }

        TEST("NETLINK_NETFILTER nf_tables blocked",
             blocked,
             blocked ? "blocked" :
             "NFTABLES — nf_tables accessible (CVE-2024-1086 surface)!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
