/*
 * test_17_vsock.c — Virtio vsock & VM escape vector tests
 *
 * CVE-2024-50264 (Pwnie Award 2025 Best Privilege Escalation):
 * AF_VSOCK use-after-free in virtio_vsock_sock. The exploit uses
 * cross-cache attacks via msg_msg + pipe_buffer to achieve arbitrary
 * kernel memory R/W from a vsock connection.
 *
 * Also tests other VM/hypervisor escape surfaces.
 *
 * Tests:
 *  1. AF_VSOCK socket creation (CVE-2024-50264)
 *  2. AF_VSOCK STREAM socket
 *  3. AF_VSOCK DGRAM socket
 *  4. AF_VSOCK SEQPACKET socket
 *  5. /dev/vsock device access
 *  6. /dev/vhost-vsock device access
 *  7. AF_KCM socket (kernel connection multiplexor)
 *  8. AF_XDP socket (express data path — direct NIC access)
 */
#include "test_harness.h"

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
#ifndef AF_KCM
#define AF_KCM   41
#endif
#ifndef AF_XDP
#define AF_XDP   44
#endif

/* Test 1: AF_VSOCK STREAM */
static int try_vsock_stream(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

/* Test 2: AF_VSOCK DGRAM */
static int try_vsock_dgram(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

/* Test 3: AF_VSOCK SEQPACKET */
static int try_vsock_seqpacket(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

/* Test 4: /dev/vsock */
static int try_dev_vsock(void) {
    int fd = open("/dev/vsock", O_RDWR);
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

/* Test 5: /dev/vhost-vsock */
static int try_dev_vhost_vsock(void) {
    int fd = open("/dev/vhost-vsock", O_RDWR);
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

/* Test 6: AF_KCM — Kernel Connection Multiplexor */
static int try_kcm(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_KCM, SOCK_DGRAM, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

/* Test 7: AF_XDP — Express Data Path (direct NIC access) */
static int try_xdp(void) {
    g_got_sigsys = 0;
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

/* Test 8: Other exotic socket families */
static int try_exotic_sockets(void) {
    int available = 0;
    /* Socket families that could expose kernel attack surface */
    struct { int family; int type; const char *name; } families[] = {
        { 16, SOCK_RAW, "AF_NETLINK" },   /* Covered in test_16 but check again */
        { 17, SOCK_RAW, "AF_PACKET" },    /* Raw packet capture */
        { 24, SOCK_DGRAM, "AF_KEY" },     /* IPsec key management */
        { 27, SOCK_DGRAM, "AF_BLUETOOTH" },
        { 29, SOCK_DGRAM, "AF_CAN" },
        { 36, SOCK_RAW, "AF_LLC" },
        { 38, SOCK_DGRAM, "AF_TIPC" },
        { 43, SOCK_DGRAM, "AF_SMC" },     /* Shared memory comms */
    };

    for (unsigned i = 0; i < sizeof(families)/sizeof(families[0]); i++) {
        int fd = socket(families[i].family, families[i].type, 0);
        if (fd >= 0) {
            available++;
            close(fd);
        }
    }
    return available;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("VSOCK/VM ESCAPE VECTORS (CVE-2024-50264 Pwnie 2025)");

    int vs_stream = try_vsock_stream();
    TEST("AF_VSOCK STREAM blocked",
         vs_stream <= 0,
         vs_stream == 1  ? "AVAILABLE — CVE-2024-50264 exploitable!" :
         vs_stream == -2 ? "SIGSYS" : "blocked");

    int vs_dgram = try_vsock_dgram();
    TEST("AF_VSOCK DGRAM blocked",
         vs_dgram <= 0,
         vs_dgram == 1  ? "AVAILABLE!" :
         vs_dgram == -2 ? "SIGSYS" : "blocked");

    int vs_seqpacket = try_vsock_seqpacket();
    TEST("AF_VSOCK SEQPACKET blocked",
         vs_seqpacket <= 0,
         vs_seqpacket == 1  ? "AVAILABLE!" :
         vs_seqpacket == -2 ? "SIGSYS" : "blocked");

    int dev_vsock = try_dev_vsock();
    TEST("/dev/vsock blocked",
         dev_vsock == 0,
         dev_vsock ? "ACCESSIBLE!" : "blocked");

    int dev_vhost = try_dev_vhost_vsock();
    TEST("/dev/vhost-vsock blocked",
         dev_vhost == 0,
         dev_vhost ? "ACCESSIBLE!" : "blocked");

    int kcm = try_kcm();
    TEST("AF_KCM blocked",
         kcm <= 0,
         kcm == 1  ? "AVAILABLE!" :
         kcm == -2 ? "SIGSYS" : "blocked");

    int xdp = try_xdp();
    TEST("AF_XDP blocked (direct NIC access)",
         xdp <= 0,
         xdp == 1  ? "AVAILABLE — can access NIC directly!" :
         xdp == -2 ? "SIGSYS" : "blocked");

    int exotic = try_exotic_sockets();
    TEST("Exotic socket families blocked",
         exotic == 0,
         exotic > 0 ? "%d exotic socket families available!" : "all blocked",
         exotic);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
