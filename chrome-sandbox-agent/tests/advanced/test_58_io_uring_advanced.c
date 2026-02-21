/*
 * test_58_io_uring_advanced.c — Advanced io_uring attack surfaces
 *
 * While test_11 covers basic io_uring setup, this tests the more dangerous
 * advanced features that have been sources of many CVEs:
 *   - CVE-2024-0582: io_uring PBUF_RING pages UAF
 *   - CVE-2023-6817: io_uring fixed files refcount
 *   - CVE-2024-24857: io_uring SQPOLL thread race
 *
 * Attack surfaces tested:
 *  1. io_uring_setup with IORING_SETUP_SQPOLL (kernel thread)
 *  2. IORING_REGISTER_BUFFERS (fixed buffer registration)
 *  3. IORING_REGISTER_FILES (fixed file set)
 *  4. IORING_REGISTER_PBUF_RING (provided buffer ring — CVE-2024-0582)
 *  5. io_uring_enter with IORING_ENTER_SQ_WAKEUP
 *  6. IORING_OP_MSG_RING (cross-ring messaging)
 *  7. IORING_SETUP_DEFER_TASKRUN
 *  8. IORING_REGISTER_FILE_ALLOC_RANGE
 */
#include "test_harness.h"
#include <linux/io_uring.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

/* io_uring register opcodes */
#ifndef IORING_REGISTER_BUFFERS
#define IORING_REGISTER_BUFFERS 0
#endif
#ifndef IORING_REGISTER_FILES
#define IORING_REGISTER_FILES 2
#endif
#ifndef IORING_REGISTER_PBUF_RING
#define IORING_REGISTER_PBUF_RING 22
#endif
#ifndef IORING_REGISTER_FILE_ALLOC_RANGE
#define IORING_REGISTER_FILE_ALLOC_RANGE 25
#endif

/* io_uring setup flags */
#ifndef IORING_SETUP_SQPOLL
#define IORING_SETUP_SQPOLL (1U << 1)
#endif
#ifndef IORING_SETUP_DEFER_TASKRUN
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#endif
#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#endif

/* io_uring enter flags */
#ifndef IORING_ENTER_SQ_WAKEUP
#define IORING_ENTER_SQ_WAKEUP (1U << 1)
#endif

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("ADVANCED io_uring ATTACK SURFACES");

    /* Test 1: io_uring_setup basic — should be blocked */
    g_got_sigsys = 0;
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    long ring_fd = syscall(__NR_io_uring_setup, 8, &params);
    int basic_blocked = (ring_fd < 0 || g_got_sigsys);
    TEST("io_uring_setup() blocked",
         basic_blocked,
         basic_blocked ? "blocked" : "RING CREATED — io_uring accessible!");

    /* Test 2: io_uring_setup with SQPOLL — kernel-side polling thread */
    g_got_sigsys = 0;
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 1000;
    long sqpoll_fd = syscall(__NR_io_uring_setup, 8, &params);
    int sqpoll_blocked = (sqpoll_fd < 0 || g_got_sigsys);
    TEST("SQPOLL kernel thread blocked",
         sqpoll_blocked,
         sqpoll_blocked ? "blocked" :
         "SQPOLL — kernel polling thread created from sandbox!");

    /* Test 3: IORING_REGISTER_BUFFERS — fixed buffer registration */
    g_got_sigsys = 0;
    struct iovec iov;
    char buf[4096];
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    long reg = syscall(__NR_io_uring_register,
                       ring_fd > 0 ? (int)ring_fd : 0,
                       IORING_REGISTER_BUFFERS, &iov, 1);
    int regbuf_blocked = (reg < 0 || g_got_sigsys);
    TEST("REGISTER_BUFFERS blocked",
         regbuf_blocked,
         regbuf_blocked ? "blocked" :
         "REGISTERED — fixed buffers from sandbox!");

    /* Test 4: IORING_REGISTER_FILES — fixed file descriptors */
    g_got_sigsys = 0;
    int fds[1] = { STDIN_FILENO };
    reg = syscall(__NR_io_uring_register,
                  ring_fd > 0 ? (int)ring_fd : 0,
                  IORING_REGISTER_FILES, fds, 1);
    int regfile_blocked = (reg < 0 || g_got_sigsys);
    TEST("REGISTER_FILES blocked",
         regfile_blocked,
         regfile_blocked ? "blocked" :
         "REGISTERED — fixed files from sandbox!");

    /* Test 5: IORING_REGISTER_PBUF_RING — CVE-2024-0582 surface */
    g_got_sigsys = 0;
    struct {
        uint64_t ring_addr;
        uint32_t ring_entries;
        uint16_t bgid;
        uint16_t pad;
        uint64_t resv[3];
    } pbuf_reg;
    memset(&pbuf_reg, 0, sizeof(pbuf_reg));
    pbuf_reg.ring_entries = 16;
    reg = syscall(__NR_io_uring_register,
                  ring_fd > 0 ? (int)ring_fd : 0,
                  IORING_REGISTER_PBUF_RING, &pbuf_reg, 1);
    int pbuf_blocked = (reg < 0 || g_got_sigsys);
    TEST("REGISTER_PBUF_RING (CVE-2024-0582) blocked",
         pbuf_blocked,
         pbuf_blocked ? "blocked" :
         "PBUF RING — CVE-2024-0582 surface accessible!");

    /* Test 6: io_uring_enter with SQ_WAKEUP */
    g_got_sigsys = 0;
    long enter = syscall(__NR_io_uring_enter,
                         ring_fd > 0 ? (int)ring_fd : 0,
                         0, 0, IORING_ENTER_SQ_WAKEUP, NULL, 0);
    int enter_blocked = (enter < 0 || g_got_sigsys);
    TEST("io_uring_enter SQ_WAKEUP blocked",
         enter_blocked,
         enter_blocked ? "blocked" :
         "ENTERED — io_uring_enter from sandbox!");

    /* Test 7: DEFER_TASKRUN + SINGLE_ISSUER setup */
    g_got_sigsys = 0;
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
    long defer_fd = syscall(__NR_io_uring_setup, 8, &params);
    int defer_blocked = (defer_fd < 0 || g_got_sigsys);
    TEST("DEFER_TASKRUN setup blocked",
         defer_blocked,
         defer_blocked ? "blocked" :
         "DEFER — deferred task run ring created!");

    /* Test 8: REGISTER_FILE_ALLOC_RANGE */
    g_got_sigsys = 0;
    struct {
        uint32_t off;
        uint32_t len;
        uint64_t resv;
    } alloc_range = { .off = 0, .len = 64, .resv = 0 };
    reg = syscall(__NR_io_uring_register,
                  ring_fd > 0 ? (int)ring_fd : 0,
                  IORING_REGISTER_FILE_ALLOC_RANGE, &alloc_range, 0);
    int allocrange_blocked = (reg < 0 || g_got_sigsys);
    TEST("REGISTER_FILE_ALLOC_RANGE blocked",
         allocrange_blocked,
         allocrange_blocked ? "blocked" :
         "ALLOC RANGE — file alloc range from sandbox!");

    /* Clean up */
    if (ring_fd > 0) close((int)ring_fd);
    if (sqpoll_fd > 0) close((int)sqpoll_fd);
    if (defer_fd > 0) close((int)defer_fd);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
