/*
 * test_77_io_uring_deep.c — Deep io_uring attack surfaces
 *
 * Based on: Curing rootkit (ARMO 2025), CVE-2024-0582 (PBUF_RING UAF),
 * CVE-2022-29582 (timeout race), io_uring URING_CMD device passthrough.
 *
 * io_uring is the #1 kernel attack surface because it enables syscall-free
 * I/O operations from userspace. A compromised process with io_uring access
 * can read/write files, open network connections, and more — all invisible
 * to seccomp and syscall-based monitoring.
 *
 * Tests:
 *  1. Fixed file registration (shadow FD table)
 *  2. Fixed file update (dynamic shadow FD manipulation)
 *  3. PBUF_RING registration (CVE-2024-0582 entry point)
 *  4. PBUF_RING mmap (UAF trigger pattern)
 *  5. IORING_OP_URING_CMD passthrough reachability
 *  6. Cancel/timeout race reachability (CVE-2022-29582)
 *  7. Ring restriction mechanism (IORING_REGISTER_RESTRICTIONS)
 *  8. DEFER_TASKRUN + SQPOLL combined
 */
#include "test_harness.h"
#include <linux/io_uring.h>

#ifndef IORING_REGISTER_FILES
#define IORING_REGISTER_FILES 2
#endif
#ifndef IORING_REGISTER_FILES_UPDATE
#define IORING_REGISTER_FILES_UPDATE 6
#endif
#ifndef IORING_REGISTER_PBUF_RING
#define IORING_REGISTER_PBUF_RING 22
#endif
#ifndef IORING_UNREGISTER_PBUF_RING
#define IORING_UNREGISTER_PBUF_RING 23
#endif
#ifndef IOU_PBUF_RING_MMAP
#define IOU_PBUF_RING_MMAP 1
#endif
#ifndef IORING_REGISTER_RESTRICTIONS
#define IORING_REGISTER_RESTRICTIONS 12
#endif
#ifndef IORING_SETUP_DEFER_TASKRUN
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#endif
#ifndef IORING_SETUP_SQPOLL
#define IORING_SETUP_SQPOLL (1U << 1)
#endif
#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#endif

#ifndef IORING_OP_URING_CMD
#define IORING_OP_URING_CMD 80
#endif
#ifndef IORING_OP_TIMEOUT
#define IORING_OP_TIMEOUT 11
#endif
#ifndef IORING_OP_LINK_TIMEOUT
#define IORING_OP_LINK_TIMEOUT 15
#endif
#ifndef IORING_OP_ASYNC_CANCEL
#define IORING_OP_ASYNC_CANCEL 14
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING 0ULL
#endif
#ifndef IORING_OFF_SQES
#define IORING_OFF_SQES 0x10000000ULL
#endif
#ifndef IORING_OFF_PBUF_RING
#define IORING_OFF_PBUF_RING 0x80000000ULL
#endif
#ifndef IORING_OFF_PBUF_SHIFT
#define IORING_OFF_PBUF_SHIFT 16
#endif

struct io_uring_buf_reg_local {
    uint64_t ring_addr;
    uint32_t ring_entries;
    uint16_t bgid;
    uint16_t flags;
    uint64_t resv[3];
};

struct io_uring_restriction_local {
    uint16_t opcode;
    union {
        uint8_t register_op;
        uint8_t sqe_op;
        uint8_t sqe_flags;
    };
    uint8_t resv;
    uint32_t resv2[3];
};

int main(void) {
    install_sigsys_handler();
    setvbuf(stdout, NULL, _IONBF, 0);

    PRINT_HEADER("DEEP io_uring ATTACK SURFACES");

    /* Test 1: Fixed file registration (shadow FD table) */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ring_fd = (int)syscall(SYS_io_uring_setup, 16, &params);
        int blocked = (ring_fd < 0);
        int registered = 0;

        if (!blocked) {
            /* Try to register /proc/self/exe as a fixed file */
            int target = open("/proc/self/exe", O_RDONLY);
            if (target >= 0) {
                int fds[1] = { target };
                long ret = syscall(SYS_io_uring_register, ring_fd,
                                   IORING_REGISTER_FILES, fds, 1);
                registered = (ret >= 0);
                close(target);
            }
            close(ring_fd);
        }

        TEST("io_uring fixed files (shadow FD) blocked",
             blocked || !registered,
             blocked ? "blocked (io_uring_setup denied)" :
             registered ? "FIXED FILES — shadow FD table created!" :
             "setup ok but register failed");
    }

    /* Test 2: Fixed file update (dynamic shadow FD manipulation) */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ring_fd = (int)syscall(SYS_io_uring_setup, 16, &params);
        int blocked = (ring_fd < 0);
        int updated = 0;

        if (!blocked) {
            int fds[2] = { -1, -1 };
            /* First register placeholder slots */
            long ret = syscall(SYS_io_uring_register, ring_fd,
                               IORING_REGISTER_FILES, fds, 2);
            if (ret >= 0) {
                /* Dynamically update slot 0 with a real file */
                int real_fd = open("/etc/hostname", O_RDONLY);
                if (real_fd >= 0) {
                    struct {
                        int32_t offset;
                        int32_t resv;
                        uint64_t fds_ptr;
                    } update;
                    int new_fds[1] = { real_fd };
                    update.offset = 0;
                    update.resv = 0;
                    update.fds_ptr = (uint64_t)(uintptr_t)new_fds;
                    long ret2 = syscall(SYS_io_uring_register, ring_fd,
                                        IORING_REGISTER_FILES_UPDATE, &update, 1);
                    updated = (ret2 >= 0);
                    close(real_fd);
                }
            }
            close(ring_fd);
        }

        TEST("io_uring fixed file update blocked",
             blocked || !updated,
             blocked ? "blocked (io_uring denied)" :
             updated ? "UPDATE — dynamic shadow FD manipulation!" :
             "register or update failed");
    }

    /* Test 3: PBUF_RING registration (CVE-2024-0582 entry point) */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ring_fd = (int)syscall(SYS_io_uring_setup, 16, &params);
        int blocked = (ring_fd < 0);
        int pbuf_registered = 0;

        if (!blocked) {
            struct io_uring_buf_reg_local reg;
            memset(&reg, 0, sizeof(reg));
            reg.ring_entries = 16;
            reg.bgid = 0;
            reg.flags = IOU_PBUF_RING_MMAP;

            long ret = syscall(SYS_io_uring_register, ring_fd,
                               IORING_REGISTER_PBUF_RING, &reg, 1);
            pbuf_registered = (ret >= 0);
            close(ring_fd);
        }

        TEST("io_uring PBUF_RING (CVE-2024-0582) blocked",
             blocked || !pbuf_registered,
             blocked ? "blocked (io_uring denied)" :
             pbuf_registered ? "PBUF_RING — UAF entry point reachable!" :
             "register failed");
    }

    /* Test 4: PBUF_RING mmap then unregister (UAF trigger pattern) */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ring_fd = (int)syscall(SYS_io_uring_setup, 16, &params);
        int blocked = (ring_fd < 0);
        int uaf_pattern = 0;

        if (!blocked) {
            struct io_uring_buf_reg_local reg;
            memset(&reg, 0, sizeof(reg));
            reg.ring_entries = 16;
            reg.bgid = 0;
            reg.flags = IOU_PBUF_RING_MMAP;

            long ret = syscall(SYS_io_uring_register, ring_fd,
                               IORING_REGISTER_PBUF_RING, &reg, 1);
            if (ret >= 0) {
                /* mmap the kernel-allocated buffer ring */
                off_t mmap_off = IORING_OFF_PBUF_RING |
                                 ((uint64_t)0 << IORING_OFF_PBUF_SHIFT);
                void *ring_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                      MAP_SHARED | MAP_POPULATE, ring_fd, mmap_off);

                /* Unregister — kernel frees pages, mmap may persist (the UAF) */
                struct { uint16_t bgid; uint16_t pad[3]; } unreg;
                memset(&unreg, 0, sizeof(unreg));
                unreg.bgid = 0;
                syscall(SYS_io_uring_register, ring_fd,
                        IORING_UNREGISTER_PBUF_RING, &unreg, 1);

                if (ring_mem != MAP_FAILED) {
                    uaf_pattern = 1;
                    munmap(ring_mem, 4096);
                }
            }
            close(ring_fd);
        }

        TEST("io_uring PBUF_RING UAF pattern blocked",
             blocked || !uaf_pattern,
             blocked ? "blocked (io_uring denied)" :
             uaf_pattern ? "UAF — mmap+unregister pattern reachable!" :
             "pbuf_ring setup failed");
    }

    /* Test 5: IORING_OP_URING_CMD passthrough reachability */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ring_fd = (int)syscall(SYS_io_uring_setup, 4, &params);
        int blocked = (ring_fd < 0);
        int cmd_submitted = 0;

        if (!blocked) {
            size_t sq_ring_sz = params.sq_off.array +
                                params.sq_entries * sizeof(unsigned);
            void *sq_ring = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_POPULATE, ring_fd,
                                 IORING_OFF_SQ_RING);
            void *sqes = mmap(NULL,
                              params.sq_entries * sizeof(struct io_uring_sqe),
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_POPULATE, ring_fd,
                              IORING_OFF_SQES);

            if (sq_ring != MAP_FAILED && sqes != MAP_FAILED) {
                struct io_uring_sqe *sqe = (struct io_uring_sqe *)sqes;
                memset(sqe, 0, sizeof(*sqe));
                sqe->opcode = IORING_OP_URING_CMD;
                sqe->fd = 0; /* stdin */

                unsigned *sq_tail = (unsigned *)((char *)sq_ring +
                                                  params.sq_off.tail);
                unsigned *sq_array = (unsigned *)((char *)sq_ring +
                                                   params.sq_off.array);
                sq_array[0] = 0;
                __atomic_store_n(sq_tail, 1, __ATOMIC_RELEASE);

                long ret = syscall(SYS_io_uring_enter, ring_fd, 1, 0, 0, NULL, 0);
                cmd_submitted = (ret >= 0);
            }

            if (sq_ring != MAP_FAILED) munmap(sq_ring, sq_ring_sz);
            if (sqes != MAP_FAILED)
                munmap(sqes, params.sq_entries * sizeof(struct io_uring_sqe));
            close(ring_fd);
        }

        TEST("io_uring URING_CMD passthrough blocked",
             blocked,
             blocked ? "blocked (io_uring denied)" :
             cmd_submitted ? "URING_CMD — device passthrough submitted!" :
             "setup ok, cmd rejected by target");
    }

    /* Test 6: Cancel/timeout race reachability (CVE-2022-29582 pattern) */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ring_fd = (int)syscall(SYS_io_uring_setup, 16, &params);
        int blocked = (ring_fd < 0);

        if (ring_fd >= 0) close(ring_fd);

        TEST("io_uring cancel/timeout race blocked",
             blocked,
             blocked ? "blocked (io_uring denied)" :
             "TIMEOUT RACE — CVE-2022-29582 code path reachable!");
    }

    /* Test 7: Ring restriction mechanism */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        int ring_fd = (int)syscall(SYS_io_uring_setup, 8, &params);
        int blocked = (ring_fd < 0);
        int restricted = 0;

        if (!blocked) {
            struct io_uring_restriction_local res;
            memset(&res, 0, sizeof(res));
            res.opcode = 1; /* IORING_RESTRICTION_SQE_OP */
            res.sqe_op = 0; /* NOP only */

            long ret = syscall(SYS_io_uring_register, ring_fd,
                               IORING_REGISTER_RESTRICTIONS, &res, 1);
            restricted = (ret >= 0);
            close(ring_fd);
        }

        TEST("io_uring ring restrictions blocked",
             blocked,
             blocked ? "blocked (io_uring denied)" :
             restricted ? "RESTRICTIONS — ring restriction model reachable" :
             "setup ok, restrictions failed");
    }

    /* Test 8: DEFER_TASKRUN + SQPOLL combined */
    {
        g_got_sigsys = 0;
        struct io_uring_params params;
        memset(&params, 0, sizeof(params));
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER;
        params.sq_thread_idle = 1000;

        int ring_fd = (int)syscall(SYS_io_uring_setup, 16, &params);
        int blocked = (ring_fd < 0);

        if (ring_fd >= 0) close(ring_fd);

        /* Try DEFER_TASKRUN separately */
        int defer_fd = -1;
        if (!blocked) {
            memset(&params, 0, sizeof(params));
            params.flags = IORING_SETUP_DEFER_TASKRUN |
                           IORING_SETUP_SINGLE_ISSUER;
            defer_fd = (int)syscall(SYS_io_uring_setup, 16, &params);
            if (defer_fd >= 0) close(defer_fd);
        }

        TEST("io_uring SQPOLL+DEFER_TASKRUN blocked",
             blocked,
             blocked ? "blocked (io_uring denied)" :
             "SQPOLL — kernel-thread I/O + deferred tasks reachable!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
