/*
 * test_82_page_spray.c — Page-level heap exploitation primitives
 *
 * Based on: Page Spray (USENIX Security 2024), PageJack (Black Hat 2024),
 * SLUBStick (USENIX Security 2024).
 *
 * These techniques operate at the page level rather than the slab object
 * level, making exploitation more reliable across kernel versions.
 *
 * Attack primitives tested:
 *   - Direct Page Allocation via sendmsg (skb_page_frag_refill)
 *   - Pipe buffer page spray (splice/tee)
 *   - SLUB allocator timing side channel (SLUBStick)
 *   - msg_msg page-level spray
 *   - Cross-cache timing measurement
 *
 * Tests:
 *  1. sendmsg large payload (page spray call site)
 *  2. splice/tee pipe operations (page spray)
 *  3. timerfd_create spray (slab padding objects)
 *  4. msg_msg large message spray
 *  5. SLUB allocator timing measurement
 *  6. Page allocation timing (buddy allocator)
 *  7. Cross-cache page reclamation probe
 *  8. shmget/shmat page mapping
 */
#include "test_harness.h"
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

int main(void) {
    install_sigsys_handler();
    setvbuf(stdout, NULL, _IONBF, 0);

    PRINT_HEADER("PAGE-LEVEL HEAP EXPLOITATION PRIMITIVES");

    /* Test 1: sendmsg large payload (page spray via skb_page_frag_refill) */
    {
        g_got_sigsys = 0;
        int sv[2];
        int created = (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        int sent = 0;

        if (created) {
            /* Large payload triggers Direct Page Allocation in kernel */
            char buf[8192];
            memset(buf, 'A', sizeof(buf));
            struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            ssize_t n = sendmsg(sv[0], &msg, MSG_DONTWAIT);
            sent = (n > 0);
            close(sv[0]);
            close(sv[1]);
        }

        /* sendmsg on AF_UNIX is needed for IPC, can't easily block */
        TEST("sendmsg page spray noted",
             1, /* AF_UNIX sendmsg is needed for IPC */
             !created ? "socketpair failed" :
             sent ? "8KB sendmsg succeeded (page spray call site reachable)" :
             "sendmsg failed");
    }

    /* Test 2: splice/tee pipe operations (pipe-based page spray) */
    {
        g_got_sigsys = 0;
        int pipefd[2], pipefd2[2];
        int pipe1 = (pipe(pipefd) == 0);
        int pipe2 = (pipe(pipefd2) == 0);
        int spliced = 0;
        int teed = 0;

        if (pipe1 && pipe2) {
            /* Write data to first pipe */
            (void)write(pipefd[1], "AAAA", 4);

            /* splice between pipes — triggers page allocation */
            g_got_sigsys = 0;
            ssize_t n = splice(pipefd[0], NULL, pipefd2[1], NULL, 4, 0);
            spliced = (n > 0 && !g_got_sigsys);

            /* tee duplicates pipe data without consuming it */
            if (spliced) {
                (void)write(pipefd[1], "BBBB", 4);
                g_got_sigsys = 0;
                n = tee(pipefd[0], pipefd2[1], 4, 0);
                teed = (n > 0 && !g_got_sigsys);
            }
        }

        if (pipe1) { close(pipefd[0]); close(pipefd[1]); }
        if (pipe2) { close(pipefd2[0]); close(pipefd2[1]); }

        /* splice/tee are needed for efficient I/O */
        TEST("splice/tee page spray noted",
             1, /* splice/tee are standard I/O operations */
             spliced && teed ? "splice+tee available (page spray primitives)" :
             spliced ? "splice available, tee blocked" :
             g_got_sigsys ? "blocked" :
             "pipes failed");
    }

    /* Test 3: timerfd_create spray (slab padding objects) */
    {
        g_got_sigsys = 0;
        int created = 0;
        int fds[64];

        for (int i = 0; i < 64; i++) {
            g_got_sigsys = 0;
            fds[i] = syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
            if (fds[i] >= 0 && !g_got_sigsys) created++;
            else { fds[i] = -1; break; }
        }

        for (int i = 0; i < 64; i++) {
            if (fds[i] >= 0) close(fds[i]);
        }

        if (created > 0)
            test_checkf("timerfd_create spray noted", 1,
                        "sprayed %d timerfd objects (slab padding)", created);
        else
            test_check("timerfd_create spray noted", 1,
                       g_got_sigsys ? "blocked" : "timerfd_create failed");
    }

    /* Test 4: msg_msg large message spray */
    {
        g_got_sigsys = 0;
        int qid = syscall(SYS_msgget, IPC_PRIVATE, IPC_CREAT | 0666);
        int sprayed = 0;

        if (qid >= 0 && !g_got_sigsys) {
            /* msg_msg objects are allocated from different slab caches
             * based on message size, making them useful for page spray */
            for (int i = 0; i < 32; i++) {
                struct {
                    long mtype;
                    char mtext[4096 - sizeof(long)]; /* page-sized */
                } msg;
                msg.mtype = i + 1;
                memset(msg.mtext, 'A' + (i % 26), sizeof(msg.mtext));
                long ret = syscall(SYS_msgsnd, qid, &msg, sizeof(msg.mtext), IPC_NOWAIT);
                if (ret == 0) sprayed++;
                else break;
            }
            syscall(SYS_msgctl, qid, IPC_RMID, NULL);
        }

        int blocked = g_got_sigsys || qid < 0;
        if (blocked)
            test_check("msg_msg page spray blocked", 1, "blocked (IPC denied)");
        else if (sprayed > 0)
            test_checkf("msg_msg page spray blocked", 0,
                        "MSG_MSG — sprayed %d page-sized messages!", sprayed);
        else
            test_check("msg_msg page spray blocked", 1, "msgsnd failed");
    }

    /* Test 5: SLUB allocator timing measurement (SLUBStick pattern) */
    {
        struct timespec start, end;
        long times[10];

        /* Measure allocation timing across multiple rounds.
         * SLUBStick exploits timing differences between:
         * - Allocating from a partial slab (fast)
         * - Requiring a new slab page from buddy allocator (slow) */
        for (int round = 0; round < 10; round++) {
            clock_gettime(CLOCK_MONOTONIC, &start);
            /* Trigger kernel allocations via pipe creation */
            int pf[2];
            if (pipe(pf) == 0) {
                close(pf[0]);
                close(pf[1]);
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            times[round] = (end.tv_sec - start.tv_sec) * 1000000000L +
                           (end.tv_nsec - start.tv_nsec);
        }

        /* Check timing variance — high variance indicates measurable
         * allocator state (SLUBStick side channel) */
        long min_t = times[0], max_t = times[0];
        for (int i = 1; i < 10; i++) {
            if (times[i] < min_t) min_t = times[i];
            if (times[i] > max_t) max_t = times[i];
        }
        long variance = max_t - min_t;

        /* Allocator timing is inherent to kernel operation */
        test_checkf("SLUB allocator timing noted", 1,
                    variance > 10000 ?
                    "high variance (%ldns, SLUBStick feasible)" :
                    "low variance (%ldns)", variance);
    }

    /* Test 6: Page allocation timing (buddy allocator probe) */
    {
        struct timespec start, end;
        /* mmap/munmap exercises the buddy allocator */
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 100; i++) {
            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p != MAP_FAILED) {
                /* Touch the page to force allocation */
                *(volatile char *)p = 0;
                munmap(p, 4096);
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long total_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                        (end.tv_nsec - start.tv_nsec);
        long avg_ns = total_ns / 100;

        TEST("Buddy allocator timing noted",
             1, /* mmap is fundamental */
             "avg %ldns per page alloc+free cycle", avg_ns);
    }

    /* Test 7: Cross-cache page reclamation probe */
    {
        /* Try to observe page reclamation between different slab caches
         * by measuring timing of allocations after freeing from another cache */
        struct timespec start, end;
        int fds[32];
        int created = 0;

        /* Phase 1: Fill a slab cache with timerfd objects */
        for (int i = 0; i < 32; i++) {
            fds[i] = syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
            if (fds[i] >= 0) created++;
            else { fds[i] = -1; break; }
        }

        /* Phase 2: Free them all (pages return to buddy allocator) */
        for (int i = 0; i < 32; i++) {
            if (fds[i] >= 0) close(fds[i]);
        }

        /* Phase 3: Allocate in a different cache and measure timing */
        clock_gettime(CLOCK_MONOTONIC, &start);
        int sv[2];
        int got_socket = (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        clock_gettime(CLOCK_MONOTONIC, &end);

        if (got_socket) { close(sv[0]); close(sv[1]); }

        long reclaim_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                          (end.tv_nsec - start.tv_nsec);

        if (created > 0)
            test_checkf("Cross-cache page reclamation noted", 1,
                        "freed %d objects, next alloc %ldns", created, reclaim_ns);
        else
            test_check("Cross-cache page reclamation noted", 1,
                       "timerfd blocked");
    }

    /* Test 8: shmget/shmat page mapping */
    {
        g_got_sigsys = 0;
        int shmid = syscall(SYS_shmget, IPC_PRIVATE, 4096 * 16,
                            IPC_CREAT | 0666);
        int mapped = 0;

        if (shmid >= 0 && !g_got_sigsys) {
            void *addr = (void *)syscall(SYS_shmat, shmid, NULL, 0);
            if (addr != (void *)-1) {
                /* Touch pages to force physical allocation */
                for (int i = 0; i < 16; i++) {
                    ((volatile char *)addr)[i * 4096] = (char)i;
                }
                mapped = 1;
                syscall(SYS_shmdt, addr);
            }
            syscall(SYS_shmctl, shmid, IPC_RMID, NULL);
        }

        int blocked = g_got_sigsys || shmid < 0;
        TEST("shmget/shmat page mapping blocked",
             blocked || !mapped,
             blocked ? "blocked (IPC denied)" :
             mapped ? "SHM — 16 pages mapped via shared memory!" :
             "shmat failed");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
