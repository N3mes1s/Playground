/*
 * test_73_ioperm_sched.c — I/O permissions, scheduling, and resource abuse
 *
 * Tests various syscalls that could be used for privilege escalation
 * or denial of service:
 *
 * - ioperm/iopl: Direct I/O port access (x86)
 * - sched_setscheduler: Change to real-time priority (DoS)
 * - setpriority/nice: Priority manipulation
 * - sched_setaffinity: CPU pinning (side channels)
 * - mbind/set_mempolicy: NUMA memory policy (info leak)
 * - quotactl: Disk quota manipulation
 * - acct: Process accounting control
 * - kexec_load: Load new kernel
 *
 * Tests:
 *  1. ioperm — I/O port permission
 *  2. iopl — I/O privilege level
 *  3. sched_setscheduler SCHED_FIFO (realtime)
 *  4. sched_setaffinity CPU pinning
 *  5. set_mempolicy NUMA control
 *  6. quotactl disk quota
 *  7. acct process accounting
 *  8. kexec_load new kernel
 */
#include "test_harness.h"
#include <linux/kexec.h>

#ifndef __NR_ioperm
#define __NR_ioperm 173
#endif
#ifndef __NR_iopl
#define __NR_iopl 172
#endif
#ifndef __NR_kexec_load
#define __NR_kexec_load 246
#endif

/* NUMA policies */
#ifndef MPOL_PREFERRED
#define MPOL_PREFERRED 1
#endif

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("I/O PERMISSIONS, SCHEDULING, RESOURCE ABUSE");

    /* Test 1: ioperm — I/O port permission */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_ioperm, 0x80, 1, 1);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("ioperm() blocked",
             blocked,
             blocked ? "blocked" :
             "IOPERM — I/O port access granted from sandbox!");
    }

    /* Test 2: iopl — I/O privilege level */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_iopl, 3);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("iopl(3) blocked",
             blocked,
             blocked ? "blocked" :
             "IOPL — I/O privilege level 3 from sandbox!");
    }

    /* Test 3: sched_setscheduler SCHED_FIFO (realtime) */
    {
        g_got_sigsys = 0;
        struct sched_param param = { .sched_priority = 99 };
        int ret = sched_setscheduler(0, SCHED_FIFO, &param);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("sched_setscheduler(SCHED_FIFO) blocked",
             blocked,
             blocked ? "blocked" :
             "RT — real-time scheduling from sandbox (DoS vector)!");
    }

    /* Test 4: sched_setaffinity CPU pinning */
    {
        g_got_sigsys = 0;
        cpu_set_t mask;
        CPU_ZERO(&mask);
        CPU_SET(0, &mask);
        int ret = sched_setaffinity(0, sizeof(mask), &mask);

        /* CPU affinity is generally allowed for performance.
         * The concern is cross-process affinity manipulation. */
        int cross_proc = 0;
        if (ret == 0) {
            /* Try to set affinity of PID 1 */
            int ret2 = sched_setaffinity(1, sizeof(mask), &mask);
            cross_proc = (ret2 == 0);
        }

        TEST("sched_setaffinity cross-process blocked",
             !cross_proc,
             cross_proc ? "AFFINITY — can pin other processes' CPUs!" :
             "blocked (self-affinity may be allowed)");
    }

    /* Test 5: set_mempolicy NUMA */
    {
        g_got_sigsys = 0;
        unsigned long nodemask = 1;
        long ret = syscall(SYS_set_mempolicy, MPOL_PREFERRED,
                           &nodemask, sizeof(nodemask) * 8);
        int blocked = (ret < 0 || g_got_sigsys);

        /* set_mempolicy is in-process NUMA control, generally allowed */
        TEST("set_mempolicy NUMA noted",
             1,  /* in-process NUMA, not a sandbox escape */
             blocked ? "blocked" :
             "available (in-process NUMA control)");
    }

    /* Test 6: quotactl */
    {
        g_got_sigsys = 0;
        /* Q_GETINFO (0x800005) for user quotas */
        long ret = syscall(SYS_quotactl, 0x800005, "/dev/sda1", 0, NULL);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("quotactl() blocked",
             blocked,
             blocked ? "blocked" :
             "QUOTA — disk quota manipulation from sandbox!");
    }

    /* Test 7: acct — process accounting */
    {
        g_got_sigsys = 0;
        long ret = syscall(SYS_acct, "/tmp/acct");
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("acct() blocked",
             blocked,
             blocked ? "blocked" :
             "ACCT — process accounting enabled from sandbox!");
    }

    /* Test 8: kexec_load — load new kernel */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_kexec_load, 0, 0, NULL, 0);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("kexec_load() blocked",
             blocked,
             blocked ? "blocked" :
             "KEXEC — new kernel loaded from sandbox!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
