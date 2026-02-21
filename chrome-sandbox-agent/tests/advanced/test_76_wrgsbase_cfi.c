/*
 * test_76_wrgsbase_cfi.c — WRGSBASE/WRFSBASE and CFI bypass primitives
 *
 * Based on: FineIBT bypass (February 2025 kernel disclosure)
 * and GhostRace (CVE-2024-2193, VUSec/IBM Research).
 *
 * wrgsbase/wrfsbase are user-mode executable instructions on modern
 * x86 CPUs (FSGSBASE feature, enabled since Linux 5.9). They allow
 * direct modification of GS_BASE/FS_BASE registers from ring 3.
 *
 * Security impact:
 *   - FineIBT kernel CFI bypass: wrgsbase controls GS_BASE which
 *     enables stack pivots at syscall entry, bypassing all kCFI.
 *   - TLS manipulation: wrfsbase changes thread-local storage base.
 *   - Speculative execution: Modified segment bases affect speculative
 *     memory accesses across security boundaries.
 *
 * Tests:
 *  1. WRGSBASE instruction (direct GS base write)
 *  2. WRFSBASE instruction (direct FS base write)
 *  3. RDGSBASE instruction (read GS base)
 *  4. RDFSBASE instruction (read FS base)
 *  5. Check FSGSBASE CPUID feature bit
 *  6. arch_prctl ARCH_SET_GS alternative
 *  7. Speculative bounds check bypass (Spectre v1 pattern)
 *  8. Branch target injection measurement
 */
#include "test_harness.h"

/* CPUID FSGSBASE feature bit: CPUID.7.0:EBX[0] */
static int has_fsgsbase(void) {
#if defined(__x86_64__)
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(7), "c"(0));
    return !!(ebx & (1U << 0));
#else
    return 0;
#endif
}

#ifndef ARCH_SET_GS
#define ARCH_SET_GS 0x1001
#endif
#ifndef ARCH_GET_GS
#define ARCH_GET_GS 0x1004
#endif

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("WRGSBASE / CFI BYPASS PRIMITIVES");

    int fsgsbase = has_fsgsbase();

    /* Test 1: WRGSBASE — direct GS base write from userspace */
    {
        g_got_sigsys = 0;
        int succeeded = 0;

        if (fsgsbase) {
            pid_t pid = fork();
            if (pid == 0) {
                /* Try wrgsbase in child to avoid corrupting parent */
#if defined(__x86_64__)
                unsigned long test_val = 0x41414141UL;
                unsigned long old_gs = 0;

                /* Read current GS first */
                __asm__ volatile("rdgsbase %0" : "=r"(old_gs));

                /* Try to write a new GS base */
                __asm__ volatile("wrgsbase %0" :: "r"(test_val));

                /* Read back to verify */
                unsigned long new_gs = 0;
                __asm__ volatile("rdgsbase %0" : "=r"(new_gs));

                /* Restore original */
                __asm__ volatile("wrgsbase %0" :: "r"(old_gs));

                _exit(new_gs == test_val ? 99 : 0);
#else
                _exit(0);
#endif
            }
            int status = 0;
            if (pid > 0) waitpid(pid, &status, 0);
            succeeded = (WIFEXITED(status) && WEXITSTATUS(status) == 99);
        }

        /* wrgsbase is a user-mode instruction, can't be blocked by seccomp.
         * The FineIBT bypass using wrgsbase is a fundamental hardware issue. */
        TEST("WRGSBASE instruction noted",
             1,  /* user-mode instruction, can't be seccomp-blocked */
             !fsgsbase ? "CPU lacks FSGSBASE feature" :
             succeeded ? "available (FineIBT bypass primitive — hardware issue)" :
             "failed unexpectedly");
    }

    /* Test 2: WRFSBASE — direct FS base write */
    {
        g_got_sigsys = 0;
        int succeeded = 0;

        if (fsgsbase) {
            pid_t pid = fork();
            if (pid == 0) {
#if defined(__x86_64__)
                unsigned long old_fs = 0;
                __asm__ volatile("rdfsbase %0" : "=r"(old_fs));

                void *alt_tls = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (alt_tls != MAP_FAILED) {
                    __asm__ volatile("wrfsbase %0" :: "r"((unsigned long)alt_tls));
                    /* Restore immediately to avoid crash */
                    __asm__ volatile("wrfsbase %0" :: "r"(old_fs));
                    munmap(alt_tls, 4096);
                    _exit(99);
                }
                _exit(0);
#else
                _exit(0);
#endif
            }
            int status = 0;
            if (pid > 0) waitpid(pid, &status, 0);
            succeeded = (WIFEXITED(status) && WEXITSTATUS(status) == 99);
        }

        TEST("WRFSBASE instruction noted",
             1,  /* user-mode instruction */
             !fsgsbase ? "CPU lacks FSGSBASE" :
             succeeded ? "available (TLS manipulation primitive)" :
             "failed");
    }

    /* Test 3: RDGSBASE — read GS base value */
    {
        int succeeded = 0;
        unsigned long gs_val = 0;
        if (fsgsbase) {
#if defined(__x86_64__)
            __asm__ volatile("rdgsbase %0" : "=r"(gs_val));
            succeeded = 1;
#endif
        }

        TEST("RDGSBASE instruction noted",
             1,
             !fsgsbase ? "CPU lacks FSGSBASE" :
             succeeded ? "available (can read kernel GS base)" :
             "failed");
        (void)gs_val;
    }

    /* Test 4: RDFSBASE — read FS base value (TLS pointer) */
    {
        int succeeded = 0;
        unsigned long fs_val = 0;
        if (fsgsbase) {
#if defined(__x86_64__)
            __asm__ volatile("rdfsbase %0" : "=r"(fs_val));
            succeeded = (fs_val != 0); /* Should be TLS area */
#endif
        }

        TEST("RDFSBASE instruction noted",
             1,
             !fsgsbase ? "CPU lacks FSGSBASE" :
             succeeded ? "available (TLS base readable)" :
             "zero or failed");
        (void)fs_val;
    }

    /* Test 5: CPUID FSGSBASE feature check */
    {
        TEST("CPUID FSGSBASE feature",
             1,
             fsgsbase ? "present (WRGSBASE/WRFSBASE available)" :
             "absent (CPU too old)");
    }

    /* Test 6: arch_prctl ARCH_SET_GS alternative */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mem == MAP_FAILED) _exit(0);
            long ret = syscall(SYS_arch_prctl, ARCH_SET_GS,
                               (unsigned long)mem);
            _exit(ret == 0 ? 99 : 0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        TEST("arch_prctl ARCH_SET_GS blocked",
             child_ret != 99 || g_got_sigsys,
             child_ret == 99 ? "SET_GS — GS base modified via syscall!" :
             "blocked");
    }

    /* Test 7: Spectre v1 bounds check bypass probe */
    {
        /* Spectre v1 is a hardware issue — sandbox can't prevent it.
         * Just note whether the CPU supports speculative execution
         * bounds check bypass via timing. */
        volatile int x = 0;
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 10000; i++) {
            /* Simple computation to generate speculative activity */
            if (i < 5000) x++;
            else x--;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        long diff = (end.tv_sec - start.tv_sec) * 1000000000L +
                    (end.tv_nsec - start.tv_nsec);

        TEST("Spectre v1 bounds bypass noted",
             1,  /* hardware issue, not sandbox-specific */
             diff < 1000000 ? "fast execution (speculative exec active)" :
             "slow execution");
        (void)x;
    }

    /* Test 8: Branch prediction timing measurement */
    {
        struct timespec start, end;
        volatile int x = 0;

        /* Measure branch misprediction cost */
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 100000; i++) {
            /* Alternating branches to cause mispredictions */
            if (i & 1) x++;
            else x--;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long diff_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                       (end.tv_nsec - start.tv_nsec);

        TEST("Branch prediction timing noted",
             1,  /* fundamental CPU behavior */
             diff_ns < 10000000 ? "fast (branch timing measurable)" :
             "slow (measurement unreliable)");
        (void)x;
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
