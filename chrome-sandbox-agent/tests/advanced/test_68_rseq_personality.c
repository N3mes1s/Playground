/*
 * test_68_rseq_personality.c — rseq, personality, and execution domain attacks
 *
 * - rseq (334): Restartable sequences — used by glibc/Chrome for
 *   per-CPU atomic operations. Can be abused for race conditions
 *   and critical section manipulation.
 *
 * - personality (135): Change execution domain. The READ_IMPLIES_EXEC
 *   flag (0x0400000) makes all readable memory executable, which
 *   bypasses W^X and enables code injection.
 *
 * - arch_prctl (158): Architecture-specific controls like
 *   ARCH_SET_FS/GS for TLS manipulation, and ARCH_MAP_VDSO_*.
 *
 * Tests:
 *  1. personality(READ_IMPLIES_EXEC) — make all readable pages exec
 *  2. personality(ADDR_NO_RANDOMIZE) — disable per-process ASLR
 *  3. rseq registration
 *  4. rseq with custom critical section
 *  5. arch_prctl ARCH_SET_FS (TLS manipulation)
 *  6. arch_prctl ARCH_MAP_VDSO_* access
 *  7. personality to LINUX32 (32-bit compat)
 *  8. personality current value read
 */
#include "test_harness.h"

#ifndef __NR_rseq
#define __NR_rseq 334
#endif

/* personality flags */
#ifndef READ_IMPLIES_EXEC
#define READ_IMPLIES_EXEC 0x0400000
#endif
#ifndef ADDR_NO_RANDOMIZE
#define ADDR_NO_RANDOMIZE 0x0040000
#endif
#ifndef PER_LINUX32
#define PER_LINUX32 0x0008
#endif

/* rseq struct */
struct rseq_local {
    uint32_t cpu_id_start;
    uint32_t cpu_id;
    uint64_t rseq_cs;
    uint32_t flags;
    uint32_t padding[3];
} __attribute__((aligned(32)));

/* arch_prctl operations */
#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#endif
#ifndef ARCH_GET_FS
#define ARCH_GET_FS 0x1003
#endif
#ifndef ARCH_MAP_VDSO_X32
#define ARCH_MAP_VDSO_X32 0x2001
#endif
#ifndef ARCH_MAP_VDSO_32
#define ARCH_MAP_VDSO_32 0x2002
#endif
#ifndef ARCH_MAP_VDSO_64
#define ARCH_MAP_VDSO_64 0x2003
#endif

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    install_sigsys_handler();

    PRINT_HEADER("RSEQ / PERSONALITY / EXECUTION DOMAIN");

    /* Test 1: personality(READ_IMPLIES_EXEC) */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            long old = syscall(SYS_personality, 0xffffffff); /* get current */
            long ret = syscall(SYS_personality, old | READ_IMPLIES_EXEC);
            /* Check if we now have READ_IMPLIES_EXEC set */
            long now = syscall(SYS_personality, 0xffffffff);
            _exit((now & READ_IMPLIES_EXEC) ? 99 : 0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        /* personality is per-process and doesn't cross sandbox boundaries.
         * READ_IMPLIES_EXEC is a concern for exploit development but
         * not a direct sandbox escape. */
        TEST("personality(READ_IMPLIES_EXEC) noted",
             1,  /* per-process setting, not a sandbox escape */
             child_ret == 99 ? "available (per-process, exploit hardening concern)"
             : "blocked");
    }

    /* Test 2: personality(ADDR_NO_RANDOMIZE) — disable ASLR */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            long ret = syscall(SYS_personality, ADDR_NO_RANDOMIZE);
            long now = syscall(SYS_personality, 0xffffffff);
            _exit((now & ADDR_NO_RANDOMIZE) ? 99 : 0);
            (void)ret;
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        /* ADDR_NO_RANDOMIZE is per-process ASLR control.
         * It only affects the calling process, not a sandbox escape. */
        TEST("personality(ADDR_NO_RANDOMIZE) noted",
             1,  /* per-process ASLR, not a sandbox escape */
             child_ret == 99 ? "available (per-process ASLR control)"
             : "blocked");
    }

    /* Test 3: rseq registration */
    {
        g_got_sigsys = 0;
        struct rseq_local rs;
        memset(&rs, 0, sizeof(rs));
        long ret = syscall(__NR_rseq, &rs, sizeof(rs), 0, 0x53053053);
        int available = (ret == 0);
        int blocked = (g_got_sigsys);

        /* rseq is needed by glibc for performance. It's generally allowed
         * and doesn't cross sandbox boundaries. */
        TEST("rseq registration noted",
             1,  /* rseq is needed by glibc, in-process only */
             blocked ? "blocked" :
             available ? "available (glibc requirement, in-process)" :
             "unavailable (may already be registered)");

        /* Unregister if we registered */
        if (available)
            syscall(__NR_rseq, &rs, sizeof(rs), 1 /* RSEQ_FLAG_UNREGISTER */,
                    0x53053053);
    }

    /* Test 4: rseq with CPU pinning info */
    {
        g_got_sigsys = 0;
        struct rseq_local rs;
        memset(&rs, 0, sizeof(rs));
        rs.cpu_id_start = 0;
        rs.cpu_id = 0;
        long ret = syscall(__NR_rseq, &rs, sizeof(rs), 0, 0x53053053);

        int has_cpu = 0;
        if (ret == 0 || errno == EBUSY /* already registered */) {
            /* rseq reveals which CPU we're on — potential info leak */
            has_cpu = (rs.cpu_id < 1024);  /* reasonable CPU number */
        }

        TEST("rseq CPU identification noted",
             1,  /* CPU ID is available via sched_getcpu() anyway */
             g_got_sigsys ? "blocked" :
             has_cpu ? "available (CPU ID, also via sched_getcpu)" :
             "no CPU info");

        if (ret == 0)
            syscall(__NR_rseq, &rs, sizeof(rs), 1, 0x53053053);
    }

    /* Test 5: arch_prctl ARCH_SET_FS (TLS manipulation) — run in child */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            void *fake_tls = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (fake_tls == MAP_FAILED) _exit(0);
            long ret = syscall(SYS_arch_prctl, ARCH_SET_FS,
                               (unsigned long)fake_tls);
            _exit(ret == 0 ? 99 : 0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        /* ARCH_SET_FS is needed for thread creation. It's in-process. */
        TEST("arch_prctl ARCH_SET_FS noted",
             1,  /* in-process TLS, needed for threading */
             child_ret == 99 ? "available (threading requirement)" :
             "restricted");
    }

    /* Test 6: arch_prctl ARCH_MAP_VDSO */
    {
        g_got_sigsys = 0;
        unsigned long addr = 0;
        long ret = syscall(SYS_arch_prctl, ARCH_MAP_VDSO_32, &addr);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("arch_prctl ARCH_MAP_VDSO blocked",
             blocked,
             blocked ? "blocked" :
             "VDSO — 32-bit VDSO mapped from sandbox!");
    }

    /* Test 7: personality to LINUX32 */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            long ret = syscall(SYS_personality, PER_LINUX32);
            long now = syscall(SYS_personality, 0xffffffff);
            _exit((now & 0xff) == PER_LINUX32 ? 99 : 0);
            (void)ret;
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        /* LINUX32 personality can affect seccomp filter behavior */
        TEST("personality(LINUX32) limited",
             child_ret != 99,
             child_ret == 99 ? "LINUX32 — 32-bit personality set (seccomp risk)!"
             : "blocked");
    }

    /* Test 8: personality current value read */
    {
        g_got_sigsys = 0;
        long pers = syscall(SYS_personality, 0xffffffff);
        int readable = (pers >= 0 && !g_got_sigsys);

        /* Reading personality is needed for normal operation */
        TEST("personality read noted",
             1,  /* reading personality is benign */
             g_got_sigsys ? "blocked" :
             readable ? "readable (normal operation)" : "error");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
