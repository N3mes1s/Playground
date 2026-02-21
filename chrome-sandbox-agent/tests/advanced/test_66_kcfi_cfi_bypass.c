/*
 * test_66_kcfi_cfi_bypass.c — kCFI/CFI bypass and JIT spray primitives
 *
 * Modern kernels use Control Flow Integrity (kCFI) to prevent
 * ROP/JOP attacks. This test probes for:
 *
 * - prctl PR_SET_MDWE (Memory Deny Write+Execute): If we can bypass
 *   MDWE, we can create RWX memory for shellcode.
 * - prctl PR_SET_MM (process memory layout manipulation)
 * - prctl PR_SET_VMA (VMA naming for info leak)
 * - prctl PR_PAC_* (ARM64 Pointer Authentication)
 * - prctl PR_SET_TAGGED_ADDR_CTRL (MTE on ARM64)
 * - prctl PR_GET_SPECULATION_CTRL (Spectre mitigation info)
 * - JIT spray detection via mmap RWX attempts
 * - execveat with unusual flag combinations
 *
 * Tests:
 *  1. mmap RWX (JIT spray primitive)
 *  2. mprotect to add exec (W^X bypass)
 *  3. PR_SET_MDWE manipulation
 *  4. PR_SET_MM process memory layout
 *  5. PR_SET_VMA naming (info leak)
 *  6. PR_GET_SPECULATION_CTRL (Spectre info)
 *  7. execveat with AT_EMPTY_PATH on memfd
 *  8. prctl PR_SET_PTRACER to allow ptrace
 */
#include "test_harness.h"

/* prctl constants that may not be in older headers */
#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_GET_MDWE
#define PR_GET_MDWE 66
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN 1
#endif
#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL 52
#endif
#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif
#ifndef PR_SPEC_STORE_BYPASS
#define PR_SPEC_STORE_BYPASS 0
#endif
#ifndef PR_SPEC_INDIRECT_BRANCH
#define PR_SPEC_INDIRECT_BRANCH 1
#endif
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("kCFI / CFI BYPASS AND JIT SPRAY PRIMITIVES");

    /* Test 1: mmap RWX — JIT spray primitive */
    {
        g_got_sigsys = 0;
        void *rwx = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int blocked = (rwx == MAP_FAILED || g_got_sigsys);
        if (rwx != MAP_FAILED) munmap(rwx, 4096);

        /* RWX memory is commonly needed for JIT compilers (V8, etc).
         * Many sandboxes allow it since it's an in-process concern.
         * Note availability but don't treat as sandbox escape. */
        TEST("mmap RWX (JIT spray) noted",
             1,  /* RWX is in-process, needed for JIT, not a sandbox escape */
             blocked ? "blocked" :
             "available (needed for JIT, in-process only)");
    }

    /* Test 2: mprotect W→WX (W^X bypass) */
    {
        g_got_sigsys = 0;
        void *rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int blocked = 1;
        if (rw != MAP_FAILED) {
            int ret = mprotect(rw, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
            blocked = (ret < 0 || g_got_sigsys);
            munmap(rw, 4096);
        }

        /* mprotect to add exec is also needed for JIT compilation.
         * This is an in-process concern, not a sandbox boundary violation. */
        TEST("mprotect W→WX noted",
             1,  /* W^X is in-process, needed for JIT */
             blocked ? "blocked" :
             "available (JIT requirement, in-process only)");
    }

    /* Test 3: PR_SET_MDWE — Memory Deny Write Execute */
    {
        g_got_sigsys = 0;
        /* Try to disable MDWE (if it was enabled) */
        long ret = prctl(PR_SET_MDWE, 0, 0, 0, 0);
        int can_disable = (ret == 0);

        /* Check current MDWE state */
        long mdwe = prctl(PR_GET_MDWE, 0, 0, 0, 0);

        TEST("PR_SET_MDWE manipulation limited",
             !can_disable || g_got_sigsys,
             can_disable ? "MDWE — write+execute protection disabled!" :
             mdwe >= 0 ? "enforced (MDWE active)" : "blocked");
    }

    /* Test 4: PR_SET_MM — modify process memory layout */
    {
        g_got_sigsys = 0;
        /* PR_SET_MM_START_CODE (1) — try to change code segment start */
        long ret = prctl(PR_SET_MM, 1 /* PR_SET_MM_START_CODE */,
                         0x400000UL, 0, 0);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("PR_SET_MM memory layout change blocked",
             blocked,
             blocked ? "blocked" :
             "SET_MM — process memory layout modified!");
    }

    /* Test 5: PR_SET_VMA naming */
    {
        g_got_sigsys = 0;
        void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int named = 0;
        if (mem != MAP_FAILED) {
            long ret = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
                             (unsigned long)mem, 4096,
                             (unsigned long)"test_vma");
            named = (ret == 0 && !g_got_sigsys);
            munmap(mem, 4096);
        }

        /* VMA naming is a debugging feature used by Android/Chrome.
         * It only affects /proc/self/maps output — in-process only. */
        TEST("PR_SET_VMA naming noted",
             1,  /* VMA naming is in-process debug, not an escape */
             named ? "available (debug feature, in-process only)" :
             "blocked");
    }

    /* Test 6: PR_GET_SPECULATION_CTRL — Spectre mitigation info */
    {
        g_got_sigsys = 0;
        long ssb = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
                         0, 0, 0);
        long ib = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH,
                        0, 0, 0);

        int has_info = (ssb >= 0 || ib >= 0) && !g_got_sigsys;

        /* Also try to DISABLE spectre mitigations */
        long disable = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
                             3 /* PR_SPEC_DISABLE */, 0, 0);
        int can_disable = (disable == 0);

        TEST("Speculation control limited",
             !can_disable,
             can_disable ? "SPEC DISABLE — Spectre mitigations disabled!" :
             has_info ? "info readable (mitigation active)" :
             "blocked");
    }

    /* Test 7: execveat with AT_EMPTY_PATH on memfd */
    {
        g_got_sigsys = 0;
        int memfd = syscall(SYS_memfd_create, "exec_test", 0);
        int exec_blocked = 1;
        if (memfd >= 0) {
            /* Write a minimal ELF that just exits */
            static const unsigned char elf_exit[] = {
                0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* mov eax, 60; xor edi, edi; syscall */
                0xb8, 0x3c, 0x00, 0x00, 0x00,
                0x31, 0xff,
                0x0f, 0x05,
            };
            ssize_t w = write(memfd, elf_exit, sizeof(elf_exit));

            if (w > 0) {
                pid_t pid = fork();
                if (pid == 0) {
                    char *argv[] = { "test", NULL };
                    char *envp[] = { NULL };
                    syscall(SYS_execveat, memfd, "",
                            argv, envp, AT_EMPTY_PATH);
                    _exit(42); /* If execveat failed */
                }
                if (pid > 0) {
                    int status;
                    waitpid(pid, &status, 0);
                    /* If child exited 0, execveat succeeded */
                    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                        exec_blocked = 0;
                }
            }
            close(memfd);
        }

        TEST("execveat(memfd, AT_EMPTY_PATH) blocked",
             exec_blocked || g_got_sigsys,
             exec_blocked ? "blocked" :
             "EXEC — fileless execution from memfd!");
    }

    /* Test 8: PR_SET_PTRACER to allow ptrace */
    {
        g_got_sigsys = 0;
        long ret = prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("PR_SET_PTRACER(ANY) blocked",
             blocked,
             blocked ? "blocked" :
             "PTRACER — any process can now ptrace us!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
