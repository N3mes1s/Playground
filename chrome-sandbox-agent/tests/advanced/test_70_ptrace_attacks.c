/*
 * test_70_ptrace_attacks.c — ptrace-based sandbox escape vectors
 *
 * ptrace is one of the most powerful syscalls for sandbox escapes:
 *   - PTRACE_ATTACH to other processes
 *   - PTRACE_PEEKDATA/POKEDATA for memory read/write
 *   - PTRACE_GETREGS/SETREGS for register manipulation
 *   - PTRACE_SEIZE for non-stop debugging
 *   - PTRACE_SYSCALL for syscall interception
 *   - /proc/[pid]/mem write via ptrace attachment
 *
 * Tests:
 *  1. PTRACE_TRACEME (allow parent to trace)
 *  2. PTRACE_ATTACH to child process
 *  3. PTRACE_PEEKDATA from child
 *  4. PTRACE_POKEDATA to child
 *  5. PTRACE_SEIZE (non-stop mode)
 *  6. PTRACE_GETREGSET
 *  7. ptrace + /proc/pid/mem write
 *  8. PTRACE_ATTACH to PID 1 (init)
 */
#include "test_harness.h"
#include <sys/uio.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif

/* NT_PRSTATUS for GETREGSET */
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("PTRACE-BASED SANDBOX ESCAPE VECTORS");

    /* Test 1: PTRACE_TRACEME */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            _exit(ret == 0 ? 99 : 0);
        }
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);
        int child_ret = WIFEXITED(status) ? WEXITSTATUS(status) : 0;

        TEST("PTRACE_TRACEME blocked",
             child_ret != 99,
             child_ret == 99 ? "TRACEME — process now traceable!" :
             "blocked");
    }

    /* Test 2: PTRACE_ATTACH to child */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            /* Child: just sleep */
            sleep(5);
            _exit(0);
        }
        int attached = 0;
        if (pid > 0) {
            usleep(10000); /* Let child start */
            long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
            if (ret == 0) {
                attached = 1;
                waitpid(pid, NULL, 0); /* Wait for stop */
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }

        TEST("PTRACE_ATTACH blocked",
             !attached || g_got_sigsys,
             attached ? "ATTACHED — can debug other processes!" :
             "blocked");
    }

    /* Test 3: PTRACE_PEEKDATA */
    {
        g_got_sigsys = 0;
        volatile long target_data = 0xDEADBEEF;

        pid_t pid = fork();
        if (pid == 0) {
            sleep(5);
            _exit(0);
        }
        int peeked = 0;
        if (pid > 0) {
            usleep(10000);
            if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
                waitpid(pid, NULL, 0);
                errno = 0;
                long data = ptrace(PTRACE_PEEKDATA, pid,
                                   (void *)&target_data, NULL);
                peeked = (errno == 0 && data != 0);
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }

        TEST("PTRACE_PEEKDATA blocked",
             !peeked || g_got_sigsys,
             peeked ? "PEEKED — can read other process memory!" :
             "blocked");
    }

    /* Test 4: PTRACE_POKEDATA */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            sleep(5);
            _exit(0);
        }
        int poked = 0;
        if (pid > 0) {
            usleep(10000);
            if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
                waitpid(pid, NULL, 0);
                /* Try to write to child's stack */
                long ret = ptrace(PTRACE_POKEDATA, pid,
                                  (void *)0x7fffffffe000UL, 0x41414141UL);
                poked = (ret == 0);
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }

        TEST("PTRACE_POKEDATA blocked",
             !poked || g_got_sigsys,
             poked ? "POKED — can write other process memory!" :
             "blocked");
    }

    /* Test 5: PTRACE_SEIZE (non-stop) */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            sleep(5);
            _exit(0);
        }
        int seized = 0;
        if (pid > 0) {
            usleep(10000);
            long ret = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
            if (ret == 0) {
                seized = 1;
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }

        TEST("PTRACE_SEIZE blocked",
             !seized || g_got_sigsys,
             seized ? "SEIZED — non-stop debug from sandbox!" :
             "blocked");
    }

    /* Test 6: PTRACE_GETREGSET */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            sleep(5);
            _exit(0);
        }
        int got_regs = 0;
        if (pid > 0) {
            usleep(10000);
            if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
                waitpid(pid, NULL, 0);
                char regbuf[512];
                struct iovec iov = {
                    .iov_base = regbuf,
                    .iov_len = sizeof(regbuf),
                };
                long ret = ptrace(PTRACE_GETREGSET, pid,
                                  (void *)(uintptr_t)NT_PRSTATUS, &iov);
                got_regs = (ret == 0);
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }

        TEST("PTRACE_GETREGSET blocked",
             !got_regs || g_got_sigsys,
             got_regs ? "REGS — can read other process registers!" :
             "blocked");
    }

    /* Test 7: ptrace + /proc/pid/mem write */
    {
        g_got_sigsys = 0;
        pid_t pid = fork();
        if (pid == 0) {
            sleep(5);
            _exit(0);
        }
        int mem_written = 0;
        if (pid > 0) {
            usleep(10000);
            if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
                waitpid(pid, NULL, 0);

                char path[64];
                snprintf(path, sizeof(path), "/proc/%d/mem", pid);
                int memfd = open(path, O_WRONLY);
                if (memfd >= 0) {
                    mem_written = 1;
                    close(memfd);
                }
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
            }
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }

        TEST("ptrace + /proc/pid/mem write blocked",
             !mem_written || g_got_sigsys,
             mem_written ? "MEM WRITE — /proc/pid/mem writable!" :
             "blocked");
    }

    /* Test 8: PTRACE_ATTACH to PID 1 (init) */
    {
        g_got_sigsys = 0;
        long ret = ptrace(PTRACE_ATTACH, 1, NULL, NULL);
        int attached = (ret == 0);
        if (attached) {
            ptrace(PTRACE_DETACH, 1, NULL, NULL);
        }

        TEST("PTRACE_ATTACH PID 1 blocked",
             !attached || g_got_sigsys,
             attached ? "INIT TRACED — attached to PID 1!" :
             "blocked");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
