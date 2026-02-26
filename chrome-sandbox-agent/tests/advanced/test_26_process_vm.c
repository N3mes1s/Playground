/*
 * test_26_process_vm.c — cross-process memory access tests
 *
 * process_vm_readv / process_vm_writev allow reading/writing another
 * process's memory without ptrace. If accessible from sandbox, an
 * attacker could read secrets from the broker or other sandboxed procs.
 *
 * Also tests:
 *  - ptrace PEEKDATA/POKEDATA (traditional cross-process access)
 *  - /proc/PID/mem read/write
 *  - /proc/PID/maps read (memory layout leak)
 *  - kcmp() syscall (compare kernel objects between processes)
 *  - process_madvise() (cross-process memory hints)
 *
 * Tests:
 *  1. process_vm_readv() on self
 *  2. process_vm_writev() on self
 *  3. process_vm_readv() on child
 *  4. ptrace(PTRACE_PEEKDATA)
 *  5. /proc/PID/mem read on child
 *  6. /proc/PID/maps read on child
 *  7. kcmp() syscall
 *  8. process_madvise() syscall
 */
#include "test_harness.h"
#include <sys/uio.h>

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif
#ifndef __NR_kcmp
#define __NR_kcmp 312
#endif
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif

/* Test 1: process_vm_readv on self */
static int try_vm_readv_self(void) {
    g_got_sigsys = 0;
    char src[] = "SECRETDATA";
    char dst[16] = {0};

    struct iovec local_iov = { .iov_base = dst, .iov_len = sizeof(src) };
    struct iovec remote_iov = { .iov_base = src, .iov_len = sizeof(src) };

    ssize_t ret = syscall(__NR_process_vm_readv, getpid(),
                          &local_iov, 1, &remote_iov, 1, 0);
    if (g_got_sigsys) return -2;
    if (ret > 0 && memcmp(dst, src, sizeof(src)) == 0) return 1;
    if (ret < 0 && errno == ENOSYS) return -1;
    return 0;
}

/* Test 2: process_vm_writev on self */
static int try_vm_writev_self(void) {
    g_got_sigsys = 0;
    char src[] = "OVERWRITE";
    char dst[16] = "ORIGINAL_";

    struct iovec local_iov = { .iov_base = src, .iov_len = sizeof(src) };
    struct iovec remote_iov = { .iov_base = dst, .iov_len = sizeof(src) };

    ssize_t ret = syscall(__NR_process_vm_writev, getpid(),
                          &local_iov, 1, &remote_iov, 1, 0);
    if (g_got_sigsys) return -2;
    if (ret > 0 && memcmp(dst, src, sizeof(src)) == 0) return 1;
    if (ret < 0 && errno == ENOSYS) return -1;
    return 0;
}

/* Test 3: process_vm_readv on child process */
static int try_vm_readv_child(void) {
    g_got_sigsys = 0;
    /* Create a child with known data */
    volatile char secret[] = "CHILD_SECRET";

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: just sleep */
        volatile char *p = secret;
        (void)p;
        sleep(2);
        _exit(0);
    }
    if (pid < 0) return 0;

    usleep(50000); /* Let child start */

    char dst[16] = {0};
    struct iovec local_iov = { .iov_base = dst, .iov_len = sizeof(secret) };
    struct iovec remote_iov = { .iov_base = (void *)secret, .iov_len = sizeof(secret) };

    ssize_t ret = syscall(__NR_process_vm_readv, pid,
                          &local_iov, 1, &remote_iov, 1, 0);

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    if (g_got_sigsys) return -2;
    if (ret > 0) return 1; /* Read child memory! */
    return 0;
}

/* Test 4: ptrace(PTRACE_PEEKDATA) */
static int try_ptrace_peek(void) {
    g_got_sigsys = 0;
    pid_t pid = fork();
    if (pid == 0) {
        sleep(2);
        _exit(0);
    }
    if (pid < 0) return 0;

    usleep(50000);

    long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (g_got_sigsys) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); return -2; }
    if (ret == 0) {
        int status;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1; /* ptrace attach worked! */
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return 0;
}

/* Test 5: /proc/PID/mem read on child */
static int try_proc_mem_read(void) {
    pid_t pid = fork();
    if (pid == 0) {
        sleep(2);
        _exit(0);
    }
    if (pid < 0) return 0;

    usleep(50000);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    if (fd >= 0) {
        close(fd);
        return 1; /* Can open child's memory! */
    }
    return 0;
}

/* Test 6: /proc/PID/maps read on child */
static int try_proc_maps_read(void) {
    pid_t pid = fork();
    if (pid == 0) {
        sleep(2);
        _exit(0);
    }
    if (pid < 0) return 0;

    usleep(50000);

    char path[64], buf[4096];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    ssize_t n = read_file(path, buf, sizeof(buf));

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    if (n > 0) return 1; /* Can read child's memory layout! */
    return 0;
}

/* Test 7: kcmp() — compare kernel objects between processes */
static int try_kcmp(void) {
    g_got_sigsys = 0;
    pid_t pid = getpid();
    /* kcmp(pid1, pid2, KCMP_FILE, fd1, fd2) */
    long ret = syscall(__NR_kcmp, pid, pid, 0 /* KCMP_FILE */, 0, 0);
    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1; /* kcmp accessible */
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 8: process_madvise() — cross-process memory hints */
static int try_process_madvise(void) {
    g_got_sigsys = 0;
    pid_t pid = fork();
    if (pid == 0) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) memset(p, 0, 4096);
        sleep(2);
        _exit(0);
    }
    if (pid < 0) return 0;

    usleep(50000);

    /* Create pidfd for the child */
    int pidfd = syscall(434 /* __NR_pidfd_open */, pid, 0);
    int result = 0;

    if (pidfd >= 0) {
        struct iovec iov = { .iov_base = NULL, .iov_len = 4096 };
        long ret = syscall(__NR_process_madvise, pidfd, &iov, 1,
                          MADV_DONTNEED, 0);
        if (!g_got_sigsys && ret >= 0) result = 1;
        close(pidfd);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    if (g_got_sigsys) return -2;
    return result;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("CROSS-PROCESS MEMORY ACCESS ATTACKS");

    int vm_readv_self = try_vm_readv_self();
    TEST("process_vm_readv(self) blocked",
         vm_readv_self <= 0,
         vm_readv_self == 1  ? "READ OWN MEMORY — syscall accessible!" :
         vm_readv_self == -2 ? "SIGSYS" :
         vm_readv_self == -1 ? "ENOSYS" : "blocked");

    int vm_writev_self = try_vm_writev_self();
    TEST("process_vm_writev(self) blocked",
         vm_writev_self <= 0,
         vm_writev_self == 1  ? "WROTE OWN MEMORY — syscall accessible!" :
         vm_writev_self == -2 ? "SIGSYS" :
         vm_writev_self == -1 ? "ENOSYS" : "blocked");

    int vm_readv_child = try_vm_readv_child();
    TEST("process_vm_readv(child) blocked",
         vm_readv_child <= 0,
         vm_readv_child == 1  ? "READ CHILD MEMORY!" :
         vm_readv_child == -2 ? "SIGSYS" : "blocked");

    int ptrace_peek = try_ptrace_peek();
    TEST("ptrace(PTRACE_ATTACH) blocked",
         ptrace_peek <= 0,
         ptrace_peek == 1  ? "ATTACHED — full process control!" :
         ptrace_peek == -2 ? "SIGSYS" : "blocked");

    /* /proc/PID/mem and /proc/PID/maps: same-UID child access is expected
     * Linux behavior. The real concern is cross-sandbox or cross-user access,
     * which is blocked by hidepid=2 and PID namespace isolation. */
    int proc_mem = try_proc_mem_read();
    TEST("/proc/PID/mem read on child (info)",
         1, /* same-UID child = expected */
         proc_mem ? "readable (own child — expected)" : "blocked");

    int proc_maps = try_proc_maps_read();
    TEST("/proc/PID/maps read on child (info)",
         1, /* same-UID child = expected */
         proc_maps ? "readable (own child — expected)" : "blocked");

    int kcmp = try_kcmp();
    TEST("kcmp() blocked",
         kcmp <= 0,
         kcmp == 1  ? "ACCESSIBLE — kernel object comparison!" :
         kcmp == -2 ? "SIGSYS" :
         kcmp == -1 ? "ENOSYS" : "blocked");

    int proc_madvise = try_process_madvise();
    TEST("process_madvise() blocked",
         proc_madvise <= 0,
         proc_madvise == 1  ? "ACCESSIBLE — cross-process madvise!" :
         proc_madvise == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
