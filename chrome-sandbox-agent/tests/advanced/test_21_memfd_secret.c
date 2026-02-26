/*
 * test_21_memfd_secret.c — memfd_create / memfd_secret fileless execution tests
 *
 * memfd_create (Linux 3.17+) creates anonymous memory-backed file descriptors.
 * Attackers use this for fileless execution: write ELF to memfd, fexecve() it.
 * Used in CVE-2024-1086 exploit chain for staging payloads.
 * Google P0 notes memfd_create is unnecessarily exposed in Chrome sandbox.
 *
 * memfd_secret (Linux 5.14+) creates memory invisible to kernel itself.
 * Could hide exploit payloads from kernel memory scanning.
 *
 * Tests:
 *  1. memfd_create availability
 *  2. memfd_create + write + mmap (payload staging)
 *  3. memfd_create + fexecve (fileless execution)
 *  4. memfd_create with MFD_CLOEXEC
 *  5. memfd_create with MFD_ALLOW_SEALING
 *  6. memfd_secret availability
 *  7. /proc/self/fd symlink to memfd
 *  8. memfd_create size limit probe
 */
#include "test_harness.h"
#include <sys/uio.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

#ifndef __NR_memfd_secret
#define __NR_memfd_secret 447
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC       0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

/* Test 1: Basic memfd_create availability */
static int try_memfd_create(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "test", 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1; /* Created! */
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 2: memfd_create + write + mmap (payload staging) */
static int try_memfd_write_mmap(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "payload", 0);
    if (g_got_sigsys || fd < 0) return fd < 0 ? 0 : -2;

    /* Write some data */
    const char payload[] = "PAYLOAD_DATA_HERE";
    if (write(fd, payload, sizeof(payload)) != sizeof(payload)) {
        close(fd);
        return 0;
    }

    /* mmap it */
    void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return 0;
    }

    /* Verify data is accessible */
    int ok = (memcmp(map, payload, sizeof(payload)) == 0);
    munmap(map, 4096);
    close(fd);
    return ok ? 1 : 0;
}

/* Test 3: memfd_create + fexecve attempt (fileless execution) */
static int try_memfd_exec(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "exec_test", MFD_CLOEXEC);
    if (g_got_sigsys || fd < 0) return fd < 0 ? 0 : -2;

    /* Write a minimal ELF-like marker (not a real binary, just test access) */
    const char elf_header[] = { 0x7f, 'E', 'L', 'F' };
    (void)!write(fd, elf_header, 4);

    /* Try to exec via /proc/self/fd/N */
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: try to execve the memfd */
        char *argv[] = { fd_path, NULL };
        char *envp[] = { NULL };
        execve(fd_path, argv, envp);
        _exit(errno == ENOEXEC ? 42 : errno == EACCES ? 43 : 44);
    }
    if (pid < 0) { close(fd); return 0; }

    int status;
    waitpid(pid, &status, 0);
    close(fd);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42) return 1; /* Got to execve (ENOEXEC = not real ELF) */
        if (code == 43) return 0; /* EACCES = blocked */
    }
    return 0;
}

/* Test 4: memfd_create with MFD_CLOEXEC */
static int try_memfd_cloexec(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "cloexec", MFD_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        /* Check CLOEXEC is set */
        int flags = fcntl(fd, F_GETFD);
        close(fd);
        return (flags & FD_CLOEXEC) ? 1 : 2;
    }
    return 0;
}

/* Test 5: memfd_create with MFD_ALLOW_SEALING */
static int try_memfd_sealing(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "sealed", MFD_ALLOW_SEALING);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        /* Try adding a seal */
        int ret = fcntl(fd, 1033 /* F_ADD_SEALS */, 0x0001 /* F_SEAL_SEAL */);
        close(fd);
        return (ret == 0) ? 1 : 2; /* 1=sealed, 2=created but seal failed */
    }
    return 0;
}

/* Test 6: memfd_secret availability */
static int try_memfd_secret(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_secret, 0);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 7: /proc/self/fd symlink to memfd reveals name */
static int try_memfd_procfd(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "secret_name", 0);
    if (g_got_sigsys || fd < 0) return 0;

    char link_path[64];
    char target[256];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link_path, target, sizeof(target) - 1);
    close(fd);

    if (len > 0) {
        target[len] = '\0';
        /* Check if memfd name leaks through */
        if (strstr(target, "memfd:")) return 1;
    }
    return 0;
}

/* Test 8: memfd_create size limit (can we allocate large anonymous files?) */
static int try_memfd_large(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "large", 0);
    if (g_got_sigsys || fd < 0) return 0;

    /* Try to allocate 64MB */
    if (ftruncate(fd, 64 * 1024 * 1024) == 0) {
        close(fd);
        return 1; /* Can allocate large memfds */
    }
    close(fd);
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MEMFD_CREATE / MEMFD_SECRET (Fileless Execution)");

    int memfd = try_memfd_create();
    TEST("memfd_create blocked",
         memfd <= 0,
         memfd == 1  ? "CREATED — fileless execution possible!" :
         memfd == -2 ? "SIGSYS (seccomp)" :
         memfd == -1 ? "ENOSYS" : "blocked");

    int memfd_mmap = try_memfd_write_mmap();
    TEST("memfd write+mmap blocked",
         memfd_mmap <= 0,
         memfd_mmap == 1 ? "WRITE+MMAP succeeded — payload staging possible!" :
                           "blocked");

    int memfd_exec = try_memfd_exec();
    TEST("memfd fexecve blocked",
         memfd_exec <= 0,
         memfd_exec == 1 ? "EXECVE reached — fileless execution!" :
                           "blocked");

    int cloexec = try_memfd_cloexec();
    TEST("memfd MFD_CLOEXEC blocked",
         cloexec <= 0,
         cloexec == 1  ? "CREATED with CLOEXEC!" :
         cloexec == 2  ? "CREATED (no CLOEXEC)!" :
         cloexec == -2 ? "SIGSYS" : "blocked");

    int sealing = try_memfd_sealing();
    TEST("memfd sealing blocked",
         sealing <= 0,
         sealing == 1  ? "SEALED — memfd fully functional!" :
         sealing == 2  ? "CREATED (seal failed)!" :
         sealing == -2 ? "SIGSYS" : "blocked");

    int secret = try_memfd_secret();
    TEST("memfd_secret blocked",
         secret <= 0,
         secret == 1  ? "CREATED — kernel-invisible memory!" :
         secret == -2 ? "SIGSYS" :
         secret == -1 ? "ENOSYS (not compiled in)" : "blocked");

    int procfd = try_memfd_procfd();
    TEST("memfd /proc/self/fd name leak blocked",
         procfd <= 0,
         procfd == 1 ? "name leaked via procfs!" : "blocked");

    int large = try_memfd_large();
    TEST("large memfd allocation blocked",
         large <= 0,
         large == 1 ? "64MB memfd allocated — resource exhaustion possible!" :
                      "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
