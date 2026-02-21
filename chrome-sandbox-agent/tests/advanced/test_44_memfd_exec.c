/*
 * test_44_memfd_exec.c — memfd_create fileless execution chains
 *
 * memfd_create(2) creates anonymous files backed by RAM. Combined with
 * execveat(2) or fexecve(3), this enables fileless execution — running
 * binaries that never touch disk. This is the #1 technique for:
 *  - Malware that evades file-based detection
 *  - Sandbox escape payloads that bypass filesystem restrictions
 *  - Loading exploit code without write access to any filesystem
 *
 * Also tests related fileless execution vectors:
 *  - memfd_create + MFD_CLOEXEC vs MFD_ALLOW_SEALING
 *  - Writing ELF headers to memfd
 *  - execveat(fd, "", ..., AT_EMPTY_PATH) — execute by FD
 *  - /proc/self/fd/N exec
 *  - shm_open as alternative anonymous file
 *
 * Tests:
 *  1. memfd_create basic
 *  2. memfd_create + write ELF payload
 *  3. memfd_create + execveat AT_EMPTY_PATH
 *  4. memfd_create + /proc/self/fd exec
 *  5. memfd_create MFD_ALLOW_SEALING + seal
 *  6. memfd_create name visibility in /proc
 *  7. shm_open anonymous file
 *  8. Multiple memfd accumulation (memory exhaustion)
 */
#include "test_harness.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC        0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING  0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS  (1024 + 9)
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE  0x0008
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW   0x0004
#endif

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif
#ifndef __NR_execveat
#define __NR_execveat 322
#endif

/* Minimal ELF that just does exit(42) — x86_64 */
static const unsigned char mini_elf[] = {
    /* ELF header */
    0x7f, 'E', 'L', 'F',  /* magic */
    2, 1, 1, 0,            /* 64-bit, little-endian, ELF v1, SysV ABI */
    0,0,0,0,0,0,0,0,       /* padding */
    2, 0,                   /* ET_EXEC */
    0x3e, 0,                /* EM_X86_64 */
    1,0,0,0,               /* EV_CURRENT */
    0x78,0x00,0x40,0,0,0,0,0, /* e_entry = 0x400078 */
    0x40,0,0,0,0,0,0,0,    /* e_phoff = 64 */
    0,0,0,0,0,0,0,0,       /* e_shoff */
    0,0,0,0,               /* e_flags */
    0x40,0,                 /* e_ehsize = 64 */
    0x38,0,                 /* e_phentsize = 56 */
    1,0,                    /* e_phnum = 1 */
    0,0,                    /* e_shentsize */
    0,0,                    /* e_shnum */
    0,0,                    /* e_shstrndx */
    /* Program header (LOAD) */
    1,0,0,0,               /* PT_LOAD */
    5,0,0,0,               /* PF_R | PF_X */
    0,0,0,0,0,0,0,0,       /* p_offset */
    0,0,0x40,0,0,0,0,0,    /* p_vaddr = 0x400000 */
    0,0,0x40,0,0,0,0,0,    /* p_paddr */
    0x84,0,0,0,0,0,0,0,    /* p_filesz */
    0x84,0,0,0,0,0,0,0,    /* p_memsz */
    0,0,0x20,0,0,0,0,0,    /* p_align */
    /* Code at offset 0x78: mov rdi, 42; mov rax, 60; syscall */
    0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, /* mov rdi, 42 */
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, /* mov rax, 60 (exit) */
    0x0f, 0x05,                                 /* syscall */
    0x00, 0x00,                                 /* padding */
};

/* Test 1: memfd_create basic */
static int try_memfd_basic(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "test", MFD_CLOEXEC);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 2: memfd_create + write ELF payload */
static int try_memfd_elf_write(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "payload", MFD_CLOEXEC);
    if (fd < 0) return 0;

    ssize_t n = write(fd, mini_elf, sizeof(mini_elf));
    close(fd);

    if (g_got_sigsys) return -2;
    return (n == sizeof(mini_elf)) ? 1 : 0;
}

/* Test 3: memfd_create + execveat AT_EMPTY_PATH */
static int try_memfd_execveat(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "exec_test", MFD_CLOEXEC);
    if (fd < 0) return 0;

    write(fd, mini_elf, sizeof(mini_elf));

    pid_t pid = fork();
    if (pid == 0) {
        /* Make fd executable */
        fchmod(fd, 0755);
        char *argv[] = { "memfd_exec", NULL };
        char *envp[] = { NULL };
        syscall(__NR_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
        _exit(errno == EACCES ? 43 : errno == ENOEXEC ? 44 : 45);
    }

    close(fd);
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (g_got_sigsys) return -2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
        return 1; /* Fileless execution succeeded! */
    return 0;
}

/* Test 4: memfd_create + /proc/self/fd exec */
static int try_memfd_proc_exec(void) {
    g_got_sigsys = 0;
    /* Don't use MFD_CLOEXEC so the fd survives exec */
    int fd = syscall(__NR_memfd_create, "proc_exec", 0);
    if (fd < 0) return 0;

    write(fd, mini_elf, sizeof(mini_elf));
    fchmod(fd, 0755);

    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);

    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { "memfd_exec", NULL };
        char *envp[] = { NULL };
        execve(fdpath, argv, envp);
        _exit(errno == EACCES ? 43 : 45);
    }

    close(fd);
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);

    if (g_got_sigsys) return -2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
        return 1; /* /proc/self/fd exec worked! */
    return 0;
}

/* Test 5: memfd_create MFD_ALLOW_SEALING + sealing */
static int try_memfd_sealing(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "sealed", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return 0;

    write(fd, "test data", 9);

    /* Apply seals */
    int ret = fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW);
    close(fd);

    if (g_got_sigsys) return -2;
    return (ret == 0) ? 1 : 0;
}

/* Test 6: memfd name visibility in /proc */
static int try_memfd_procfs_name(void) {
    g_got_sigsys = 0;
    int fd = syscall(__NR_memfd_create, "secret_payload", MFD_CLOEXEC);
    if (fd < 0) return 0;

    char link[256];
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(fdpath, link, sizeof(link) - 1);

    close(fd);

    if (n > 0) {
        link[n] = '\0';
        /* Name visible as /memfd:secret_payload (deleted) */
        return (strstr(link, "memfd:") != NULL) ? 1 : 0;
    }
    return 0;
}

/* Test 7: shm_open as alternative anonymous file */
static int try_shm_open(void) {
    g_got_sigsys = 0;
    int fd = open("/dev/shm/test_sandbox_shm", O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (g_got_sigsys) return -2;
        return 0;
    }

    write(fd, "test", 4);
    fchmod(fd, 0755);

    close(fd);
    unlink("/dev/shm/test_sandbox_shm");
    return 1;
}

/* Test 8: Multiple memfd accumulation */
static int try_memfd_accumulate(void) {
    g_got_sigsys = 0;
    int count = 0;
    int fds[256];

    for (int i = 0; i < 256; i++) {
        fds[i] = syscall(__NR_memfd_create, "spam", MFD_CLOEXEC);
        if (fds[i] < 0) break;
        /* Write 1MB to each */
        ftruncate(fds[i], 1024 * 1024);
        count++;
    }

    /* Cleanup */
    for (int i = 0; i < count; i++)
        close(fds[i]);

    if (g_got_sigsys) return -2;
    return count;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MEMFD FILELESS EXECUTION CHAINS");

    int basic = try_memfd_basic();
    TEST("memfd_create (info)",
         1,
         basic == 1  ? "available (fileless execution primitive)" :
         basic == -2 ? "SIGSYS" :
         basic == -1 ? "ENOSYS" : "blocked");

    int elf = try_memfd_elf_write();
    TEST("memfd + ELF payload write (info)",
         1,
         elf == 1  ? "ELF written to memfd" :
         elf == -2 ? "SIGSYS" : "blocked");

    int execveat = try_memfd_execveat();
    TEST("memfd + execveat fileless exec blocked",
         execveat <= 0,
         execveat == 1  ? "EXECUTED — fileless binary from memfd!" :
         execveat == -2 ? "SIGSYS" : "blocked");

    int proc_exec = try_memfd_proc_exec();
    TEST("memfd + /proc/self/fd exec blocked",
         proc_exec <= 0,
         proc_exec == 1  ? "EXECUTED — via /proc/self/fd!" :
         proc_exec == -2 ? "SIGSYS" : "blocked");

    int seal = try_memfd_sealing();
    TEST("memfd sealing (info)",
         1,
         seal == 1  ? "sealing works" :
         seal == -2 ? "SIGSYS" : "blocked");

    int name = try_memfd_procfs_name();
    TEST("memfd name in /proc (info)",
         1,
         name == 1 ? "visible as memfd:* in /proc" : "not visible");

    int shm = try_shm_open();
    TEST("/dev/shm writable (info)",
         1,
         shm == 1  ? "writable (shared memory available)" :
         shm == -2 ? "SIGSYS" : "blocked");

    int accum = try_memfd_accumulate();
    TEST("memfd accumulation (info — DoS potential)",
         1,
         "%d memfds created (1MB each)", accum);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
