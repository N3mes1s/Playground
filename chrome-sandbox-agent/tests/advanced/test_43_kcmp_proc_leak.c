/*
 * test_43_kcmp_proc_leak.c — kcmp() and /proc information leaks
 *
 * kcmp(2) compares kernel resources between processes, potentially leaking:
 *  - Whether two FDs point to the same file description
 *  - Whether processes share VM, files, filesystem, etc.
 *  - Used in exploits to confirm cross-process FD duplication
 *
 * Also tests /proc information leaks that aid exploitation:
 *  - /proc/self/maps: ASLR bypass (library/heap/stack addresses)
 *  - /proc/self/syscall: Currently executing syscall
 *  - /proc/self/wchan: Wait channel (kernel function name)
 *  - /proc/self/stack: Full kernel stack trace
 *  - /proc/self/pagemap: Physical page mapping
 *  - /proc/self/smaps: Detailed memory map
 *  - /proc/self/auxv: ELF auxiliary vector (base addresses)
 *
 * Tests:
 *  1. kcmp(KCMP_FILE) between FDs
 *  2. kcmp(KCMP_VM) between processes
 *  3. /proc/self/maps readable (ASLR bypass)
 *  4. /proc/self/syscall readable
 *  5. /proc/self/stack readable
 *  6. /proc/self/pagemap readable
 *  7. /proc/self/smaps readable
 *  8. /proc/self/auxv readable
 */
#include "test_harness.h"

#ifndef __NR_kcmp
#define __NR_kcmp 312
#endif

/* kcmp types */
#define KCMP_FILE  0
#define KCMP_VM    1
#define KCMP_FILES 2
#define KCMP_FS    3
#define KCMP_SIGHAND 4
#define KCMP_IO    5

/* Test 1: kcmp(KCMP_FILE) between two FDs */
static int try_kcmp_file(void) {
    g_got_sigsys = 0;
    int fd1 = open("/dev/null", O_RDONLY);
    if (fd1 < 0) return 0;
    int fd2 = dup(fd1);
    if (fd2 < 0) { close(fd1); return 0; }

    pid_t me = getpid();
    long ret = syscall(__NR_kcmp, me, me, KCMP_FILE, fd1, fd2);

    close(fd1);
    close(fd2);

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Same file description — kcmp works */
    if (ret > 0) return 2;  /* Different — still worked */
    if (errno == ENOSYS) return -1;
    if (errno == EPERM) return 0;
    return 0;
}

/* Test 2: kcmp(KCMP_VM) between parent and child */
static int try_kcmp_vm(void) {
    g_got_sigsys = 0;
    pid_t me = getpid();

    pid_t child = fork();
    if (child == 0) {
        /* Child sleeps briefly */
        usleep(50000);
        _exit(0);
    }
    if (child < 0) return 0;

    long ret = syscall(__NR_kcmp, me, child, KCMP_VM, 0, 0);
    int result;

    if (g_got_sigsys) result = -2;
    else if (ret >= 0) result = 1; /* Can compare VMs */
    else if (errno == EPERM) result = 0;
    else if (errno == ENOSYS) result = -1;
    else result = 0;

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

/* Test 3: /proc/self/maps readable (ASLR info leak) */
static int try_proc_maps(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/maps", buf, sizeof(buf));
    if (n <= 0) return 0;

    /* Check if we can see library addresses */
    int has_stack = (strstr(buf, "[stack]") != NULL);
    int has_heap = (strstr(buf, "[heap]") != NULL);
    int has_vdso = (strstr(buf, "[vdso]") != NULL);
    int has_lib = (strstr(buf, ".so") != NULL);

    return (has_stack ? 1 : 0) | (has_heap ? 2 : 0) |
           (has_vdso ? 4 : 0) | (has_lib ? 8 : 0);
}

/* Test 4: /proc/self/syscall readable */
static int try_proc_syscall(void) {
    char buf[256];
    ssize_t n = read_file("/proc/self/syscall", buf, sizeof(buf));
    if (n <= 0) return 0;
    return 1; /* Contains current syscall number and args */
}

/* Test 5: /proc/self/stack readable */
static int try_proc_stack(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/stack", buf, sizeof(buf));
    if (n <= 0) return 0;
    /* Stack contains kernel function names — useful for exploits */
    return 1;
}

/* Test 6: /proc/self/pagemap readable */
static int try_proc_pagemap(void) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;

    /* Try to read a pagemap entry for our own stack */
    uint64_t entry = 0;
    /* Calculate offset for stack address */
    char stack_var;
    unsigned long addr = (unsigned long)&stack_var;
    off_t offset = (addr / 4096) * sizeof(uint64_t);

    int readable = 0;
    if (lseek(fd, offset, SEEK_SET) >= 0) {
        ssize_t n = read(fd, &entry, sizeof(entry));
        if (n == sizeof(entry)) readable = 1;
    }

    close(fd);
    return readable;
}

/* Test 7: /proc/self/smaps readable */
static int try_proc_smaps(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/smaps", buf, sizeof(buf));
    if (n <= 0) return 0;

    /* smaps reveals RSS, PSS, referenced pages, etc. */
    int has_rss = (strstr(buf, "Rss:") != NULL);
    int has_pss = (strstr(buf, "Pss:") != NULL);
    return (has_rss ? 1 : 0) | (has_pss ? 2 : 0);
}

/* Test 8: /proc/self/auxv readable */
static int try_proc_auxv(void) {
    int fd = open("/proc/self/auxv", O_RDONLY);
    if (fd < 0) return 0;

    /* auxv contains AT_BASE (ld.so base), AT_PHDR, etc. — ASLR bypass */
    uint64_t buf[32];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);

    if (n > 0) return 1;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("KCMP & /PROC INFORMATION LEAKS");

    int kcmp_file = try_kcmp_file();
    TEST("kcmp(KCMP_FILE) blocked",
         kcmp_file <= 0,
         kcmp_file == 1  ? "SAME — FD comparison works!" :
         kcmp_file == 2  ? "DIFFERENT — kcmp accessible!" :
         kcmp_file == -2 ? "SIGSYS" :
         kcmp_file == -1 ? "ENOSYS" : "blocked");

    int kcmp_vm = try_kcmp_vm();
    TEST("kcmp(KCMP_VM) blocked",
         kcmp_vm <= 0,
         kcmp_vm == 1  ? "COMPARABLE — VM comparison across processes!" :
         kcmp_vm == -2 ? "SIGSYS" :
         kcmp_vm == -1 ? "ENOSYS" : "blocked");

    int maps = try_proc_maps();
    TEST("/proc/self/maps info leak (info)",
         1,
         maps == 0 ? "not readable" :
         "readable (stack=%d heap=%d vdso=%d lib=%d)",
         !!(maps & 1), !!(maps & 2), !!(maps & 4), !!(maps & 8));

    int sc = try_proc_syscall();
    TEST("/proc/self/syscall (info)",
         1,
         sc == 1 ? "readable (syscall state visible)" : "not readable");

    int stack = try_proc_stack();
    TEST("/proc/self/stack blocked",
         stack <= 0,
         stack == 1 ? "READABLE — kernel stack trace exposed!" : "blocked");

    int pagemap = try_proc_pagemap();
    TEST("/proc/self/pagemap blocked",
         pagemap <= 0,
         pagemap == 1 ? "READABLE — physical page info exposed!" : "blocked");

    int smaps = try_proc_smaps();
    TEST("/proc/self/smaps (info)",
         1,
         smaps == 0 ? "not readable" :
         "readable (rss=%d pss=%d)", !!(smaps & 1), !!(smaps & 2));

    int auxv = try_proc_auxv();
    TEST("/proc/self/auxv (info — ASLR bypass aid)",
         1,
         auxv == 1 ? "readable (ELF base addresses)" : "not readable");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
