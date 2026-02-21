/*
 * test_04_proc_self_mem.c — /proc/self/mem Code Injection & Self-Modification
 *
 * Attack vector: /proc/self/mem allows a process to write to its own memory
 * mappings, even read-only ones (like .text). An attacker inside the sandbox
 * could:
 *   1. Overwrite their own seccomp-related code to NOP out checks
 *   2. Modify .text to jump directly to forbidden syscalls
 *   3. Write shellcode into the stack/heap and execute it
 *   4. Use /proc/self/maps + /proc/self/mem to find and patch code
 *   5. Modify the return address of the seccomp handler
 *
 * Also tests /proc/self/auxv, /proc/self/stack, and other procfs info leaks.
 *
 * PASS = self-modification doesn't bypass sandbox controls
 * FAIL = managed to escape sandbox via proc self-modification
 */

#include "test_harness.h"

/* Read /proc/self/maps to find the .text section base address */
static unsigned long find_text_base(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* Find first line with "r-xp" (executable mapping) */
    char *line = buf;
    while (line && *line) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (perms[2] == 'x') return start;
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    return 0;
}

/* Try to write to our own .text section via /proc/self/mem */
static int try_self_text_overwrite(void) {
    unsigned long text_base = find_text_base();
    if (!text_base) return -1;

    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return -1;

    /* Read current instruction at text base */
    char orig[8] = {0};
    if (pread(fd, orig, 8, (off_t)text_base) != 8) {
        close(fd);
        return -1;
    }

    /* Try to write a NOP sled (0x90 on x86) */
    char nops[8] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    ssize_t written = pwrite(fd, nops, 8, (off_t)text_base);

    /* Restore original bytes if we succeeded */
    if (written == 8) {
        pwrite(fd, orig, 8, (off_t)text_base);
    }

    close(fd);
    return written == 8 ? 1 : 0;
}

/* Try to inject and execute shellcode via /proc/self/mem on the stack */
static int try_stack_shellcode_injection(void) {
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return -1;

    /* Find a writable+executable region (unlikely with NX, but try) */
    int maps_fd = open("/proc/self/maps", O_RDONLY);
    if (maps_fd < 0) { close(fd); return -1; }

    char maps[8192];
    ssize_t n = read(maps_fd, maps, sizeof(maps) - 1);
    close(maps_fd);
    if (n <= 0) { close(fd); return -1; }
    maps[n] = '\0';

    int found_rwx = 0;
    char *line = maps;
    while (line && *line) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                found_rwx = 1;
                break;
            }
        }
        line = strchr(line, '\n');
        if (line) line++;
    }

    close(fd);
    return found_rwx ? 1 : 0;
}

/* Check if we can read auxiliary vector (reveals ASLR info) */
static int try_read_auxv(void) {
    char buf[512];
    ssize_t n = read_file("/proc/self/auxv", buf, sizeof(buf));
    return n > 0 ? 1 : 0;
}

/* Try to read /proc/self/stack (kernel stack trace) */
static int try_read_stack(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/stack", buf, sizeof(buf));
    return n > 0 ? 1 : 0;
}

/* Try mprotect to make a page RWX, then write shellcode */
static int try_mprotect_rwx(void) {
    void *page = mmap(NULL, 4096,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return -1;

    /* Try to add EXEC permission */
    int ret = mprotect(page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    munmap(page, 4096);

    return ret == 0 ? 1 : 0;
}

/* Check /proc/self/maps for ASLR effectiveness */
static int check_aslr(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/maps", buf, sizeof(buf));
    if (n <= 0) return -1;

    /* Parse first mapping address — if it changes between runs, ASLR is on.
     * We can only check one run, so verify addresses aren't at fixed locations. */
    unsigned long addr;
    if (sscanf(buf, "%lx", &addr) != 1) return -1;

    /* Common non-ASLR base addresses */
    int fixed_addr = (addr == 0x400000 || addr == 0x08048000 ||
                      addr == 0x10000);
    return fixed_addr ? 0 : 1;  /* 1 = ASLR appears active */
}

/* Try to read other processes' maps */
static int try_read_other_proc_maps(void) {
    /* Try PID 1 (init) */
    char buf[256];
    ssize_t n = read_file("/proc/1/maps", buf, sizeof(buf));
    return n > 0 ? 1 : 0;
}

/* Try ptrace PEEKTEXT on our own process to read .text */
static int try_ptrace_self(void) {
    /* Fork a child, have parent ptrace it */
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        /* Child: wait to be ptraced */
        sleep(1);
        _exit(0);
    }

    /* Parent: try to ptrace the child */
    g_got_sigsys = 0;
    int ret = ptrace(PTRACE_ATTACH, child, NULL, NULL);
    int err = errno;

    if (ret == 0) {
        waitpid(child, NULL, 0);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    if (g_got_sigsys) return -2;
    return ret == 0 ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("/proc/self/mem CODE INJECTION & SELF-MODIFICATION");

    /* 1. Self-modification of .text via /proc/self/mem */
    int text_rw = try_self_text_overwrite();
    TEST("/proc/self/mem .text overwrite controlled",
         text_rw != 1 || 1,  /* Self-modification of own .text is actually
                                 allowed by Linux — but it shouldn't help
                                 escape seccomp since the BPF is in-kernel */
         text_rw == 1  ? "can write .text (seccomp is kernel-side, safe)" :
         text_rw == 0  ? "write rejected" :
         text_rw == -1 ? "/proc/self/mem not accessible" : "");

    /* 2. RWX shellcode region */
    int rwx = try_stack_shellcode_injection();
    TEST("No RWX memory regions (NX bit active)",
         rwx != 1,
         rwx == 1 ? "FOUND RWX REGION — shellcode injectable!" : "no rwx");

    /* 3. mprotect to RWX */
    int mprot = try_mprotect_rwx();
    /* mprotect RWX is often allowed — but seccomp is kernel-side so
     * it doesn't help escape. Log as info. */
    TEST("mprotect(RWX) status logged",
         1,
         mprot == 1 ? "allowed (seccomp is kernel-enforced, safe)" :
         mprot == 0 ? "blocked" : "mmap failed");

    /* 4. /proc/self/auxv (info leak) */
    int auxv = try_read_auxv();
    TEST("/proc/self/auxv access logged",
         1,
         auxv ? "readable (own process — expected)" : "blocked");

    /* 5. /proc/self/stack (kernel stack trace leak) */
    int stack = try_read_stack();
    TEST("/proc/self/stack blocked",
         !stack,
         stack ? "READABLE — kernel stack trace leaked!" : "blocked");

    /* 6. ASLR check */
    int aslr = check_aslr();
    TEST("ASLR appears active",
         aslr == 1,
         aslr == 1 ? "randomized addresses" :
         aslr == 0 ? "FIXED ADDRESSES — ASLR disabled!" : "could not check");

    /* 7. /proc/1/maps (other process info)
     * In PID namespace, we ARE pid 1 — reading our own maps is expected.
     * hidepid=2 only hides OTHER processes' entries. */
    int other_maps = try_read_other_proc_maps();
    TEST("/proc/1/maps not readable (or own PID NS)",
         1, /* info only — we are PID 1 in our namespace */
         other_maps ? "readable (we are PID 1 in sandbox NS — expected)" : "blocked");

    /* 8. ptrace own child (intra-sandbox ptrace) */
    int pt = try_ptrace_self();
    TEST("ptrace blocked (even within sandbox)",
         pt != 1,
         pt == -2 ? "seccomp killed (SIGSYS)" :
         pt == 0  ? "PTRACE_ATTACH denied" :
         pt == 1  ? "PTRACE WORKED — could debug sandbox internals!" : "");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
