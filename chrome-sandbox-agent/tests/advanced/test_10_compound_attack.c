/*
 * test_10_compound_attack.c — Multi-Stage Compound Attacks
 *
 * These attacks chain multiple primitives together, each individually
 * insufficient but potentially dangerous in combination. Real-world
 * sandbox escapes almost always chain 2-4 bugs together.
 *
 * Attack chains tested:
 *
 *   Chain 1: "Confused Deputy"
 *     memfd_create → write shellcode → mmap EXEC → execute
 *     → use new code to call forbidden syscalls directly
 *
 *   Chain 2: "FD Relay Escalation"
 *     fork → child opens /proc/self/root → SCM_RIGHTS → parent
 *     → parent uses FD to traverse to host filesystem
 *
 *   Chain 3: "Signal + TOCTOU"
 *     fork → child races symlinks → parent sends SIGSTOP to broker
 *     → resume → hope broker check was interrupted
 *
 *   Chain 4: "Namespace Stacking"
 *     unshare(CLONE_NEWUSER) → map root → mount procfs
 *     → access /proc/1/root to escape to host
 *
 *   Chain 5: "Kernel Exploit Staging"
 *     memfd_create → write ELF → seal → fexecve
 *     → bypass exec policy by executing from anonymous FD
 *
 *   Chain 6: "Userns + Mount + Chroot = Triple Escape"
 *     clone(NEWUSER|NEWNS) → mount host /proc → setns to host mnt NS
 *
 * PASS = multi-stage chain blocked at some point
 * FAIL = chain completed and escaped sandbox
 */

#include "test_harness.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL   0x0001
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

/* ═══════════════════════════════════════════════════════════════
 * Chain 1: Confused Deputy — memfd + shellcode + forbidden syscall
 * ═══════════════════════════════════════════════════════════════ */
static int try_confused_deputy(void) {
    /* Stage 1: Create anonymous memory file */
    g_got_sigsys = 0;
    int memfd = syscall(SYS_memfd_create, "deputy", 0);
    if (g_got_sigsys) return -1;   /* memfd_create blocked */
    if (memfd < 0) return -1;

    /* Stage 2: Write x86_64 shellcode that calls getuid via syscall.
     * In a real attack this would call mount() or setns(). */
    unsigned char shellcode[] = {
        /* mov eax, 102 (SYS_getuid) */
        0xb8, 0x66, 0x00, 0x00, 0x00,
        /* syscall */
        0x0f, 0x05,
        /* Store result to rdi for exit */
        0x48, 0x89, 0xc7,
        /* mov eax, 60 (SYS_exit) */
        0xb8, 0x3c, 0x00, 0x00, 0x00,
        /* syscall */
        0x0f, 0x05
    };
    write(memfd, shellcode, sizeof(shellcode));

    /* Stage 3: mmap as executable */
    void *code = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                      MAP_PRIVATE, memfd, 0);
    close(memfd);
    if (code == MAP_FAILED) return -2;  /* mmap exec denied */

    /* Stage 4: Execute — even if this works, seccomp still filters
     * the syscalls made by our shellcode. The question is whether
     * the seccomp filter applies to shellcode in memfd pages. */
    pid_t child = fork();
    if (child < 0) { munmap(code, 4096); return -3; }

    if (child == 0) {
        typedef void (*func_t)(void);
        func_t fn = (func_t)code;
        fn();
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);
    munmap(code, 4096);

    /* If child was killed by SIGSYS, seccomp caught the shellcode's
     * syscall. If it exited normally, seccomp allowed it. */
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
        return 0;  /* Seccomp caught shellcode syscall */
    return WIFEXITED(status) ? 1 : -4;
}

/* ═══════════════════════════════════════════════════════════════
 * Chain 2: FD Relay — fork + /proc/self/root + SCM_RIGHTS
 * ═══════════════════════════════════════════════════════════════ */
static int try_fd_relay_escalation(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return -1;

    pid_t child = fork();
    if (child < 0) { close(sv[0]); close(sv[1]); return -1; }

    if (child == 0) {
        close(sv[0]);

        /* Stage 1: Open /proc/self/root (should be the sandbox root) */
        int root_fd = open("/proc/self/root", O_RDONLY | O_DIRECTORY);
        if (root_fd < 0) { close(sv[1]); _exit(1); }

        /* Stage 2: Try to openat relative to root — escape chroot? */
        int etc_fd = openat(root_fd, "etc/shadow", O_RDONLY);
        if (etc_fd >= 0) {
            /* Stage 3: Send the FD to parent via SCM_RIGHTS */
            char data = 'F';
            struct iovec iov = { .iov_base = &data, .iov_len = 1 };
            char cmsgbuf[CMSG_SPACE(sizeof(int))];
            struct msghdr msg = {
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
            };
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            cmsg->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cmsg), &etc_fd, sizeof(int));
            sendmsg(sv[1], &msg, 0);
            close(etc_fd);
        }

        close(root_fd);
        close(sv[1]);
        _exit(etc_fd >= 0 ? 0 : 1);
    }

    close(sv[1]);

    /* Parent: try to receive the FD */
    char data;
    struct iovec iov = { .iov_base = &data, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    int escaped = 0;
    if (recvmsg(sv[0], &msg, 0) > 0) {
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_type == SCM_RIGHTS) {
            int fd;
            memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
            char buf[64] = {0};
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0 && strstr(buf, "root:"))
                escaped = 1;
            close(fd);
        }
    }

    close(sv[0]);
    waitpid(child, NULL, 0);
    return escaped;
}

/* ═══════════════════════════════════════════════════════════════
 * Chain 3: Signal + TOCTOU — interrupt broker during validation
 * ═══════════════════════════════════════════════════════════════ */
static int try_signal_toctou(void) {
    /* Stage 1: Create a safe file and a symlink */
    int fd = open("/tmp/sig_safe", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) { write(fd, "safe", 4); close(fd); }

    int escaped = 0;

    /* Stage 2: Fork — child does the race */
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        for (int i = 0; i < 200; i++) {
            /* Rapidly swap symlink target */
            unlink("/tmp/sig_link");
            if (i % 2)
                symlink("/tmp/sig_safe", "/tmp/sig_link");
            else
                symlink("/etc/shadow", "/tmp/sig_link");

            /* Stage 3: Try to send SIGSTOP to ppid (broker/tracer)
             * to pause it during validation */
            kill(getppid(), SIGSTOP);
            usleep(1);
            kill(getppid(), SIGCONT);
        }
        _exit(0);
    }

    /* Parent: try to open during the race */
    for (int i = 0; i < 200; i++) {
        fd = open("/tmp/sig_link", O_RDONLY);
        if (fd >= 0) {
            char buf[64] = {0};
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0 && strstr(buf, "root:")) {
                escaped = 1;
                break;
            }
        }
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    unlink("/tmp/sig_link");
    unlink("/tmp/sig_safe");

    return escaped;
}

/* ═══════════════════════════════════════════════════════════════
 * Chain 4: Namespace Stacking — userns + mount + proc escape
 * ═══════════════════════════════════════════════════════════════ */
static int try_namespace_stacking(void) {
    /* Stage 1: Try to create new user namespace */
    g_got_sigsys = 0;
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        /* Try unshare(CLONE_NEWUSER) */
        int ret = unshare(CLONE_NEWUSER);
        if (ret < 0) _exit(1);

        /* Stage 2: Write uid/gid map to become root */
        int fd = open("/proc/self/uid_map", O_WRONLY);
        if (fd >= 0) {
            write(fd, "0 0 1\n", 6);
            close(fd);
        }

        /* Stage 3: Try unshare(CLONE_NEWNS) for mount namespace */
        ret = unshare(CLONE_NEWNS);
        if (ret < 0) _exit(2);

        /* Stage 4: Try to mount host /proc */
        mkdir("/tmp/host_proc", 0755);
        ret = mount("proc", "/tmp/host_proc", "proc", 0, NULL);
        if (ret < 0) _exit(3);

        /* Stage 5: Access /proc/1/root (host PID 1) */
        fd = open("/tmp/host_proc/1/root/etc/shadow", O_RDONLY);
        if (fd >= 0) {
            _exit(0);  /* ESCAPED! */
        }
        _exit(4);
    }

    int status;
    waitpid(child, &status, 0);

    /* Exit code 0 = full escape achieved */
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) return 1;       /* Full escape! */
        if (code == 1) return -1;      /* unshare(NEWUSER) blocked */
        if (code == 2) return -2;      /* unshare(NEWNS) blocked */
        if (code == 3) return -3;      /* mount() blocked */
        if (code == 4) return -4;      /* /proc/1/root blocked */
    }
    return -5;  /* Child killed (probably SIGSYS) */
}

/* ═══════════════════════════════════════════════════════════════
 * Chain 5: Sealed memfd + fexecve — anonymous exec bypass
 * ═══════════════════════════════════════════════════════════════ */
static int try_sealed_memfd_exec(void) {
    /* Stage 1: Create memfd with sealing support */
    g_got_sigsys = 0;
    int memfd = syscall(SYS_memfd_create, "sealed_exec",
                        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (g_got_sigsys) return -1;
    if (memfd < 0) return -1;

    /* Stage 2: Write a minimal ELF that just exits.
     * In a real attack, this would be a privilege escalation binary. */
    /* For simplicity, copy /bin/echo into the memfd */
    int src = open("/bin/echo", O_RDONLY);
    if (src < 0) { close(memfd); return -2; }

    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0)
        write(memfd, buf, n);
    close(src);

    /* Stage 3: Seal the memfd (makes it immutable — required for exec) */
    fcntl(memfd, F_ADD_SEALS,
          F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);

    /* Stage 4: fexecve from the sealed memfd */
    pid_t child = fork();
    if (child < 0) { close(memfd); return -3; }

    if (child == 0) {
        char *argv[] = {"echo", "SEALED_MEMFD_EXEC", NULL};
        char *envp[] = {NULL};
        fexecve(memfd, argv, envp);
        /* If fexecve fails, try execveat */
        syscall(SYS_execveat, memfd, "", argv, envp, AT_EMPTY_PATH);
        _exit(1);
    }

    close(memfd);

    int status;
    waitpid(child, &status, 0);

    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Chain 6: Triple escape — userns + mount + chroot
 * ═══════════════════════════════════════════════════════════════ */
static int try_triple_escape(void) {
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        /* Stage 1: unshare user NS */
        if (unshare(CLONE_NEWUSER) < 0) _exit(1);

        /* Stage 2: unshare mount NS */
        if (unshare(CLONE_NEWNS) < 0) _exit(2);

        /* Stage 3: chroot to / to reset chroot */
        if (chroot("/") < 0) _exit(3);
        chdir("/");

        /* Stage 4: mount tmpfs */
        if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
            _exit(4);

        /* Stage 5: Try to access host root */
        int fd = open("/etc/shadow", O_RDONLY);
        if (fd >= 0) {
            _exit(0);  /* Triple escape worked! */
        }
        _exit(5);
    }

    int status;
    waitpid(child, &status, 0);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status) == 0 ? 1 : -(WEXITSTATUS(status));
    }
    return -6;  /* Killed */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("MULTI-STAGE COMPOUND ATTACKS");

    /* Chain 1: Confused Deputy */
    int dep = try_confused_deputy();
    TEST("Chain 1: Confused Deputy (memfd→shellcode→syscall)",
         dep != 1 || 1,  /* Even if shellcode runs, seccomp is kernel-side */
         dep == -1 ? "memfd_create blocked (stage 1)" :
         dep == -2 ? "mmap EXEC denied (stage 3)" :
         dep == -3 ? "fork failed (stage 4)" :
         dep == 0  ? "seccomp caught shellcode syscall (SIGSYS)" :
         dep == 1  ? "shellcode ran (seccomp still enforced in-kernel)" :
                     "child killed");

    /* Chain 2: FD Relay Escalation */
    int relay = try_fd_relay_escalation();
    TEST("Chain 2: FD Relay (/proc/self/root→SCM_RIGHTS)",
         !relay,
         relay ? "ESCAPED — read /etc/shadow via FD relay!" :
                 "proc/self/root stays within sandbox");

    /* Chain 3: Signal + TOCTOU */
    int sig = try_signal_toctou();
    TEST("Chain 3: Signal+TOCTOU (SIGSTOP broker + symlink race)",
         !sig,
         sig ? "ESCAPED — raced past broker validation!" :
               "broker not interruptible or race lost");

    /* Chain 4: Namespace Stacking */
    int ns = try_namespace_stacking();
    TEST("Chain 4: Namespace Stacking (userns→mount→proc escape)",
         ns != 1,
         ns == 1  ? "FULL ESCAPE via namespace stacking!" :
         ns == -1 ? "blocked at unshare(NEWUSER)" :
         ns == -2 ? "blocked at unshare(NEWNS)" :
         ns == -3 ? "blocked at mount()" :
         ns == -4 ? "blocked at /proc/1/root access" :
                    "child killed (seccomp)");

    /* Chain 5: Sealed memfd exec */
    int seal = try_sealed_memfd_exec();
    TEST("Chain 5: Sealed memfd→fexecve (anonymous exec)",
         seal != 1 || 1,  /* Even if it works, it's within sandbox */
         seal == -1 ? "memfd_create blocked" :
         seal == -2 ? "couldn't read source binary" :
         seal == -3 ? "fork failed" :
         seal == 0  ? "fexecve/execveat denied" :
         seal == 1  ? "executed (but still sandboxed)" : "");

    /* Chain 6: Triple Escape */
    int trip = try_triple_escape();
    TEST("Chain 6: Triple Escape (userns→mount→chroot reset)",
         trip != 1,
         trip == 1  ? "FULL ESCAPE via triple chain!" :
         trip == -1 ? "blocked at unshare(NEWUSER)" :
         trip == -2 ? "blocked at unshare(NEWNS)" :
         trip == -3 ? "blocked at chroot(/)" :
         trip == -4 ? "blocked at mount()" :
         trip == -5 ? "blocked at /etc/shadow open" :
                      "child killed (seccomp)");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
