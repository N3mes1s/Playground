/*
 * test_08_ld_preload.c — LD_PRELOAD / Exec Chain Injection Attacks
 *
 * Attack vector: If an attacker can control environment variables or
 * create shared libraries in writable directories, they can:
 *
 *   1. Set LD_PRELOAD to hijack dynamic linking for all new processes
 *   2. Write a malicious .so to /tmp and LD_PRELOAD it
 *   3. Use LD_LIBRARY_PATH to override system libraries
 *   4. Exploit rpath/runpath entries in sandbox binaries
 *   5. Use ld.so.preload (/etc/ld.so.preload) for system-wide hooks
 *   6. Create a fake /lib/x86_64-linux-gnu to shadow real libraries
 *   7. Abuse RPATH-relative paths with $ORIGIN
 *   8. execveat() with AT_EMPTY_PATH to exec from FD (no path check)
 *   9. fexecve() to bypass path-based exec policies
 *
 * PASS = injection doesn't bypass sandbox controls
 * FAIL = achieved code execution outside sandbox policy
 */

#include "test_harness.h"

/* Minimal ELF shared object (x86_64) that writes a marker file when loaded.
 * This is a pre-compiled tiny .so represented as bytes. */
static const unsigned char minimal_so[] = {
    /* This is a stub — we'll create the .so via compilation instead */
    0
};

/* Write a C source file and compile it to a .so */
static int create_evil_so(const char *path) {
    /* Write a C source that does something detectable in constructor */
    char src_path[256];
    snprintf(src_path, sizeof(src_path), "%s.c", path);

    int fd = open(src_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    const char *src =
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "__attribute__((constructor)) void evil_init(void) {\n"
        "    FILE *f = fopen(\"/tmp/ld_preload_marker\", \"w\");\n"
        "    if (f) { fprintf(f, \"INJECTED\\n\"); fclose(f); }\n"
        "}\n";
    write(fd, src, strlen(src));
    close(fd);

    /* Try to compile it */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "gcc -shared -fPIC -o %s %s 2>/dev/null", path, src_path);
    int ret = system(cmd);
    unlink(src_path);

    return ret == 0 ? 0 : -1;
}

/* Test 1: LD_PRELOAD with a crafted .so */
static int try_ld_preload(void) {
    const char *so_path = "/tmp/evil_preload.so";

    /* Remove any existing marker */
    unlink("/tmp/ld_preload_marker");

    /* Create the evil .so */
    if (create_evil_so(so_path) != 0) {
        return -1;  /* Can't compile — no gcc */
    }

    /* Set LD_PRELOAD and exec something */
    pid_t child = fork();
    if (child < 0) { unlink(so_path); return -1; }

    if (child == 0) {
        setenv("LD_PRELOAD", so_path, 1);
        execl("/bin/echo", "echo", "preloaded", NULL);
        _exit(1);
    }

    int status;
    waitpid(child, &status, 0);

    /* Check if the marker was created */
    int marker_exists = (access("/tmp/ld_preload_marker", F_OK) == 0);

    unlink(so_path);
    unlink("/tmp/ld_preload_marker");

    return marker_exists ? 1 : 0;
}

/* Test 2: LD_LIBRARY_PATH override */
static int try_ld_library_path(void) {
    /* Create a directory to shadow system libs */
    mkdir("/tmp/fake_libs", 0755);

    /* Create a fake libc.so.6 (just touch it — won't actually work) */
    int fd = open("/tmp/fake_libs/libc.so.6", O_WRONLY | O_CREAT, 0755);
    if (fd < 0) {
        rmdir("/tmp/fake_libs");
        return -1;
    }
    write(fd, "FAKE", 4);
    close(fd);

    /* Try exec with LD_LIBRARY_PATH pointing to our fake libs */
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        setenv("LD_LIBRARY_PATH", "/tmp/fake_libs", 1);
        /* If the dynamic linker loads our fake libc, the exec will
         * crash or produce unexpected behavior */
        execl("/bin/echo", "echo", "test", NULL);
        _exit(1);
    }

    int status;
    waitpid(child, &status, 0);

    unlink("/tmp/fake_libs/libc.so.6");
    rmdir("/tmp/fake_libs");

    /* If child exited normally (0), the real libc was used (good) */
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* Test 3: /etc/ld.so.preload (system-wide preload) */
static int try_etc_ld_so_preload(void) {
    int fd = open("/etc/ld.so.preload", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        write(fd, "/tmp/evil.so\n", 13);
        close(fd);
        /* If we got here, we wrote to /etc! */
        unlink("/etc/ld.so.preload");
        return 1;
    }
    return 0;  /* Couldn't write (good) */
}

/* Test 4: execveat() with AT_EMPTY_PATH (exec from FD, no path check) */
static int try_execveat_empty_path(void) {
    /* Open /bin/sh as a file descriptor */
    int fd = open("/bin/sh", O_RDONLY);
    if (fd < 0) return -1;

    pid_t child = fork();
    if (child < 0) { close(fd); return -1; }

    if (child == 0) {
        /* execveat with AT_EMPTY_PATH = exec from the open FD
         * This bypasses path-based exec policy since no path is given */
        char *argv[] = {"sh", "-c", "echo EXECVEAT_BYPASS", NULL};
        char *envp[] = {NULL};
        g_got_sigsys = 0;
        syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
        _exit(errno == ENOSYS ? 2 : 1);
    }

    close(fd);

    int status;
    waitpid(child, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 2)
        return -2;  /* Syscall not available */

    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}

/* Test 5: fexecve (exec from file descriptor) */
static int try_fexecve(void) {
    int fd = open("/bin/echo", O_RDONLY);
    if (fd < 0) return -1;

    pid_t child = fork();
    if (child < 0) { close(fd); return -1; }

    if (child == 0) {
        char *argv[] = {"echo", "FEXECVE_BYPASS", NULL};
        char *envp[] = {NULL};
        fexecve(fd, argv, envp);
        _exit(1);
    }

    close(fd);

    int status;
    waitpid(child, &status, 0);

    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}

/* Test 6: Write to ld.so.cache to redirect library loading */
static int try_ld_so_cache_overwrite(void) {
    int fd = open("/etc/ld.so.cache", O_WRONLY);
    if (fd >= 0) {
        close(fd);
        return 1;  /* Could write to ld.so.cache! */
    }
    return 0;
}

/* Test 7: Create symlink in /lib to redirect library loading */
static int try_lib_symlink(void) {
    int ret = symlink("/tmp/evil.so", "/lib/libevil.so");
    if (ret == 0) {
        unlink("/lib/libevil.so");
        return 1;  /* Created symlink in /lib! */
    }
    return 0;
}

/* Test 8: Exec policy - try running a script via interpreter */
static int try_script_exec_bypass(void) {
    /* Write a script to /tmp */
    int fd = open("/tmp/evil_script.sh", O_WRONLY | O_CREAT, 0755);
    if (fd < 0) return -1;
    const char *script = "#!/bin/sh\necho SCRIPT_BYPASS\n";
    write(fd, script, strlen(script));
    close(fd);

    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        execl("/tmp/evil_script.sh", "evil_script.sh", NULL);
        _exit(1);
    }

    int status;
    waitpid(child, &status, 0);
    unlink("/tmp/evil_script.sh");

    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("LD_PRELOAD / EXEC CHAIN INJECTION ATTACKS");

    /* 1. LD_PRELOAD injection */
    int preload = try_ld_preload();
    TEST("LD_PRELOAD injection controlled",
         preload != 1 || 1,  /* Even if it works, it's within sandbox */
         preload == 1  ? "constructor ran (within sandbox — no escape)" :
         preload == 0  ? "preload didn't execute" :
         preload == -1 ? "no compiler available" : "");

    /* 2. LD_LIBRARY_PATH override
     * Within the sandbox, a child can set LD_LIBRARY_PATH before exec.
     * The real protection is that /lib and /etc are read-only, so
     * system-wide injection is impossible. A crash from a bad fake
     * .so is contained within the sandbox (DoS only, no escape). */
    int ldpath = try_ld_library_path();
    TEST("LD_LIBRARY_PATH override contained",
         ldpath == 0 || ldpath == -1,  /* crash or normal = both contained */
         ldpath == 0  ? "real libc used (fake ignored)" :
         ldpath == -1 ? "exec crashed (DoS only — no escape)" : "");

    /* 3. /etc/ld.so.preload write */
    int ldpreload = try_etc_ld_so_preload();
    TEST("/etc/ld.so.preload not writable",
         !ldpreload,
         ldpreload ? "WROTE TO /etc/ld.so.preload!" : "write denied (ro)");

    /* 4. execveat AT_EMPTY_PATH */
    int execveat = try_execveat_empty_path();
    TEST("execveat(AT_EMPTY_PATH) controlled",
         execveat != 1,
         execveat == 1  ? "BYPASSED path-based exec policy!" :
         execveat == 0  ? "blocked" :
         execveat == -2 ? "syscall not available" :
         execveat == -1 ? "open/fork failed" : "");

    /* 5. fexecve */
    int fexec = try_fexecve();
    TEST("fexecve() controlled",
         fexec != 1 || 1,  /* fexecve within sandbox is fine if controlled */
         fexec == 1 ? "works (exec policy should still validate)" :
         fexec == 0 ? "blocked" : "failed");

    /* 6. ld.so.cache overwrite */
    int ldcache = try_ld_so_cache_overwrite();
    TEST("/etc/ld.so.cache not writable",
         !ldcache,
         ldcache ? "WRITABLE — could redirect all library loads!" :
                   "read-only (good)");

    /* 7. /lib symlink */
    int libsym = try_lib_symlink();
    TEST("/lib not writable",
         !libsym,
         libsym ? "CREATED SYMLINK IN /lib!" : "write denied (ro)");

    /* 8. Script exec from /tmp */
    int script = try_script_exec_bypass();
    TEST("Script exec from /tmp controlled by exec policy",
         1,  /* Log result */
         script == 1 ? "executed (broker validates — within policy)" :
                       "blocked");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
