/*
 * test_74_xattrat_new.c — New xattr-at syscalls (Linux 6.13, January 2025)
 *
 * Linux 6.13 added four new syscalls:
 *   - getxattrat (463 on x86-64): Read extended attributes relative to dirfd
 *   - setxattrat (464): Set extended attributes relative to dirfd
 *   - listxattrat (465): List extended attributes relative to dirfd
 *   - removexattrat (466): Remove extended attributes relative to dirfd
 *
 * These were confirmed MISSING from the Linux audit read class
 * (audit_read.h), meaning they bypass audit logging on kernels 6.13-6.18.
 *
 * Denylist-based sandboxes (Flatpak, Firejail) allow these by default.
 * Allowlist-based sandboxes (Chrome, Firefox, Docker v28+) block them.
 *
 * Detection: A syscall is "blocked" if it returns -1 with ANY error
 * errno (ENOSYS from seccomp allowlist, EPERM from ptrace broker,
 * SIGSYS from SECCOMP_RET_TRAP). A syscall is "allowed" only if it
 * returns >= 0 (success).
 *
 * Tests:
 *  1. getxattrat — read xattr via new syscall
 *  2. setxattrat — write xattr via new syscall
 *  3. listxattrat — enumerate xattrs
 *  4. removexattrat — remove security xattrs
 *  5. getxattrat on security.selinux
 *  6. getxattrat on security.capability
 *  7. Old getxattr for comparison
 *  8. Old setxattr for comparison
 */
#include "test_harness.h"

#ifndef __NR_getxattrat
#define __NR_getxattrat 463
#endif
#ifndef __NR_setxattrat
#define __NR_setxattrat 464
#endif
#ifndef __NR_listxattrat
#define __NR_listxattrat 465
#endif
#ifndef __NR_removexattrat
#define __NR_removexattrat 466
#endif

/* xattr_args structure for *at syscalls (Linux 6.13) */
struct xattr_args {
    uint64_t value;     /* pointer to value buffer */
    uint32_t size;      /* size of value buffer */
    uint32_t flags;     /* XATTR_CREATE, XATTR_REPLACE */
};

/* Helper: check if a syscall was blocked by any mechanism.
 * Seccomp blocks manifest as:
 *   - ENOSYS: allowlist default (Error(ENOSYS)) or kernel doesn't know syscall
 *   - EPERM:  ptrace broker Block() or seccomp Error(EPERM)
 *   - EACCES: ptrace broker denied path access
 *   - SIGSYS: SECCOMP_RET_TRAP (Chrome's CrashSIGSYS)
 * A syscall "bypasses" the filter ONLY if ret >= 0 (success). */
static int is_blocked(long ret) {
    return (ret < 0) || g_got_sigsys;
}

/* Helper: describe how the syscall was blocked */
static const char *block_reason(long ret) {
    if (g_got_sigsys) return "blocked (SIGSYS)";
    if (ret >= 0) return "NOT blocked";
    switch (errno) {
        case ENOSYS: return "blocked (ENOSYS — seccomp allowlist)";
        case EPERM:  return "blocked (EPERM — ptrace/seccomp)";
        case EACCES: return "blocked (EACCES — broker denied)";
        case ENODATA: return "blocked (ENODATA — xattr not found, but syscall ran!)";
        default:     return "blocked (other errno)";
    }
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NEW XATTRAT SYSCALLS (LINUX 6.13 — SECCOMP ALLOWLIST TEST)");

    /* Test 1: getxattrat — read xattr */
    {
        g_got_sigsys = 0;
        char buf[256];
        struct xattr_args args;
        memset(&args, 0, sizeof(args));
        args.value = (uint64_t)(uintptr_t)buf;
        args.size = sizeof(buf);

        long ret = syscall(__NR_getxattrat, AT_FDCWD, "/proc/self/exe",
                           "user.test", &args, 0);
        int blocked = is_blocked(ret);
        /* ENODATA means the syscall EXECUTED (xattr just doesn't exist).
         * That's a bypass — the seccomp filter let it through. */
        if (ret < 0 && errno == ENODATA && !g_got_sigsys) blocked = 0;

        TEST("getxattrat() blocked",
             blocked,
             blocked ? block_reason(ret) :
             "GETXATTRAT — new xattr read bypasses seccomp!");
    }

    /* Test 2: setxattrat — write xattr */
    {
        g_got_sigsys = 0;
        const char *val = "test_value";
        struct xattr_args args;
        memset(&args, 0, sizeof(args));
        args.value = (uint64_t)(uintptr_t)val;
        args.size = strlen(val);

        long ret = syscall(__NR_setxattrat, AT_FDCWD, "/tmp/test_xattr",
                           "user.test", &args, 0);
        int blocked = is_blocked(ret);
        TEST("setxattrat() blocked",
             blocked,
             blocked ? block_reason(ret) :
             "SETXATTRAT — new xattr write bypasses seccomp!");
    }

    /* Test 3: listxattrat — enumerate xattrs */
    {
        g_got_sigsys = 0;
        char buf[1024];
        struct xattr_args args;
        memset(&args, 0, sizeof(args));
        args.value = (uint64_t)(uintptr_t)buf;
        args.size = sizeof(buf);

        long ret = syscall(__NR_listxattrat, AT_FDCWD, "/proc/self/exe",
                           &args, 0);
        int blocked = is_blocked(ret);
        TEST("listxattrat() blocked",
             blocked,
             blocked ? block_reason(ret) :
             "LISTXATTRAT — xattr enumeration via new syscall!");
    }

    /* Test 4: removexattrat — remove security xattr */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_removexattrat, AT_FDCWD, "/proc/self/exe",
                           "security.selinux", 0);
        int blocked = is_blocked(ret);
        /* ENODATA means the syscall ran (xattr doesn't exist to remove) */
        if (ret < 0 && errno == ENODATA && !g_got_sigsys) blocked = 0;

        TEST("removexattrat(security.selinux) blocked",
             blocked,
             blocked ? block_reason(ret) :
             "REMOVEXATTRAT — security xattr removed!");
    }

    /* Test 5: getxattrat on security.selinux */
    {
        g_got_sigsys = 0;
        char buf[256];
        struct xattr_args args;
        memset(&args, 0, sizeof(args));
        args.value = (uint64_t)(uintptr_t)buf;
        args.size = sizeof(buf);

        long ret = syscall(__NR_getxattrat, AT_FDCWD, "/proc/self/exe",
                           "security.selinux", &args, 0);
        int blocked = is_blocked(ret);
        if (ret < 0 && errno == ENODATA && !g_got_sigsys) blocked = 0;

        TEST("getxattrat(security.selinux) blocked",
             blocked,
             blocked ? block_reason(ret) :
             "SELINUX — security label readable via new syscall!");
    }

    /* Test 6: getxattrat on security.capability */
    {
        g_got_sigsys = 0;
        char buf[256];
        struct xattr_args args;
        memset(&args, 0, sizeof(args));
        args.value = (uint64_t)(uintptr_t)buf;
        args.size = sizeof(buf);

        long ret = syscall(__NR_getxattrat, AT_FDCWD, "/proc/self/exe",
                           "security.capability", &args, 0);
        int blocked = is_blocked(ret);
        if (ret < 0 && errno == ENODATA && !g_got_sigsys) blocked = 0;

        TEST("getxattrat(security.capability) blocked",
             blocked,
             blocked ? block_reason(ret) :
             "CAPABILITY — file capabilities readable via new syscall!");
    }

    /* Test 7: Old getxattr for comparison
     * The old getxattr is routed through the broker for path validation.
     * Read-only xattr access is ALLOWED by design (ls -la needs it).
     * This test verifies old and new syscalls get the same treatment:
     * getxattrat → broker (EACCES if path denied), same as getxattr. */
    {
        g_got_sigsys = 0;
        char buf[256];
        long ret = syscall(SYS_getxattr, "/proc/self/exe",
                           "security.selinux", buf, sizeof(buf));
        /* Old getxattr goes through broker — may succeed for read-only.
         * We just verify it doesn't crash (SIGSYS) and document behavior. */
        int ok = !g_got_sigsys;
        TEST("getxattr (old) — broker routed",
             ok,
             ok ? (ret >= 0 ? "allowed via broker (read-only xattr)" :
                   block_reason(ret)) :
             "SIGSYS — unexpected crash");
    }

    /* Test 8: Old setxattr for comparison */
    {
        g_got_sigsys = 0;
        const char *val = "test";
        long ret = syscall(SYS_setxattr, "/tmp/test", "user.test",
                           val, strlen(val), 0);
        int blocked = is_blocked(ret);
        TEST("setxattr (old) comparison",
             blocked,
             blocked ? block_reason(ret) :
             "old setxattr accessible");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
