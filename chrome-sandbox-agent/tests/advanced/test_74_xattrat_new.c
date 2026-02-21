/*
 * test_74_xattrat_new.c — New xattr-at syscalls (Linux 6.13, January 2025)
 *
 * Linux 6.13 added four new syscalls that many seccomp profiles don't
 * filter yet:
 *   - getxattrat (466): Read extended attributes relative to dirfd
 *   - setxattrat (467): Set extended attributes relative to dirfd
 *   - listxattrat (468): List extended attributes relative to dirfd
 *   - removexattrat (469): Remove extended attributes relative to dirfd
 *
 * These were confirmed MISSING from the Linux audit read class
 * (audit_read.h), meaning they bypass audit and may bypass seccomp
 * allowlists that whitelist old xattr syscalls.
 *
 * Security impact: Can read/write security-sensitive xattrs like
 * security.selinux, security.capability, and security.apparmor
 * without being filtered.
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
#define __NR_getxattrat 466
#endif
#ifndef __NR_setxattrat
#define __NR_setxattrat 467
#endif
#ifndef __NR_listxattrat
#define __NR_listxattrat 468
#endif
#ifndef __NR_removexattrat
#define __NR_removexattrat 469
#endif

/* xattr_args structure for *at syscalls (Linux 6.13) */
struct xattr_args {
    uint64_t value;     /* pointer to value buffer */
    uint32_t size;      /* size of value buffer */
    uint32_t flags;     /* XATTR_CREATE, XATTR_REPLACE */
};

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NEW XATTRAT SYSCALLS (LINUX 6.13 — SECCOMP GAP)");

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
        int blocked = (ret < 0 && (g_got_sigsys || errno == ENOSYS));
        TEST("getxattrat() blocked",
             blocked,
             blocked ? "blocked" :
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
        int blocked = (ret < 0 && (g_got_sigsys || errno == ENOSYS));
        TEST("setxattrat() blocked",
             blocked,
             blocked ? "blocked" :
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
        int blocked = (ret < 0 && (g_got_sigsys || errno == ENOSYS));
        TEST("listxattrat() blocked",
             blocked,
             blocked ? "blocked" :
             "LISTXATTRAT — xattr enumeration via new syscall!");
    }

    /* Test 4: removexattrat — remove security xattr */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_removexattrat, AT_FDCWD, "/proc/self/exe",
                           "security.selinux", 0);
        int blocked = (ret < 0 && (g_got_sigsys || errno == ENOSYS));
        TEST("removexattrat(security.selinux) blocked",
             blocked,
             blocked ? "blocked" :
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
        int blocked = (ret < 0 && (g_got_sigsys || errno == ENOSYS));
        TEST("getxattrat(security.selinux) blocked",
             blocked,
             blocked ? "blocked" :
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
        int blocked = (ret < 0 && (g_got_sigsys || errno == ENOSYS));
        TEST("getxattrat(security.capability) blocked",
             blocked,
             blocked ? "blocked" :
             "CAPABILITY — file capabilities readable via new syscall!");
    }

    /* Test 7: Old getxattr for comparison */
    {
        g_got_sigsys = 0;
        char buf[256];
        long ret = syscall(SYS_getxattr, "/proc/self/exe",
                           "security.selinux", buf, sizeof(buf));
        int blocked = (ret < 0 || g_got_sigsys);
        TEST("getxattr (old) comparison",
             blocked,
             blocked ? "blocked" :
             "old getxattr accessible (expected)");
    }

    /* Test 8: Old setxattr for comparison */
    {
        g_got_sigsys = 0;
        const char *val = "test";
        long ret = syscall(SYS_setxattr, "/tmp/test", "user.test",
                           val, strlen(val), 0);
        int blocked = (ret < 0 || g_got_sigsys);
        TEST("setxattr (old) comparison",
             blocked,
             blocked ? "blocked" :
             "old setxattr accessible");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
