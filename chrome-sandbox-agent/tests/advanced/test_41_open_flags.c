/* test_41_open_flags.c — O_LARGEFILE and open flag security tests
 *
 * Tests that stripping O_LARGEFILE from the broker's flag check
 * doesn't create a bypass vector. Verifies:
 * 1. O_LARGEFILE + O_RDONLY on allowed paths → allowed
 * 2. O_LARGEFILE + O_WRONLY on read-only paths → denied
 * 3. O_LARGEFILE + O_RDWR on read-only paths → denied
 * 4. O_LARGEFILE + O_CREAT on read-only paths → denied
 * 5. Open with smuggled flags (O_LARGEFILE | O_WRONLY | O_TRUNC) → denied
 * 6. Raw syscall 2 (open) works same as syscall 257 (openat) for reads
 * 7. Raw open with all dangerous flag combos → denied on sensitive paths
 * 8. O_LARGEFILE doesn't bypass deny-list (/etc/shadow)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

static int pass_count = 0;
static int fail_count = 0;

#define O_LARGEFILE_VAL 0100000  /* 0x8000 — musl's O_LARGEFILE on x86_64 */

#define TEST(name, cond) do { \
    if (cond) { pass_count++; printf("  [PASS] %s\n", name); } \
    else { fail_count++; printf("  [FAIL] %s\n", name); } \
} while(0)

int main() {
    printf("=== Test 41: open() flag security (O_LARGEFILE) ===\n");

    /* 1. O_LARGEFILE + O_RDONLY on /proc (allowed path) */
    {
        int fd = syscall(SYS_open, "/proc/self/status",
                         O_RDONLY | O_CLOEXEC | O_LARGEFILE_VAL);
        TEST("O_LARGEFILE|O_RDONLY on /proc → allowed",
             fd >= 0 || errno == ENOENT);
        if (fd >= 0) close(fd);
    }

    /* 2. O_LARGEFILE + O_WRONLY on /etc (read-only) → denied */
    {
        int fd = syscall(SYS_open, "/etc/hosts",
                         O_WRONLY | O_LARGEFILE_VAL);
        TEST("O_LARGEFILE|O_WRONLY on /etc/hosts → denied",
             fd < 0 && (errno == EACCES || errno == EROFS || errno == EPERM));
        if (fd >= 0) close(fd);
    }

    /* 3. O_LARGEFILE + O_RDWR on /etc → denied */
    {
        int fd = syscall(SYS_open, "/etc/passwd",
                         O_RDWR | O_LARGEFILE_VAL);
        TEST("O_LARGEFILE|O_RDWR on /etc/passwd → denied",
             fd < 0 && (errno == EACCES || errno == EROFS || errno == EPERM));
        if (fd >= 0) close(fd);
    }

    /* 4. O_LARGEFILE + O_CREAT on /etc → denied */
    {
        int fd = syscall(SYS_open, "/etc/evil_file",
                         O_WRONLY | O_CREAT | O_LARGEFILE_VAL, 0644);
        TEST("O_LARGEFILE|O_CREAT on /etc → denied",
             fd < 0 && (errno == EACCES || errno == EROFS || errno == EPERM));
        if (fd >= 0) { unlink("/etc/evil_file"); close(fd); }
    }

    /* 5. Open with smuggled dangerous flags → denied on read-only paths */
    {
        int fd = syscall(SYS_open, "/usr/bin/env",
                         O_WRONLY | O_TRUNC | O_LARGEFILE_VAL);
        TEST("O_LARGEFILE|O_WRONLY|O_TRUNC on /usr/bin → denied",
             fd < 0 && (errno == EACCES || errno == EROFS || errno == EPERM));
        if (fd >= 0) close(fd);
    }

    /* 6. Raw syscall 2 and 257 should have same behavior for reads */
    {
        int fd_open = syscall(SYS_open, "/proc/self/status",
                              O_RDONLY | O_LARGEFILE_VAL);
        int fd_openat = syscall(SYS_openat, AT_FDCWD, "/proc/self/status",
                                O_RDONLY);
        int both_ok = (fd_open >= 0 && fd_openat >= 0);
        int both_fail = (fd_open < 0 && fd_openat < 0);
        TEST("open() and openat() consistent for reads",
             both_ok || both_fail);
        if (fd_open >= 0) close(fd_open);
        if (fd_openat >= 0) close(fd_openat);
    }

    /* 7. O_LARGEFILE + O_APPEND on read-only path → denied */
    {
        int fd = syscall(SYS_open, "/etc/hostname",
                         O_WRONLY | O_APPEND | O_LARGEFILE_VAL);
        TEST("O_LARGEFILE|O_WRONLY|O_APPEND on /etc → denied",
             fd < 0 && (errno == EACCES || errno == EROFS || errno == EPERM));
        if (fd >= 0) close(fd);
    }

    /* 8. O_LARGEFILE doesn't bypass deny-list */
    {
        int fd = syscall(SYS_open, "/etc/shadow",
                         O_RDONLY | O_LARGEFILE_VAL);
        TEST("O_LARGEFILE on /etc/shadow → still denied",
             fd < 0 && (errno == EACCES || errno == ENOENT || errno == EPERM));
        if (fd >= 0) close(fd);
    }

    printf("\nResult: %d/%d passed\n", pass_count, pass_count + fail_count);
    return fail_count > 0 ? 1 : 0;
}
