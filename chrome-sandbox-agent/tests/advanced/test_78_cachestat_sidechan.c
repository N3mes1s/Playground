/*
 * test_78_cachestat_sidechan.c — cachestat page cache side channels
 *
 * cachestat (syscall 451, Linux 6.5) reveals whether file pages are in
 * the page cache. Unlike mincore() which was restricted in Linux 5.0,
 * cachestat provides richer information including eviction counters.
 *
 * Security impact:
 *   - Detect system-wide file access patterns (page cache is shared)
 *   - Infer which programs other users are running
 *   - Measure memory pressure via eviction counters
 *   - Side channel for cross-sandbox information leakage
 *
 * Also tests fchmodat2 (452) audit bypass and shadow stack edge cases.
 *
 * Tests:
 *  1. cachestat basic availability
 *  2. cachestat activity detection (binary fingerprinting)
 *  3. cachestat eviction counters (memory pressure)
 *  4. cachestat on /proc files (proc info leak)
 *  5. fchmodat2 vs fchmodat filter gap
 *  6. fchmodat2 AT_SYMLINK_NOFOLLOW
 *  7. map_shadow_stack + fork token race
 *  8. map_shadow_stack multi-allocation
 */
#include "test_harness.h"

#ifndef __NR_cachestat
#define __NR_cachestat 451
#endif
#ifndef __NR_fchmodat2
#define __NR_fchmodat2 452
#endif
#ifndef __NR_map_shadow_stack
#define __NR_map_shadow_stack 453
#endif
#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN 0x1
#endif

struct cachestat_range {
    uint64_t off;
    uint64_t len;
};

struct cachestat {
    uint64_t nr_cache;
    uint64_t nr_dirty;
    uint64_t nr_writeback;
    uint64_t nr_evicted;
    uint64_t nr_recently_evicted;
};

int main(void) {
    install_sigsys_handler();
    setvbuf(stdout, NULL, _IONBF, 0);

    PRINT_HEADER("CACHESTAT SIDE CHANNELS & FCHMODAT2 AUDIT GAP");

    /* Test 1: cachestat basic availability */
    {
        g_got_sigsys = 0;
        int fd = open("/etc/passwd", O_RDONLY);
        int available = 0;
        if (fd >= 0) {
            struct cachestat_range range = { .off = 0, .len = 0 };
            struct cachestat cs;
            memset(&cs, 0, sizeof(cs));
            long ret = syscall(__NR_cachestat, fd, &range, &cs, 0);
            available = (ret == 0 && !g_got_sigsys);
            close(fd);
        }

        int blocked = !available || g_got_sigsys;
        TEST("cachestat() blocked",
             blocked,
             blocked ? "blocked" :
             "CACHESTAT — page cache probing available!");
    }

    /* Test 2: cachestat activity detection — can we see if binaries were run? */
    {
        g_got_sigsys = 0;
        const char *targets[] = {
            "/usr/bin/ssh", "/usr/bin/sudo",
            "/usr/bin/passwd", "/usr/sbin/sshd",
        };
        int cached_count = 0;
        int any_opened = 0;

        for (int i = 0; i < 4; i++) {
            int fd = open(targets[i], O_RDONLY);
            if (fd < 0) continue;
            any_opened = 1;
            struct cachestat_range range = { .off = 0, .len = 0 };
            struct cachestat cs;
            memset(&cs, 0, sizeof(cs));
            long ret = syscall(__NR_cachestat, fd, &range, &cs, 0);
            if (ret == 0 && cs.nr_cache > 0) cached_count++;
            close(fd);
            if (g_got_sigsys) break;
        }

        int blocked = g_got_sigsys || !any_opened;
        TEST("cachestat activity fingerprinting blocked",
             blocked || cached_count == 0,
             blocked ? "blocked" :
             cached_count > 0 ? "FINGERPRINT — detected cached binaries!" :
             "no cached binaries detected");
    }

    /* Test 3: cachestat eviction counters (memory pressure side channel) */
    {
        g_got_sigsys = 0;
        int fd = open("/etc/passwd", O_RDONLY);
        int has_eviction = 0;
        int available = 0;

        if (fd >= 0) {
            struct cachestat_range range = { .off = 0, .len = 0 };
            struct cachestat cs;
            memset(&cs, 0, sizeof(cs));
            long ret = syscall(__NR_cachestat, fd, &range, &cs, 0);
            if (ret == 0 && !g_got_sigsys) {
                available = 1;
                has_eviction = (cs.nr_evicted > 0 || cs.nr_recently_evicted > 0);
            }
            close(fd);
        }

        int blocked = g_got_sigsys || !available;
        TEST("cachestat eviction counters blocked",
             blocked,
             blocked ? "blocked" :
             has_eviction ? "EVICTION — memory pressure data available!" :
             "cachestat available but no eviction data");
    }

    /* Test 4: cachestat on /proc files */
    {
        g_got_sigsys = 0;
        int fd = open("/proc/self/maps", O_RDONLY);
        int available = 0;

        if (fd >= 0) {
            struct cachestat_range range = { .off = 0, .len = 4096 };
            struct cachestat cs;
            memset(&cs, 0, sizeof(cs));
            long ret = syscall(__NR_cachestat, fd, &range, &cs, 0);
            available = (ret == 0 && !g_got_sigsys);
            close(fd);
        }

        int blocked = g_got_sigsys || !available;
        TEST("cachestat on /proc blocked",
             blocked,
             blocked ? "blocked" :
             "PROC — cachestat works on /proc files!");
    }

    /* Test 5: fchmodat2 vs fchmodat seccomp filter gap */
    {
        g_got_sigsys = 0;
        /* Create a test file */
        int tmpfd = open("/tmp/.fchmodat2_test", O_CREAT | O_WRONLY, 0644);
        if (tmpfd >= 0) close(tmpfd);

        /* Try old fchmodat */
        g_got_sigsys = 0;
        syscall(SYS_fchmodat, AT_FDCWD, "/tmp/.fchmodat2_test", 0755);
        int old_blocked = g_got_sigsys;

        /* Try new fchmodat2 */
        g_got_sigsys = 0;
        long ret2 = syscall(__NR_fchmodat2, AT_FDCWD, "/tmp/.fchmodat2_test",
                            0755, 0);
        int new_blocked = (g_got_sigsys || (ret2 < 0 && errno == ENOSYS));

        unlink("/tmp/.fchmodat2_test");

        /* The dangerous case: old is blocked but new isn't */
        int gap = (old_blocked && !new_blocked);
        TEST("fchmodat2 seccomp gap blocked",
             !gap,
             gap ? "GAP — fchmodat blocked but fchmodat2 allowed!" :
             old_blocked && new_blocked ? "both blocked" :
             !old_blocked && !new_blocked ? "both allowed (no seccomp)" :
             "consistent filtering");
    }

    /* Test 6: fchmodat2 AT_SYMLINK_NOFOLLOW (chmod on symlink itself) */
    {
        g_got_sigsys = 0;
        unlink("/tmp/.fchmodat2_symtest");
        int linked = (symlink("/etc/passwd", "/tmp/.fchmodat2_symtest") == 0);

        int changed = 0;
        if (linked) {
            g_got_sigsys = 0;
            long ret = syscall(__NR_fchmodat2, AT_FDCWD,
                               "/tmp/.fchmodat2_symtest",
                               0777, 0x100 /* AT_SYMLINK_NOFOLLOW */);
            changed = (ret == 0 && !g_got_sigsys);
            unlink("/tmp/.fchmodat2_symtest");
        }

        int blocked = g_got_sigsys || !linked;
        TEST("fchmodat2 AT_SYMLINK_NOFOLLOW blocked",
             blocked || !changed,
             blocked ? "blocked" :
             changed ? "SYMLINK CHMOD — changed symlink permissions!" :
             "not supported on this fs");
    }

    /* Test 7: map_shadow_stack + fork token race */
    {
        g_got_sigsys = 0;
        void *shstk = (void *)syscall(__NR_map_shadow_stack, 0, 8192,
                                       SHADOW_STACK_SET_TOKEN);
        int blocked = ((long)shstk <= 0 || shstk == MAP_FAILED || g_got_sigsys);
        int fork_ok = 0;

        if (!blocked) {
            pid_t child = fork();
            if (child == 0) {
                /* Child: try to read the shadow stack (readable) */
                volatile uint64_t *top = (uint64_t *)((char *)shstk + 8192 - 8);
                volatile uint64_t token = *top;
                /* Check if token has bit 63 set (restore token format) */
                _exit((token & (1ULL << 63)) ? 99 : 0);
            }
            int status = 0;
            if (child > 0) waitpid(child, &status, 0);
            fork_ok = (WIFEXITED(status) && WEXITSTATUS(status) == 99);
            munmap(shstk, 8192);
        }

        TEST("map_shadow_stack blocked",
             blocked,
             blocked ? "blocked" :
             fork_ok ? "SHADOW STACK — token accessible after fork!" :
             "shadow stack created, no token");
    }

    /* Test 8: map_shadow_stack multi-allocation */
    {
        g_got_sigsys = 0;
        int created = 0;
        void *stacks[16];

        for (int i = 0; i < 16; i++) {
            stacks[i] = (void *)syscall(__NR_map_shadow_stack, 0, 4096,
                                         (i % 2) ? SHADOW_STACK_SET_TOKEN : 0);
            if ((long)stacks[i] > 0 && stacks[i] != MAP_FAILED && !g_got_sigsys)
                created++;
            else
                stacks[i] = NULL;
            if (g_got_sigsys) break;
        }

        for (int i = 0; i < 16; i++) {
            if (stacks[i]) munmap(stacks[i], 4096);
        }

        TEST("map_shadow_stack multi-alloc blocked",
             created == 0,
             created == 0 ? "blocked" :
             "SHADOW STACKS — %d shadow stacks created!", created);
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
