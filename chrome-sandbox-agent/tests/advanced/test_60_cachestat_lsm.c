/*
 * test_60_cachestat_lsm.c — New kernel 6.x syscalls: cachestat, fchmodat2, LSM
 *
 * Tests for recently added syscalls that create new attack surfaces:
 *
 * - cachestat (451, Linux 6.5): Query page cache statistics per-file.
 *   Can leak info about what files are cached (side-channel for
 *   determining file access patterns).
 *
 * - fchmodat2 (452, Linux 6.6): Extended fchmod with AT_SYMLINK_NOFOLLOW.
 *   Could be used to change permissions on files within sandbox.
 *
 * - lsm_get_self_attr (459, Linux 6.8): Read LSM attributes of self.
 *   Can reveal security policy configuration (AppArmor/SELinux labels).
 *
 * - lsm_set_self_attr (460, Linux 6.8): Modify LSM attributes.
 *   Direct security policy manipulation attempt.
 *
 * - lsm_list_modules (461, Linux 6.8): List loaded LSM modules.
 *   Reveals security infrastructure details.
 *
 * Tests:
 *  1. cachestat on /proc/self/exe
 *  2. cachestat info leak on /etc/passwd
 *  3. fchmodat2 permission change attempt
 *  4. fchmodat2 with AT_SYMLINK_NOFOLLOW
 *  5. lsm_get_self_attr
 *  6. lsm_set_self_attr
 *  7. lsm_list_modules
 *  8. cachestat on /proc/self/maps (info leak)
 */
#include "test_harness.h"

#ifndef __NR_cachestat
#define __NR_cachestat 451
#endif
#ifndef __NR_fchmodat2
#define __NR_fchmodat2 452
#endif
#ifndef __NR_lsm_get_self_attr
#define __NR_lsm_get_self_attr 459
#endif
#ifndef __NR_lsm_set_self_attr
#define __NR_lsm_set_self_attr 460
#endif
#ifndef __NR_lsm_list_modules
#define __NR_lsm_list_modules 461
#endif

/* cachestat structures */
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

/* LSM attribute structure */
struct lsm_ctx {
    uint64_t id;
    uint64_t flags;
    uint64_t len;
    uint64_t ctx_len;
    uint8_t  ctx[];
};

/* LSM attribute IDs */
#ifndef LSM_ATTR_CURRENT
#define LSM_ATTR_CURRENT 100
#endif

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("NEW KERNEL 6.x SYSCALLS (CACHESTAT, LSM)");

    /* Test 1: cachestat on /proc/self/exe */
    {
        g_got_sigsys = 0;
        int fd = open("/proc/self/exe", O_RDONLY);
        struct cachestat_range range = { .off = 0, .len = 4096 };
        struct cachestat cs;
        memset(&cs, 0, sizeof(cs));

        long ret = -1;
        if (fd >= 0) {
            ret = syscall(__NR_cachestat, fd, &range, &cs, 0);
            close(fd);
        }

        int blocked = (ret < 0 || g_got_sigsys);
        /* If it succeeded, check if it returned actual cache info */
        int leaked = (!blocked && (cs.nr_cache > 0 || cs.nr_dirty > 0));

        TEST("cachestat(/proc/self/exe) limited",
             blocked || !leaked,
             blocked ? "blocked (syscall denied)" :
             leaked ? "LEAKED — cache stats visible from sandbox!" :
             "no useful info returned");
    }

    /* Test 2: cachestat on /etc/passwd — probe file existence via cache */
    {
        g_got_sigsys = 0;
        int fd = open("/etc/passwd", O_RDONLY);
        struct cachestat_range range = { .off = 0, .len = 65536 };
        struct cachestat cs;
        memset(&cs, 0, sizeof(cs));

        long ret = -1;
        if (fd >= 0) {
            ret = syscall(__NR_cachestat, fd, &range, &cs, 0);
            close(fd);
        }

        int blocked = (fd < 0 || ret < 0 || g_got_sigsys);
        TEST("cachestat(/etc/passwd) info leak blocked",
             blocked,
             blocked ? "blocked" :
             "CACHE INFO — can detect file access patterns!");
    }

    /* Test 3: fchmodat2 permission change */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_fchmodat2, AT_FDCWD, "/tmp", 0777, 0);
        int blocked = (ret < 0 || g_got_sigsys);
        TEST("fchmodat2 permission change blocked",
             blocked,
             blocked ? "blocked" :
             "CHMOD — permissions changed from sandbox!");
    }

    /* Test 4: fchmodat2 with AT_SYMLINK_NOFOLLOW */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_fchmodat2, AT_FDCWD, "/proc/self/exe",
                           0777, 0x100 /* AT_SYMLINK_NOFOLLOW */);
        int blocked = (ret < 0 || g_got_sigsys);
        TEST("fchmodat2(AT_SYMLINK_NOFOLLOW) blocked",
             blocked,
             blocked ? "blocked" :
             "CHMOD — symlink nofollow chmod succeeded!");
    }

    /* Test 5: lsm_get_self_attr — read security label */
    {
        g_got_sigsys = 0;
        char attr_buf[4096];
        uint32_t size = sizeof(attr_buf);
        long ret = syscall(__NR_lsm_get_self_attr,
                           LSM_ATTR_CURRENT, attr_buf, &size, 0);
        int blocked = (ret < 0 || g_got_sigsys);
        TEST("lsm_get_self_attr blocked",
             blocked,
             blocked ? "blocked" :
             "LSM ATTR — security label readable from sandbox!");
    }

    /* Test 6: lsm_set_self_attr — modify security label */
    {
        g_got_sigsys = 0;
        struct lsm_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.id = 0;
        ctx.len = sizeof(ctx);
        long ret = syscall(__NR_lsm_set_self_attr,
                           LSM_ATTR_CURRENT, &ctx, sizeof(ctx), 0);
        int blocked = (ret < 0 || g_got_sigsys);
        TEST("lsm_set_self_attr blocked",
             blocked,
             blocked ? "blocked" :
             "LSM SET — security label MODIFIED from sandbox!");
    }

    /* Test 7: lsm_list_modules — enumerate security modules */
    {
        g_got_sigsys = 0;
        uint64_t ids[32];
        uint32_t nids = 32;
        long ret = syscall(__NR_lsm_list_modules, ids, &nids, 0);
        int blocked = (ret < 0 || g_got_sigsys);
        TEST("lsm_list_modules blocked",
             blocked,
             blocked ? "blocked" :
             "LSM LIST — security modules enumerated from sandbox!");
    }

    /* Test 8: cachestat on /proc/self/maps — memory layout leak */
    {
        g_got_sigsys = 0;
        int fd = open("/proc/self/maps", O_RDONLY);
        struct cachestat_range range = { .off = 0, .len = 4096 };
        struct cachestat cs;
        memset(&cs, 0, sizeof(cs));

        long ret = -1;
        if (fd >= 0) {
            ret = syscall(__NR_cachestat, fd, &range, &cs, 0);
            close(fd);
        }

        int blocked = (ret < 0 || g_got_sigsys);
        TEST("cachestat(/proc/self/maps) limited",
             blocked,
             blocked ? "blocked" :
             "CACHE — proc maps cache info leaked!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
