/*
 * test_56_shadow_stack.c — Intel CET shadow stack probing
 *
 * map_shadow_stack(2) (Linux 6.6+) creates shadow stack mappings for
 * Intel Control-flow Enforcement Technology (CET). Shadow stacks are
 * hardware-enforced return address integrity, but:
 *  - The syscall itself is new attack surface
 *  - Shadow stack pages have unique allocation properties
 *  - arch_prctl(ARCH_SHSTK_*) controls can be probed
 *  - Interaction with mprotect/mmap may have bugs
 *
 * Tests:
 *  1. map_shadow_stack() availability
 *  2. arch_prctl(ARCH_SHSTK_STATUS)
 *  3. arch_prctl(ARCH_SHSTK_ENABLE)
 *  4. map_shadow_stack with various sizes
 *  5. mprotect on shadow stack page
 *  6. munmap on shadow stack page
 *  7. /proc/cpuinfo CET feature check
 *  8. Shadow stack WRSS instruction probe
 */
#include "test_harness.h"

#ifndef __NR_map_shadow_stack
#define __NR_map_shadow_stack 453
#endif

/* arch_prctl CET defines */
#ifndef ARCH_SHSTK_ENABLE
#define ARCH_SHSTK_ENABLE  0x5001
#endif
#ifndef ARCH_SHSTK_DISABLE
#define ARCH_SHSTK_DISABLE 0x5002
#endif
#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS  0x5004
#endif
#ifndef ARCH_SHSTK_SHSTK
#define ARCH_SHSTK_SHSTK   (1ULL << 0)
#endif
#ifndef ARCH_SHSTK_WRSS
#define ARCH_SHSTK_WRSS    (1ULL << 1)
#endif

/* map_shadow_stack flags */
#define SHADOW_STACK_SET_TOKEN 0x1

/* Test 1: map_shadow_stack() availability */
static int try_map_shadow_stack(void) {
    g_got_sigsys = 0;
    void *p = (void*)syscall(__NR_map_shadow_stack, 0, 4096, 0);
    if (g_got_sigsys) return -2;
    if (p != MAP_FAILED && (long)p > 0) {
        munmap(p, 4096);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    if (errno == EOPNOTSUPP) return -3; /* CPU doesn't support CET */
    return 0;
}

/* Test 2: arch_prctl SHSTK_STATUS */
static int try_shstk_status(void) {
    g_got_sigsys = 0;
    unsigned long features = 0;
    int ret = syscall(__NR_arch_prctl, ARCH_SHSTK_STATUS, &features);
    if (g_got_sigsys) return -2;
    if (ret == 0) {
        int shstk = !!(features & ARCH_SHSTK_SHSTK);
        int wrss = !!(features & ARCH_SHSTK_WRSS);
        return (shstk ? 1 : 0) | (wrss ? 2 : 0) | 4; /* 4 = status readable */
    }
    if (errno == ENOSYS || errno == EINVAL) return -1;
    return 0;
}

/* Test 3: arch_prctl SHSTK_ENABLE */
static int try_shstk_enable(void) {
    g_got_sigsys = 0;
    /* Try to enable shadow stacks (will fail without HW support) */
    int ret = syscall(__NR_arch_prctl, ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Enabled! */
    if (errno == ENOSYS || errno == EINVAL) return -1;
    if (errno == EOPNOTSUPP) return -3;
    return 0;
}

/* Test 4: map_shadow_stack with various sizes */
static int try_shadow_sizes(void) {
    g_got_sigsys = 0;
    int created = 0;
    size_t sizes[] = { 4096, 8192, 65536, 1024*1024 };

    for (int i = 0; i < 4; i++) {
        void *p = (void*)syscall(__NR_map_shadow_stack, 0, sizes[i], 0);
        if (g_got_sigsys) return -2;
        if (p != MAP_FAILED && (long)p > 0) {
            munmap(p, sizes[i]);
            created++;
        }
    }
    return created;
}

/* Test 5: mprotect on shadow stack page */
static int try_mprotect_shadow(void) {
    g_got_sigsys = 0;
    void *p = (void*)syscall(__NR_map_shadow_stack, 0, 4096, 0);
    if (p == MAP_FAILED || (long)p <= 0) return -1;

    /* Try to change shadow stack page to RWX */
    int ret = mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    int result = (ret == 0) ? 1 : 0;

    munmap(p, 4096);
    return result;
}

/* Test 6: munmap on shadow stack page */
static int try_munmap_shadow(void) {
    g_got_sigsys = 0;
    void *p = (void*)syscall(__NR_map_shadow_stack, 0, 4096, 0);
    if (p == MAP_FAILED || (long)p <= 0) return -1;

    int ret = munmap(p, 4096);
    return (ret == 0) ? 1 : 0;
}

/* Test 7: /proc/cpuinfo CET feature check */
static int try_cpuinfo_cet(void) {
    char buf[16384];
    ssize_t n = read_file("/proc/cpuinfo", buf, sizeof(buf));
    if (n <= 0) return 0;

    int has_shstk = (strstr(buf, " shstk") != NULL);
    int has_ibt = (strstr(buf, " ibt") != NULL);

    return (has_shstk ? 1 : 0) | (has_ibt ? 2 : 0);
}

/* Test 8: Shadow stack with SET_TOKEN flag */
static int try_shadow_token(void) {
    g_got_sigsys = 0;
    void *p = (void*)syscall(__NR_map_shadow_stack, 0, 4096, SHADOW_STACK_SET_TOKEN);
    if (g_got_sigsys) return -2;
    if (p != MAP_FAILED && (long)p > 0) {
        munmap(p, 4096);
        return 1;
    }
    if (errno == ENOSYS) return -1;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("INTEL CET SHADOW STACK PROBING");

    int cpuinfo = try_cpuinfo_cet();
    TEST("CPU CET features (info)",
         1,
         cpuinfo == 3 ? "shstk + ibt available" :
         cpuinfo == 1 ? "shstk only" :
         cpuinfo == 2 ? "ibt only" :
         "no CET in cpuinfo");

    int avail = try_map_shadow_stack();
    TEST("map_shadow_stack() blocked",
         avail <= 0,
         avail == 1  ? "CREATED — shadow stack mapping!" :
         avail == -2 ? "SIGSYS" :
         avail == -1 ? "ENOSYS" :
         avail == -3 ? "no CET hardware" : "blocked");

    int status = try_shstk_status();
    TEST("ARCH_SHSTK_STATUS (info)",
         1,
         (status & 4) ? "shstk=%d wrss=%d" :
         status == -2 ? "SIGSYS" :
         status == -1 ? "not supported" : "error",
         !!(status & 1), !!(status & 2));

    int enable = try_shstk_enable();
    TEST("ARCH_SHSTK_ENABLE blocked",
         enable <= 0,
         enable == 1  ? "ENABLED — shadow stacks activated!" :
         enable == -2 ? "SIGSYS" :
         enable == -1 ? "not supported" :
         enable == -3 ? "no hardware" : "blocked");

    int sizes = try_shadow_sizes();
    TEST("shadow stack sizes (info)",
         1,
         sizes > 0 ? "%d sizes created" :
         sizes == -2 ? "SIGSYS" : "none created", sizes);

    int mprot = try_mprotect_shadow();
    if (mprot != -1) {
        TEST("mprotect shadow stack blocked",
             mprot <= 0,
             mprot == 1 ? "CHANGED — shadow stack perms modified!" : "blocked");
    }

    int unmap = try_munmap_shadow();
    if (unmap != -1) {
        TEST("munmap shadow stack (info)",
             1,
             unmap == 1 ? "unmapped" : "blocked");
    }

    int token = try_shadow_token();
    TEST("shadow stack SET_TOKEN blocked",
         token <= 0,
         token == 1  ? "CREATED with token!" :
         token == -2 ? "SIGSYS" :
         token == -1 ? "ENOSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
