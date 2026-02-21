/*
 * test_19_ebpf.c — eBPF verifier bypass & kernel R/W tests
 *
 * eBPF verifier bugs are a recurring source of kernel LPE:
 *  - 2024: register limit tracking bug (Google Buzzer fuzzer)
 *  - CVE-2021-4204, CVE-2022-23222: verifier validation bypass
 *  - CVE-2021-31440: Kubernetes container escape via eBPF
 *
 * The eBPF verifier is supposed to ensure programs are safe, but
 * bugs in its static analysis let attackers trick it into allowing
 * programs that read/write arbitrary kernel memory.
 *
 * BPFDoor and Symbiote malware (2025) use eBPF to intercept traffic
 * and hide from user-space detection tools.
 *
 * Tests:
 *  1. bpf() syscall availability
 *  2. BPF_MAP_CREATE
 *  3. BPF_PROG_LOAD (socket filter)
 *  4. BPF_BTF_LOAD
 *  5. /sys/fs/bpf access
 *  6. perf_event_open (eBPF attachment point)
 *  7. BPF token check
 *  8. CAP_BPF check
 */
#include "test_harness.h"
#include <linux/bpf.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

/* Wrapper for bpf() syscall */
static long bpf_call(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

/* Test 1: Basic bpf() syscall availability */
static int try_bpf_syscall(void) {
    g_got_sigsys = 0;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    /* BPF_MAP_CREATE with invalid params — just testing syscall access */
    long ret = bpf_call(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (g_got_sigsys) return -2; /* SIGSYS = seccomp blocked */
    if (ret < 0 && errno == ENOSYS) return -1; /* Not compiled in */
    if (ret < 0 && errno == EPERM) return 0;   /* Permission denied */
    if (ret < 0 && errno == EINVAL) return 1;  /* Syscall reachable! */
    if (ret >= 0) { close((int)ret); return 2; } /* Created a map! */
    return 1; /* Reachable with some error */
}

/* Test 2: BPF_MAP_CREATE — array map */
static int try_bpf_map_create(void) {
    g_got_sigsys = 0;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 1;

    long ret = bpf_call(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (g_got_sigsys) return -2;
    if (ret >= 0) {
        close((int)ret);
        return 1; /* Created a BPF map! */
    }
    return 0;
}

/* Test 3: BPF_PROG_LOAD — simple socket filter */
static int try_bpf_prog_load(void) {
    g_got_sigsys = 0;
    /* Minimal BPF program: return 0 (drop) */
    struct bpf_insn insns[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0,
          .src_reg = 0, .off = 0, .imm = 0 },
        { .code = BPF_JMP | BPF_EXIT, .dst_reg = 0,
          .src_reg = 0, .off = 0, .imm = 0 },
    };

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns = (unsigned long long)(unsigned long)insns;
    attr.license = (unsigned long long)(unsigned long)"GPL";

    long ret = bpf_call(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (g_got_sigsys) return -2;
    if (ret >= 0) {
        close((int)ret);
        return 1; /* Loaded a BPF program! */
    }
    return 0;
}

/* Test 4: BPF_BTF_LOAD */
static int try_btf_load(void) {
    g_got_sigsys = 0;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.btf_size = 0; /* Invalid, but tests syscall reachability */

    long ret = bpf_call(BPF_BTF_LOAD, &attr, sizeof(attr));
    if (g_got_sigsys) return -2;
    if (ret >= 0) { close((int)ret); return 1; }
    if (errno == EPERM) return 0;
    return (errno == EINVAL) ? 1 : 0; /* EINVAL means reachable */
}

/* Test 5: /sys/fs/bpf access (pinned BPF objects) */
static int try_sysfs_bpf(void) {
    int fd = open("/sys/fs/bpf", O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 6: perf_event_open — eBPF attachment point */
static int try_perf_event_open(void) {
    g_got_sigsys = 0;
    /* Try opening a software perf event */
    struct {
        uint32_t type;
        uint32_t size;
        uint64_t config;
        /* ... minimal struct */
    } attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = 1; /* PERF_TYPE_SOFTWARE */
    attr.size = sizeof(attr);
    attr.config = 0; /* PERF_COUNT_SW_CPU_CLOCK */

    long ret = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (g_got_sigsys) return -2;
    if (ret >= 0) { close((int)ret); return 1; }
    if (errno == EPERM || errno == EACCES) return 0;
    return 0;
}

/* Test 7: Check CAP_BPF capability */
static int try_cap_bpf(void) {
    /* CAP_BPF = 39 */
    int ret = prctl(PR_CAPBSET_READ, 39);
    return (ret == 1) ? 1 : 0;
}

/* Test 8: BPF_OBJ_GET_INFO_BY_FD (enum objects) */
static int try_bpf_obj_info(void) {
    g_got_sigsys = 0;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    /* BPF_OBJ_GET_INFO_BY_FD = 15 */
    long ret = bpf_call(15, &attr, sizeof(attr));
    if (g_got_sigsys) return -2;
    if (errno == EPERM) return 0;
    return 1; /* Syscall reachable */
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("eBPF VERIFIER BYPASS & KERNEL R/W (BPFDoor 2025)");

    int bpf_sys = try_bpf_syscall();
    TEST("bpf() syscall blocked",
         bpf_sys <= 0,
         bpf_sys == 2  ? "BPF MAP CREATED — full eBPF access!" :
         bpf_sys == 1  ? "REACHABLE — eBPF syscall not blocked!" :
         bpf_sys == -2 ? "SIGSYS (seccomp)" :
         bpf_sys == -1 ? "ENOSYS" : "blocked (EPERM)");

    int bpf_map = try_bpf_map_create();
    TEST("BPF_MAP_CREATE blocked",
         bpf_map <= 0,
         bpf_map == 1  ? "CREATED — can allocate kernel objects!" :
         bpf_map == -2 ? "SIGSYS" : "blocked");

    int bpf_prog = try_bpf_prog_load();
    TEST("BPF_PROG_LOAD blocked",
         bpf_prog <= 0,
         bpf_prog == 1  ? "LOADED — can run code in kernel!" :
         bpf_prog == -2 ? "SIGSYS" : "blocked");

    int btf = try_btf_load();
    TEST("BPF_BTF_LOAD blocked",
         btf <= 0,
         btf == 1  ? "REACHABLE!" :
         btf == -2 ? "SIGSYS" : "blocked");

    int sysfs_bpf = try_sysfs_bpf();
    TEST("/sys/fs/bpf not accessible",
         sysfs_bpf == 0,
         sysfs_bpf ? "accessible — pinned BPF objects exposed!" : "blocked");

    int perf = try_perf_event_open();
    TEST("perf_event_open blocked",
         perf <= 0,
         perf == 1  ? "AVAILABLE — eBPF attachment point!" :
         perf == -2 ? "SIGSYS" : "blocked");

    int cap_bpf = try_cap_bpf();
    TEST("CAP_BPF not in bounding set",
         cap_bpf == 0,
         cap_bpf ? "CAP_BPF in bounding set (bpf() still EPERM — safe)" :
                   "dropped (good)");

    int obj_info = try_bpf_obj_info();
    TEST("BPF object enumeration blocked",
         obj_info <= 0,
         obj_info == 1  ? "REACHABLE!" :
         obj_info == -2 ? "SIGSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
