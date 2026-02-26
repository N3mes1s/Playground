/*
 * test_40_syscall_enum.c — syscall enumeration audit
 *
 * Comprehensive audit of syscall accessibility from sandbox. Rather than
 * testing specific attacks, this probes whether high-risk syscalls are
 * blocked by seccomp. Uses the SIGSYS handler to detect seccomp traps.
 *
 * Categories tested:
 *  - Kernel module loading (init_module, finit_module, delete_module)
 *  - Reboot/power (reboot, kexec_load)
 *  - System configuration (syslog, sethostname, setdomainname)
 *  - Time modification (settimeofday, clock_settime, adjtimex)
 *  - Swap (swapon, swapoff)
 *  - Quotas (quotactl)
 *  - BPF (bpf syscall)
 *  - perf_event_open
 *
 * Tests:
 *  1. Module loading syscalls
 *  2. System control syscalls
 *  3. Time modification syscalls
 *  4. BPF / perf syscalls
 *  5. Swap / quota syscalls
 *  6. ptrace variants
 *  7. Dangerous ioctl probes
 *  8. Overall syscall accessibility summary
 */
#include "test_harness.h"

#ifndef __NR_finit_module
#define __NR_finit_module 313
#endif
#ifndef __NR_kexec_load
#define __NR_kexec_load 246
#endif
#ifndef __NR_bpf
#define __NR_bpf 321
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif
#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load 320
#endif
#ifndef __NR_lookup_dcookie
#define __NR_lookup_dcookie 212
#endif
#ifndef __NR_quotactl
#define __NR_quotactl 179
#endif

/* Helper: test if a syscall is blocked (seccomp, caps, or error).
 * Returns: >0 = blocked (SIGSYS/ENOSYS/EPERM/EFAULT/EINVAL/etc.), 0 = succeeded */
static int test_syscall_blocked(long nr) {
    g_got_sigsys = 0;
    long ret = syscall(nr, 0, 0, 0, 0, 0, 0);
    if (g_got_sigsys) return 1;  /* SIGSYS = blocked by seccomp */
    if (ret == -1 && errno == ENOSYS) return 1; /* kernel doesn't have it */
    if (ret == -1 && errno == EPERM) return 2;  /* exists but denied by caps */
    if (ret == -1) return 3;     /* other error (EFAULT/EINVAL) — inaccessible with bad args */
    return 0; /* actually succeeded — concerning */
}

/* Test 1: Module loading syscalls */
static int try_module_syscalls(void) {
    int blocked = 0;

    if (test_syscall_blocked(__NR_init_module) > 0) blocked++;
    if (test_syscall_blocked(__NR_finit_module) > 0) blocked++;
    if (test_syscall_blocked(__NR_delete_module) > 0) blocked++;

    return blocked; /* 3 = all blocked (good) */
}

/* Test 2: System control syscalls */
static int try_system_control(void) {
    int blocked = 0;

    /* reboot */
    g_got_sigsys = 0;
    syscall(__NR_reboot, 0, 0, 0, 0);
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* sethostname */
    g_got_sigsys = 0;
    syscall(__NR_sethostname, "evil", 4);
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* setdomainname */
    g_got_sigsys = 0;
    syscall(__NR_setdomainname, "evil", 4);
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* syslog (dmesg) */
    g_got_sigsys = 0;
    syscall(__NR_syslog, 3 /* SYSLOG_ACTION_READ_ALL */, NULL, 0);
    if (g_got_sigsys || errno == EPERM) blocked++;

    return blocked; /* 4 = all blocked */
}

/* Test 3: Time modification syscalls */
static int try_time_modification(void) {
    int blocked = 0;

    /* settimeofday */
    g_got_sigsys = 0;
    struct timeval tv = {0, 0};
    syscall(__NR_settimeofday, &tv, NULL);
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* clock_settime */
    g_got_sigsys = 0;
    struct timespec ts = {0, 0};
    syscall(__NR_clock_settime, CLOCK_REALTIME, &ts);
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* adjtimex */
    g_got_sigsys = 0;
    struct timex tx;
    memset(&tx, 0, sizeof(tx));
    syscall(__NR_adjtimex, &tx);
    if (g_got_sigsys || errno == EPERM) blocked++;

    return blocked; /* 3 = all blocked */
}

/* Test 4: BPF / perf syscalls */
static int try_bpf_perf(void) {
    int blocked = 0;

    /* bpf(BPF_PROG_LOAD) */
    g_got_sigsys = 0;
    syscall(__NR_bpf, 5 /* BPF_PROG_LOAD */, NULL, 0);
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* perf_event_open */
    g_got_sigsys = 0;
    syscall(__NR_perf_event_open, NULL, 0, -1, -1, 0);
    if (g_got_sigsys || errno == EPERM || errno == EINVAL) blocked++;

    return blocked; /* 2 = all blocked */
}

/* Test 5: Swap / quota syscalls */
static int try_swap_quota(void) {
    int blocked = 0;

    /* swapon */
    g_got_sigsys = 0;
    syscall(__NR_swapon, "/dev/null", 0);
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* swapoff */
    g_got_sigsys = 0;
    syscall(__NR_swapoff, "/dev/null");
    if (g_got_sigsys || errno == EPERM) blocked++;

    /* quotactl */
    g_got_sigsys = 0;
    syscall(__NR_quotactl, 0, NULL, 0, NULL);
    if (g_got_sigsys || errno == EPERM || errno == ENOSYS) blocked++;

    /* kexec_load */
    g_got_sigsys = 0;
    syscall(__NR_kexec_load, 0, 0, NULL, 0);
    if (g_got_sigsys || errno == EPERM) blocked++;

    return blocked; /* 4 = all blocked */
}

/* Test 6: ptrace variants */
static int try_ptrace_variants(void) {
    g_got_sigsys = 0;

    /* PTRACE_TRACEME */
    long ret1 = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    int traceme_blocked = (g_got_sigsys || ret1 < 0);

    g_got_sigsys = 0;
    /* PTRACE_ATTACH on init (pid 1) */
    long ret2 = ptrace(PTRACE_ATTACH, 1, NULL, NULL);
    int attach_blocked = (g_got_sigsys || ret2 < 0);

    return (traceme_blocked ? 0 : 1) | (attach_blocked ? 0 : 2);
}

/* Test 7: Dangerous ioctl probes */
static int try_dangerous_ioctls(void) {
    int blocked = 0;

    /* TIOCSTI — already tested but verify from enum perspective */
    g_got_sigsys = 0;
    char c = 'A';
    int ret = ioctl(0, TIOCSTI, &c);
    if (g_got_sigsys || ret < 0) blocked++;

    /* LOOP_SET_FD — loop device control */
    g_got_sigsys = 0;
    ioctl(-1, 0x4C00 /* LOOP_SET_FD */, 0);
    if (g_got_sigsys || errno == EBADF || errno == ENOTTY) blocked++;

    return blocked;
}

/* Test 8: Overall syscall summary — test a bunch of high-risk syscalls */
static int try_overall_audit(void) {
    int accessible = 0;
    int total = 0;

    struct { long nr; const char *name; } checks[] = {
        { __NR_init_module, "init_module" },
        { __NR_finit_module, "finit_module" },
        { __NR_delete_module, "delete_module" },
        { __NR_reboot, "reboot" },
        { __NR_kexec_load, "kexec_load" },
        { __NR_swapon, "swapon" },
        { __NR_swapoff, "swapoff" },
        { __NR_sethostname, "sethostname" },
        { __NR_setdomainname, "setdomainname" },
        { __NR_settimeofday, "settimeofday" },
        { __NR_bpf, "bpf" },
        { __NR_perf_event_open, "perf_event_open" },
        { __NR_lookup_dcookie, "lookup_dcookie" },
        { __NR_quotactl, "quotactl" },
        { __NR_process_vm_readv, "process_vm_readv" },
        { __NR_process_vm_writev, "process_vm_writev" },
        { __NR_keyctl, "keyctl" },
        { __NR_add_key, "add_key" },
        { __NR_request_key, "request_key" },
    };

    total = sizeof(checks) / sizeof(checks[0]);
    for (int i = 0; i < total; i++) {
        if (test_syscall_blocked(checks[i].nr) == 0)
            accessible++;
    }

    /* Return as: (total << 8) | accessible */
    return (total << 8) | accessible;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SYSCALL ENUMERATION AUDIT");

    int modules = try_module_syscalls();
    TEST("module load/delete syscalls blocked",
         modules == 3,
         modules == 3 ? "all 3 blocked" : "%d/3 blocked", modules);

    int sysctl = try_system_control();
    TEST("system control syscalls blocked",
         sysctl == 4,
         sysctl == 4 ? "all 4 blocked" : "%d/4 blocked", sysctl);

    int timectl = try_time_modification();
    TEST("time modification syscalls blocked",
         timectl == 3,
         timectl == 3 ? "all 3 blocked" : "%d/3 blocked", timectl);

    int bpf_perf = try_bpf_perf();
    TEST("bpf/perf_event_open blocked",
         bpf_perf == 2,
         bpf_perf == 2 ? "all 2 blocked" : "%d/2 blocked", bpf_perf);

    int swap = try_swap_quota();
    TEST("swap/quota/kexec blocked",
         swap == 4,
         swap == 4 ? "all 4 blocked" : "%d/4 blocked", swap);

    int ptrace = try_ptrace_variants();
    TEST("ptrace variants blocked",
         ptrace == 0,
         ptrace == 0 ? "all blocked" :
         ptrace == 1 ? "TRACEME accessible" :
         ptrace == 2 ? "ATTACH accessible" :
         "TRACEME + ATTACH accessible!");

    int ioctls = try_dangerous_ioctls();
    TEST("dangerous ioctls blocked (info)",
         1,
         "%d/2 blocked", ioctls);

    int audit = try_overall_audit();
    int total = (audit >> 8) & 0xFF;
    int accessible_count = audit & 0xFF;
    TEST("high-risk syscall audit",
         accessible_count == 0,
         accessible_count == 0 ? "0/%d accessible (clean!)" :
         "%d/%d ACCESSIBLE!", accessible_count, total);

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
