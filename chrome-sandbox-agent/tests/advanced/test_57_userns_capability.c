/*
 * test_57_userns_capability.c — User namespace capability escalation chains
 *
 * Creating a user namespace grants full capabilities inside it, which
 * can be used to access privileged kernel interfaces. Google found that
 * 44% of kernel exploits require unprivileged user namespaces.
 *
 * Based on: Qualys 2025 (3 Ubuntu namespace restriction bypasses),
 *           DEVCORE 2025 (AppArmor bypass), CVE-2022-0185 (fsconfig)
 *
 * Attack chain: CLONE_NEWUSER → CAP_SYS_ADMIN inside → access:
 *   - Netfilter (CVE-2024-1086 vector)
 *   - BPF (CVE-2023-2163 vector)
 *   - Mount filesystem (CVE-2022-0185 vector)
 *   - Hostname/domainname modification
 *   - Keyring manipulation
 *
 * Tests:
 *  1. unshare(CLONE_NEWUSER) capability gain
 *  2. User NS + netfilter socket (CVE-2024-1086 chain)
 *  3. User NS + BPF (CVE-2023-2163 chain)
 *  4. User NS + mount (CVE-2022-0185 chain)
 *  5. User NS + sethostname
 *  6. User NS + network namespace
 *  7. User NS + mount namespace
 *  8. uid_map/gid_map writability
 */
#include "test_harness.h"
#include <linux/netlink.h>

#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif

/* Run a test function inside a new user namespace.
 * Returns the child's exit code: 99=success, 0=failed, other=error */
static int run_in_userns(int (*fn)(void)) {
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: try to create user namespace */
        if (unshare(CLONE_NEWUSER) != 0) _exit(0);

        /* We now have CAP_SYS_ADMIN inside the namespace */
        int result = fn();
        _exit(result);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 0;
}

/* Test 1 helper: Check capabilities inside user NS */
static int check_caps(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/self/status", buf, sizeof(buf));
    if (n <= 0) return 0;

    char *line = strstr(buf, "CapEff:");
    if (!line) return 0;

    unsigned long long cap_eff = 0;
    if (sscanf(line, "CapEff:\t%llx", &cap_eff) != 1) return 0;

    /* Check for key capabilities */
    int has_sys_admin = !!(cap_eff & (1ULL << 21));  /* CAP_SYS_ADMIN */
    int has_net_admin = !!(cap_eff & (1ULL << 12));  /* CAP_NET_ADMIN */

    if (has_sys_admin && has_net_admin) return 99;
    if (has_sys_admin) return 98;
    return 1;
}

/* Test 2 helper: Netfilter socket inside user NS */
static int try_netfilter_in_ns(void) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (sock >= 0) {
        close(sock);
        return 99; /* Netfilter accessible! */
    }
    return 0;
}

/* Test 3 helper: BPF inside user NS */
static int try_bpf_in_ns(void) {
    long ret = syscall(__NR_bpf, 0 /* BPF_MAP_CREATE */, NULL, 0);
    /* If we get anything other than EPERM/ENOSYS, bpf is accessible */
    if (ret >= 0) return 99;
    if (errno == EFAULT || errno == EINVAL) return 99; /* Syscall reached */
    return 0;
}

/* Test 4 helper: Mount inside user NS */
static int try_mount_in_ns(void) {
    /* Need mount namespace too */
    if (unshare(CLONE_NEWNS) != 0) return 0;

    int ret = mount("none", "/tmp", "tmpfs", 0, "");
    if (ret == 0) {
        umount("/tmp");
        return 99;
    }
    return 0;
}

/* Test 5 helper: sethostname inside user NS */
static int try_hostname_in_ns(void) {
    /* Need UTS namespace */
    if (unshare(CLONE_NEWUTS) != 0) return 0;

    int ret = sethostname("pwned", 5);
    return (ret == 0) ? 99 : 0;
}

/* Test 6 helper: Network namespace inside user NS */
static int try_netns_in_userns(void) {
    int ret = unshare(CLONE_NEWNET);
    return (ret == 0) ? 99 : 0;
}

/* Test 7 helper: Mount namespace inside user NS */
static int try_mntns_in_userns(void) {
    int ret = unshare(CLONE_NEWNS);
    return (ret == 0) ? 99 : 0;
}

/* Test 8: uid_map/gid_map writability */
static int try_write_uid_map(void) {
    pid_t pid = fork();
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER) != 0) _exit(0);

        /* Try to write uid_map */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/uid_map", getpid());
        int fd = open(path, O_WRONLY);
        if (fd < 0) _exit(0);

        const char *map = "0 1000 1\n";
        ssize_t n = write(fd, map, strlen(map));
        close(fd);

        _exit(n > 0 ? 99 : 0);
    }
    if (pid < 0) return 0;

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("USER NAMESPACE CAPABILITY ESCALATION");

    int caps = run_in_userns(check_caps);
    TEST("unshare(CLONE_NEWUSER) + caps blocked",
         caps < 98,
         caps == 99 ? "ESCALATED — SYS_ADMIN + NET_ADMIN in user NS!" :
         caps == 98 ? "ESCALATED — SYS_ADMIN in user NS!" :
         caps == 1  ? "user NS created but no dangerous caps" :
         "blocked");

    int nf = run_in_userns(try_netfilter_in_ns);
    TEST("user NS + netfilter (CVE-2024-1086 chain) blocked",
         nf < 99,
         nf == 99 ? "NETFILTER — nf_tables accessible from sandbox!" :
         "blocked");

    int bpf = run_in_userns(try_bpf_in_ns);
    TEST("user NS + BPF (CVE-2023-2163 chain) blocked",
         bpf < 99,
         bpf == 99 ? "BPF — eBPF accessible from sandbox!" :
         "blocked");

    int mnt = run_in_userns(try_mount_in_ns);
    TEST("user NS + mount (CVE-2022-0185 chain) blocked",
         mnt < 99,
         mnt == 99 ? "MOUNTED — tmpfs from sandbox!" :
         "blocked");

    int host = run_in_userns(try_hostname_in_ns);
    TEST("user NS + sethostname blocked",
         host < 99,
         host == 99 ? "HOSTNAME — changed from sandbox!" :
         "blocked");

    int netns = run_in_userns(try_netns_in_userns);
    TEST("user NS + CLONE_NEWNET blocked",
         netns < 99,
         netns == 99 ? "NET NS — network namespace in sandbox!" :
         "blocked");

    int mntns = run_in_userns(try_mntns_in_userns);
    TEST("user NS + CLONE_NEWNS blocked",
         mntns < 99,
         mntns == 99 ? "MNT NS — mount namespace in sandbox!" :
         "blocked");

    int uidmap = try_write_uid_map();
    TEST("uid_map write blocked",
         uidmap < 99,
         uidmap == 99 ? "WRITTEN — uid mapping set!" :
         "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
