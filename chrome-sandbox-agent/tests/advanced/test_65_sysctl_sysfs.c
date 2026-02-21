/*
 * test_65_sysctl_sysfs.c — Sysctl and sysfs information leaks / manipulation
 *
 * /proc/sys/ and /sys/ contain kernel tunables and system info that
 * can be exploited from within a sandbox:
 *   - Kernel ASLR defeat via /proc/sys/kernel/randomize_va_space
 *   - Network stack manipulation via /proc/sys/net/
 *   - Core pattern hijacking via /proc/sys/kernel/core_pattern
 *   - Module loading via /proc/sys/kernel/modprobe
 *   - Hostname/domainname leak
 *
 * Tests:
 *  1. /proc/sys/kernel/core_pattern read/write
 *  2. /proc/sys/kernel/modprobe read
 *  3. /proc/sys/kernel/randomize_va_space read
 *  4. /proc/sys/net/ipv4/ip_forward write
 *  5. /proc/sys/kernel/hostname read
 *  6. /proc/sys/kernel/keys/maxkeys read
 *  7. /sys/kernel/security/ enumeration
 *  8. /proc/sys/vm/overcommit_memory manipulation
 */
#include "test_harness.h"

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SYSCTL AND SYSFS INFORMATION LEAKS");

    /* Test 1: /proc/sys/kernel/core_pattern — code execution via core dumps */
    {
        char buf[256];
        ssize_t n = read_file("/proc/sys/kernel/core_pattern",
                              buf, sizeof(buf));
        int readable = (n > 0);

        /* Also try to write (pipe to program execution) */
        int writable = 0;
        int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);
        if (fd >= 0) {
            const char *payload = "|/tmp/pwned";
            ssize_t w = write(fd, payload, strlen(payload));
            writable = (w > 0);
            close(fd);
        }

        TEST("core_pattern manipulation blocked",
             !writable,
             writable ? "CORE PATTERN — wrote execution payload!" :
             readable ? "read-only (info leak)" : "blocked");
    }

    /* Test 2: /proc/sys/kernel/modprobe — module loader path */
    {
        char buf[256];
        ssize_t n = read_file("/proc/sys/kernel/modprobe", buf, sizeof(buf));
        int readable = (n > 0);

        int writable = 0;
        int fd = open("/proc/sys/kernel/modprobe", O_WRONLY);
        if (fd >= 0) {
            writable = 1;
            close(fd);
        }

        TEST("modprobe path manipulation blocked",
             !writable,
             writable ? "MODPROBE — path writable from sandbox!" :
             readable ? "read-only (info leak)" : "blocked");
    }

    /* Test 3: /proc/sys/kernel/randomize_va_space — ASLR config */
    {
        char buf[64];
        ssize_t n = read_file("/proc/sys/kernel/randomize_va_space",
                              buf, sizeof(buf));
        int readable = (n > 0);

        int writable = 0;
        int fd = open("/proc/sys/kernel/randomize_va_space", O_WRONLY);
        if (fd >= 0) {
            const char *disable = "0";
            ssize_t w = write(fd, disable, 1);
            writable = (w > 0);
            close(fd);
        }

        TEST("ASLR manipulation blocked",
             !writable,
             writable ? "ASLR — randomization DISABLED from sandbox!" :
             readable ? "read-only (info leak)" : "blocked");
    }

    /* Test 4: /proc/sys/net/ipv4/ip_forward — network routing */
    {
        int writable = 0;
        int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
        if (fd >= 0) {
            const char *enable = "1";
            ssize_t w = write(fd, enable, 1);
            writable = (w > 0);
            close(fd);
        }

        TEST("ip_forward manipulation blocked",
             !writable,
             writable ? "IP FORWARD — routing enabled from sandbox!" :
             "blocked");
    }

    /* Test 5: /proc/sys/kernel/hostname — host identification */
    {
        char buf[256];
        ssize_t n = read_file("/proc/sys/kernel/hostname", buf, sizeof(buf));
        int readable = (n > 0 && strlen(buf) > 0);

        /* hostname is also available via uname() which is always allowed.
         * Read-only info leak, not a direct escape vector. */
        TEST("/proc/sys/kernel/hostname noted",
             1,  /* read-only, also available via uname() */
             readable ? "readable (also via uname, not an escape)" :
             "blocked");
    }

    /* Test 6: /proc/sys/kernel/keys/maxkeys — keyring info */
    {
        char buf[64];
        ssize_t n = read_file("/proc/sys/kernel/keys/maxkeys",
                              buf, sizeof(buf));
        int readable = (n > 0);
        /* keyring limits are system-wide constants, not per-process secrets.
         * Read-only, low sensitivity. */
        TEST("/proc/sys/kernel/keys noted",
             1,  /* read-only system config, not an escape */
             readable ? "readable (system config, low sensitivity)" :
             "blocked");
    }

    /* Test 7: /sys/kernel/security/ enumeration */
    {
        int fd = open("/sys/kernel/security", O_RDONLY | O_DIRECTORY);
        int accessible = (fd >= 0);
        if (fd >= 0) close(fd);

        /* Also try specific security subsystems */
        char buf[256];
        ssize_t n = read_file("/sys/kernel/security/lsm", buf, sizeof(buf));
        int lsm_visible = (n > 0);

        TEST("/sys/kernel/security blocked",
             !accessible && !lsm_visible,
             lsm_visible ? "LSM — security module list visible!" :
             accessible ? "SECURITYFS — directory accessible!" :
             "blocked");
    }

    /* Test 8: /proc/sys/vm/overcommit_memory — OOM manipulation */
    {
        int writable = 0;
        int fd = open("/proc/sys/vm/overcommit_memory", O_WRONLY);
        if (fd >= 0) {
            const char *overcommit = "1";
            ssize_t w = write(fd, overcommit, 1);
            writable = (w > 0);
            close(fd);
        }

        char buf[64];
        ssize_t n = read_file("/proc/sys/vm/overcommit_memory",
                              buf, sizeof(buf));

        TEST("vm/overcommit_memory manipulation blocked",
             !writable,
             writable ? "OVERCOMMIT — VM overcommit changed!" :
             n > 0 ? "read-only (info leak)" : "blocked");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
