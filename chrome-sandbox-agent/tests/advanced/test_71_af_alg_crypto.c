/*
 * test_71_af_alg_crypto.c — Kernel crypto socket and privileged syscalls
 *
 * AF_ALG sockets provide access to the kernel's crypto API.
 * This can be used as an attack surface for:
 *   - Buffer overflow in crypto implementations
 *   - Side channels from crypto timing
 *   - Access to crypto hardware accelerators
 *
 * Also tests privileged syscalls that should be completely blocked:
 *   - syslog (read kernel logs)
 *   - reboot (system restart)
 *   - pivot_root (change root filesystem)
 *   - swapon/swapoff (swap space manipulation)
 *   - init_module/finit_module (load kernel modules)
 *
 * Tests:
 *  1. AF_ALG socket creation
 *  2. syslog (kernel log reading)
 *  3. reboot (system restart)
 *  4. pivot_root
 *  5. swapon
 *  6. init_module (kernel module loading)
 *  7. finit_module (module from fd)
 *  8. delete_module (module unloading)
 */
#include "test_harness.h"

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef __NR_finit_module
#define __NR_finit_module 313
#endif
#ifndef __NR_delete_module
#define __NR_delete_module 176
#endif

struct sockaddr_alg {
    uint16_t salg_family;
    char salg_type[14];
    uint32_t salg_feat;
    uint32_t salg_mask;
    char salg_name[64];
};

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("KERNEL CRYPTO AND PRIVILEGED SYSCALLS");

    /* Test 1: AF_ALG socket */
    {
        g_got_sigsys = 0;
        int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
        int blocked = (sock < 0 || g_got_sigsys);

        if (sock >= 0) {
            /* Try to bind to a hash algorithm */
            struct sockaddr_alg sa;
            memset(&sa, 0, sizeof(sa));
            sa.salg_family = AF_ALG;
            strncpy(sa.salg_type, "hash", sizeof(sa.salg_type));
            strncpy(sa.salg_name, "sha256", sizeof(sa.salg_name));
            int bret = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
            if (bret == 0) blocked = 0;
            close(sock);
        }

        TEST("AF_ALG crypto socket blocked",
             blocked,
             blocked ? "blocked" :
             "AF_ALG — kernel crypto API accessible from sandbox!");
    }

    /* Test 2: syslog — read kernel ring buffer */
    {
        g_got_sigsys = 0;
        char buf[4096];
        /* type=3 (SYSLOG_ACTION_READ_ALL) */
        long ret = syscall(SYS_syslog, 3, buf, sizeof(buf));
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("syslog(READ_ALL) blocked",
             blocked,
             blocked ? "blocked" :
             "SYSLOG — kernel log readable from sandbox!");
    }

    /* Test 3: reboot */
    {
        g_got_sigsys = 0;
        /* LINUX_REBOOT_CMD_CAD_OFF (0) — just disable Ctrl-Alt-Del */
        long ret = syscall(SYS_reboot,
                           0xfee1dead, /* magic1 */
                           0x28121969, /* magic2 */
                           0,          /* cmd: CAD_OFF */
                           NULL);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("reboot() blocked",
             blocked,
             blocked ? "blocked" :
             "REBOOT — system reboot from sandbox!");
    }

    /* Test 4: pivot_root */
    {
        g_got_sigsys = 0;
        long ret = syscall(SYS_pivot_root, "/tmp", "/tmp");
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("pivot_root() blocked",
             blocked,
             blocked ? "blocked" :
             "PIVOT — root filesystem changed from sandbox!");
    }

    /* Test 5: swapon */
    {
        g_got_sigsys = 0;
        long ret = syscall(SYS_swapon, "/dev/null", 0);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("swapon() blocked",
             blocked,
             blocked ? "blocked" :
             "SWAPON — swap enabled from sandbox!");
    }

    /* Test 6: init_module — load kernel module from memory */
    {
        g_got_sigsys = 0;
        char fake_module[] = "not_a_real_module";
        long ret = syscall(SYS_init_module, fake_module,
                           sizeof(fake_module), "");
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("init_module() blocked",
             blocked,
             blocked ? "blocked" :
             "MODULE — kernel module loaded from sandbox!");
    }

    /* Test 7: finit_module — load kernel module from fd */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_finit_module, STDIN_FILENO, "", 0);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("finit_module() blocked",
             blocked,
             blocked ? "blocked" :
             "FMODULE — kernel module loaded from fd!");
    }

    /* Test 8: delete_module — unload kernel module */
    {
        g_got_sigsys = 0;
        long ret = syscall(__NR_delete_module, "nonexistent", 0);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("delete_module() blocked",
             blocked,
             blocked ? "blocked" :
             "RMMOD — kernel module unloaded from sandbox!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
