/*
 * test_64_device_ioctl.c — Device file and ioctl-based sandbox escapes
 *
 * Device files provide direct access to kernel subsystems. Even within
 * a sandbox, device access can lead to:
 *   - Memory corruption via /dev/mem, /dev/kmem
 *   - GPU access via /dev/dri/*
 *   - USB access via /dev/bus/usb/*
 *   - Crypto operations via /dev/crypto
 *   - Watchdog abuse via /dev/watchdog
 *   - DMA attacks via various device ioctls
 *
 * Based on: ChromeOS exploit chains using /dev/dri (GPU escape),
 *           Container escapes via device mounts
 *
 * Tests:
 *  1. /dev/mem access
 *  2. /dev/kmem access
 *  3. /dev/port access
 *  4. /dev/dri/renderD128 (GPU)
 *  5. /dev/kvm (virtualization)
 *  6. /dev/vhost-net
 *  7. /dev/fuse
 *  8. TIOCSTI ioctl (terminal injection)
 */
#include "test_harness.h"
#include <sys/ioctl.h>
#include <termios.h>

#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("DEVICE FILE AND IOCTL ESCAPE VECTORS");

    /* Test 1: /dev/mem — physical memory access */
    {
        int fd = open("/dev/mem", O_RDWR);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);
        TEST("/dev/mem access blocked",
             blocked,
             blocked ? "blocked" :
             "DEV MEM — physical memory accessible from sandbox!");
    }

    /* Test 2: /dev/kmem — kernel memory access */
    {
        int fd = open("/dev/kmem", O_RDWR);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);
        TEST("/dev/kmem access blocked",
             blocked,
             blocked ? "blocked" :
             "KMEM — kernel memory accessible from sandbox!");
    }

    /* Test 3: /dev/port — x86 I/O port access */
    {
        int fd = open("/dev/port", O_RDWR);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);
        TEST("/dev/port access blocked",
             blocked,
             blocked ? "blocked" :
             "PORT — I/O ports accessible from sandbox!");
    }

    /* Test 4: /dev/dri/renderD128 — GPU access */
    {
        int fd = open("/dev/dri/renderD128", O_RDWR);
        if (fd < 0) fd = open("/dev/dri/card0", O_RDWR);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);
        TEST("/dev/dri GPU access blocked",
             blocked,
             blocked ? "blocked" :
             "GPU — DRI device accessible from sandbox!");
    }

    /* Test 5: /dev/kvm — KVM virtualization */
    {
        int fd = open("/dev/kvm", O_RDWR);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);
        TEST("/dev/kvm access blocked",
             blocked,
             blocked ? "blocked" :
             "KVM — virtualization accessible from sandbox!");
    }

    /* Test 6: /dev/vhost-net — vhost networking */
    {
        int fd = open("/dev/vhost-net", O_RDWR);
        if (fd < 0) fd = open("/dev/vhost-vsock", O_RDWR);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);
        TEST("/dev/vhost-net access blocked",
             blocked,
             blocked ? "blocked" :
             "VHOST — vhost device accessible from sandbox!");
    }

    /* Test 7: /dev/fuse — FUSE filesystem */
    {
        int fd = open("/dev/fuse", O_RDWR);
        int blocked = (fd < 0);
        if (fd >= 0) close(fd);
        TEST("/dev/fuse access blocked",
             blocked,
             blocked ? "blocked" :
             "FUSE — FUSE device accessible from sandbox!");
    }

    /* Test 8: TIOCSTI ioctl — terminal character injection */
    {
        g_got_sigsys = 0;
        /* Try to inject a character into the terminal */
        int fd = open("/dev/tty", O_RDWR);
        int blocked = 1;
        if (fd >= 0) {
            char c = 'X';
            int ret = ioctl(fd, TIOCSTI, &c);
            blocked = (ret < 0 || g_got_sigsys);
            close(fd);
        }
        /* No tty is also considered blocked */
        TEST("TIOCSTI terminal injection blocked",
             blocked,
             blocked ? "blocked" :
             "TIOCSTI — character injected into terminal!");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
