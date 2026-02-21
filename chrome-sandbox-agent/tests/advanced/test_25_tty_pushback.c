/*
 * test_25_tty_pushback.c — TTY pushback / TIOCSTI injection tests
 *
 * TIOCSTI (Terminal I/O Control — Simulate Terminal Input) allows a process
 * to inject characters into the terminal input buffer. Attackers use this to:
 *  - Inject commands into parent shell sessions
 *  - Escape from restricted shells
 *  - Execute commands in contexts that read from the terminal
 *
 * Linux 6.2+ disabled TIOCSTI by default (CONFIG_LEGACY_TIOCSTI=n).
 * TIOCLINUX is another dangerous ioctl for virtual console manipulation.
 *
 * Tests:
 *  1. TIOCSTI ioctl (inject char to terminal)
 *  2. TIOCLINUX ioctl (virtual console commands)
 *  3. TIOCGWINSZ/TIOCSWINSZ (window size get/set)
 *  4. /dev/tty access
 *  5. /dev/ptmx (pseudoterminal master)
 *  6. /dev/pts access
 *  7. TIOCSCTTY (steal controlling terminal)
 *  8. Terminal escape sequence injection via write
 */
#include "test_harness.h"
#include <termios.h>
#include <sys/ioctl.h>

#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif
#ifndef TIOCLINUX
#define TIOCLINUX 0x541C
#endif
#ifndef TIOCSCTTY
#define TIOCSCTTY 0x540E
#endif
#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif
#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif

/* Test 1: TIOCSTI — inject character to terminal */
static int try_tiocsti(void) {
    g_got_sigsys = 0;
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        /* No controlling terminal — try stdin/stdout */
        fd = 0; /* stdin */
    }

    char c = 'X';
    int ret = ioctl(fd, TIOCSTI, &c);
    int saved_errno = errno;

    if (fd > 2) close(fd);
    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Injected! */
    if (saved_errno == EPERM) return 0;
    if (saved_errno == EIO || saved_errno == ENOTTY) return 0;
    return 0;
}

/* Test 2: TIOCLINUX — virtual console control */
static int try_tioclinux(void) {
    g_got_sigsys = 0;
    /* TIOCLINUX subcommand 2 = get/set selection */
    char subcode = 2;
    int ret = ioctl(0, TIOCLINUX, &subcode);
    int saved_errno = errno;

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1;
    if (saved_errno == EPERM) return 0;
    if (saved_errno == EIO || saved_errno == ENOTTY) return 0;
    return 0;
}

/* Test 3: TIOCGWINSZ/TIOCSWINSZ — window size manipulation */
static int try_winsize(void) {
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));

    /* Get window size */
    if (ioctl(0, TIOCGWINSZ, &ws) != 0) return 0;

    /* Try to set (might fail on non-terminal) */
    ws.ws_row = 25;
    ws.ws_col = 80;
    int ret = ioctl(0, TIOCSWINSZ, &ws);
    return (ret == 0) ? 2 : 1; /* 2=can set, 1=can read */
}

/* Test 4: /dev/tty access */
static int try_dev_tty(void) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 5: /dev/ptmx (pseudoterminal master) */
static int try_dev_ptmx(void) {
    g_got_sigsys = 0;
    int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (g_got_sigsys) return -2;
    if (fd >= 0) {
        /* Can create pseudoterminals */
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 6: /dev/pts access */
static int try_dev_pts(void) {
    int fd = open("/dev/pts", O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Test 7: TIOCSCTTY — steal controlling terminal */
static int try_steal_ctty(void) {
    g_got_sigsys = 0;
    /* Try on stdin */
    int ret = ioctl(0, TIOCSCTTY, 0);
    int saved_errno = errno;

    if (g_got_sigsys) return -2;
    if (ret == 0) return 1; /* Stole terminal! */
    if (saved_errno == EPERM) return 0;
    if (saved_errno == EIO || saved_errno == ENOTTY) return 0;
    return 0;
}

/* Test 8: Terminal escape sequence injection via write to stdout */
static int try_escape_sequence_write(void) {
    /* Try writing an OSC (Operating System Command) escape sequence
     * that could set terminal title or exfiltrate data */
    const char *osc_query = "\033]0;test\007"; /* Set window title */
    ssize_t ret = write(1 /* stdout */, osc_query, strlen(osc_query));
    /* Note: we can't easily detect if this was processed by a terminal,
     * but we test if the write succeeds at all */
    return (ret > 0) ? 1 : 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("TTY PUSHBACK / TIOCSTI INJECTION ATTACKS");

    int tiocsti = try_tiocsti();
    TEST("TIOCSTI blocked",
         tiocsti <= 0,
         tiocsti == 1  ? "INJECTED — terminal command injection!" :
         tiocsti == -2 ? "SIGSYS" : "blocked");

    int tioclinux = try_tioclinux();
    TEST("TIOCLINUX blocked",
         tioclinux <= 0,
         tioclinux == 1  ? "ACCESSIBLE — virtual console manipulation!" :
         tioclinux == -2 ? "SIGSYS" : "blocked");

    int winsize = try_winsize();
    TEST("Terminal window size manipulation blocked",
         winsize <= 1,
         winsize == 2 ? "CAN SET window size!" :
         winsize == 1 ? "can read (info only)" : "no terminal");

    int dev_tty = try_dev_tty();
    TEST("/dev/tty not accessible",
         dev_tty == 0,
         dev_tty ? "/dev/tty open!" : "not accessible (good)");

    int ptmx = try_dev_ptmx();
    TEST("/dev/ptmx not accessible",
         ptmx <= 0,
         ptmx == 1  ? "PTY MASTER — can create pseudoterminals!" :
         ptmx == -2 ? "SIGSYS" : "blocked");

    int pts = try_dev_pts();
    TEST("/dev/pts not accessible",
         pts == 0,
         pts ? "/dev/pts accessible!" : "blocked");

    int steal = try_steal_ctty();
    TEST("TIOCSCTTY blocked",
         steal <= 0,
         steal == 1  ? "STOLE controlling terminal!" :
         steal == -2 ? "SIGSYS" : "blocked");

    /* Escape sequences via write are expected — stdout is a pipe/fd */
    int esc_write = try_escape_sequence_write();
    TEST("Escape sequence write (info)",
         1,
         esc_write ? "can write to stdout (expected)" : "write blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
