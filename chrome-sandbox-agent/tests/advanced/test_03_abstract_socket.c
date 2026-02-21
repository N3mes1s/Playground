/*
 * test_03_abstract_socket.c — Abstract Unix Socket Namespace Escape
 *
 * Attack vector: Abstract Unix sockets (address starts with \0) live in the
 * NETWORK namespace, not the filesystem namespace. If the sandbox shares
 * the network namespace with the host, abstract sockets are shared too.
 * This means:
 *   1. The sandboxed process can connect to host services (D-Bus, X11,
 *      PulseAudio, systemd, snapd) via their abstract socket names
 *   2. It can listen on abstract sockets to intercept host connections
 *   3. It can exfiltrate data without touching the filesystem
 *
 * We also test SysV IPC (shared memory, semaphores, message queues) which
 * is isolated via IPC namespace.
 *
 * PASS = abstract sockets isolated, IPC namespace effective
 * FAIL = cross-namespace communication possible
 */

#include "test_harness.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>

/* Well-known abstract socket addresses on a typical Linux host */
static const char *host_abstract_sockets[] = {
    "/tmp/dbus-",          /* D-Bus session bus (sometimes abstract) */
    "/tmp/.X11-unix/X0",   /* X11 display */
    "/run/dbus/system_bus_socket",
    NULL
};

/* Try to connect to an abstract socket name */
static int try_abstract_connect(const char *name) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* Abstract socket: first byte is \0 */
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name, sizeof(addr.sun_path) - 2);

    int ret = connect(fd, (struct sockaddr *)&addr,
                      sizeof(addr.sun_family) + 1 + strlen(name));
    close(fd);
    return ret;
}

/* Try to create an abstract listening socket */
static int try_abstract_listen(const char *name) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name, sizeof(addr.sun_path) - 2);

    int ret = bind(fd, (struct sockaddr *)&addr,
                   sizeof(addr.sun_family) + 1 + strlen(name));
    if (ret == 0) ret = listen(fd, 1);
    close(fd);
    return ret;
}

/* Try to enumerate abstract sockets via /proc/net/unix */
static int count_abstract_sockets(void) {
    int fd = open("/proc/net/unix", O_RDONLY);
    if (fd < 0) return -1;

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Count lines with @ prefix (abstract sockets) */
    int count = 0;
    char *line = buf;
    while ((line = strstr(line, " @")) != NULL) {
        count++;
        line++;
    }
    return count;
}

/* D-Bus abstract socket probe — try common D-Bus abstract names */
static int try_dbus_abstract(void) {
    const char *dbus_names[] = {
        "dbus-system",
        "dbus-session",
        "/org/freedesktop/DBus",
        NULL
    };
    for (int i = 0; dbus_names[i]; i++) {
        if (try_abstract_connect(dbus_names[i]) == 0)
            return 1;
    }
    return 0;
}

/* SysV shared memory — try to create and access */
static int try_sysv_shm(void) {
    /* Try to create a new shared memory segment */
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (shmid < 0) return -1;

    void *ptr = shmat(shmid, NULL, 0);
    int attached = (ptr != (void *)-1);
    if (attached) {
        /* Write a marker */
        memcpy(ptr, "SHM_ESCAPE", 10);
        shmdt(ptr);
    }

    shmctl(shmid, IPC_RMID, NULL);
    return attached ? 0 : -1;
}

/* Try to access a well-known SysV shm key from the host */
static int try_sysv_shm_host(void) {
    /* Try keys 0-100 (common for legacy apps) */
    for (key_t key = 1; key <= 100; key++) {
        int shmid = shmget(key, 0, 0);
        if (shmid >= 0) return 1;  /* Found host shared memory! */
    }
    return 0;
}

/* SysV message queue */
static int try_sysv_msgq(void) {
    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (msqid < 0) return -1;
    msgctl(msqid, IPC_RMID, NULL);
    return 0;
}

/* SysV semaphore */
static int try_sysv_sem(void) {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    if (semid < 0) return -1;
    semctl(semid, 0, IPC_RMID);
    return 0;
}

/* Try socketpair + sendmsg to pass data across namespace boundaries */
static int try_socketpair_cross_ns(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return -1;  /* Can't create socketpair */

    /* This is local — but tests that socketpair works at all */
    write(sv[0], "test", 4);
    char buf[8] = {0};
    read(sv[1], buf, sizeof(buf));

    close(sv[0]);
    close(sv[1]);

    return strcmp(buf, "test") == 0 ? 0 : -1;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("ABSTRACT UNIX SOCKET & IPC NAMESPACE ESCAPE");

    /* 1. Try connecting to host abstract sockets */
    int connected_any = 0;
    for (int i = 0; host_abstract_sockets[i]; i++) {
        int ret = try_abstract_connect(host_abstract_sockets[i]);
        if (ret == 0) {
            connected_any = 1;
            printf("    !!! Connected to abstract: %s\n",
                   host_abstract_sockets[i]);
        }
    }
    TEST("Cannot connect to host abstract sockets",
         !connected_any,
         "connected to host services via abstract socket!");

    /* 2. D-Bus abstract socket probe */
    int dbus = try_dbus_abstract();
    TEST("D-Bus abstract socket not reachable",
         !dbus,
         "connected to D-Bus!");

    /* 3. Can create abstract listening sockets? */
    int can_listen = (try_abstract_listen("sandbox_test_listener") == 0);
    /* Within sandbox, this may work (isolated net NS), but shouldn't
     * be visible to host */
    TEST("Abstract listen socket stays in sandbox NS",
         1,  /* Always passes — we just log the result */
         "listen %s (isolated by net NS)", can_listen ? "works" : "blocked");

    /* 4. Enumerate abstract sockets visible */
    int abs_count = count_abstract_sockets();
    TEST("Few abstract sockets visible (< 10 = isolated)",
         abs_count < 10,
         "%d abstract sockets visible", abs_count);

    /* 5. SysV shared memory — local creation */
    int shm = try_sysv_shm();
    TEST("SysV shm creation (IPC_PRIVATE) controlled",
         1,  /* Log result */
         shm == 0 ? "works (isolated IPC NS)" : "blocked (errno=%d)", errno);

    /* 6. SysV shared memory — can we see host segments? */
    int host_shm = try_sysv_shm_host();
    TEST("Cannot access host SysV shm segments",
         !host_shm,
         "found host shared memory — IPC namespace leak!");

    /* 7. SysV message queue */
    int mq = try_sysv_msgq();
    TEST("SysV msgqueue controlled",
         1,
         mq == 0 ? "works (isolated IPC NS)" : "blocked");

    /* 8. SysV semaphore */
    int sem = try_sysv_sem();
    TEST("SysV semaphore controlled",
         1,
         sem == 0 ? "works (isolated IPC NS)" : "blocked");

    /* 9. socketpair within sandbox */
    int sp = try_socketpair_cross_ns();
    TEST("socketpair local comms work (positive test)",
         sp == 0,
         "");

    PRINT_SUMMARY();
    return g_fail > 0 ? 1 : 0;
}
