#include <stdarg.h>
/*
 * Drawbridge API Tracer - LD_PRELOAD library
 *
 * Intercepts key libc functions that the SQLPAL host calls on behalf
 * of the NTUM. This gives us visibility into EVERY Win32 API that
 * translates to a Linux syscall through the PAL.
 *
 * Usage: LD_PRELOAD=./drawbridge_trace.so drawbridge-run app.exe
 *
 * Intercepted functions:
 * - open/openat    → NtCreateFile / NtOpenFile
 * - read/pread     → NtReadFile
 * - write/pwrite   → NtWriteFile
 * - close          → NtClose
 * - mmap/munmap    → NtAllocateVirtualMemory / NtFreeVirtualMemory
 * - mprotect       → NtProtectVirtualMemory
 * - socket/connect → Winsock (WSASocket, connect)
 * - clone          → NtCreateThread
 * - eventfd        → NtCreateEvent
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

/* Log file */
static FILE *g_log = NULL;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;

/* PE image range (set by env var) */
static uintptr_t g_pe_start = 0x180000000ULL;
static uintptr_t g_pe_end   = 0x181000000ULL;

/* Check if return address is from NTUM code (not host init) */
static int is_from_ntum(void) {
    void *ret = __builtin_return_address(1);
    uintptr_t addr = (uintptr_t)ret;
    /* Check if caller is in the PE image range or LibOS heap */
    return (addr >= g_pe_start && addr < g_pe_end) ||
           (addr >= 0x200000000ULL && addr < 0x400000000000ULL);
}

static void trace_init(void) {
    if (g_initialized) return;
    g_initialized = 1;
    const char *logfile = getenv("DRAWBRIDGE_TRACE_LOG");
    if (!logfile) logfile = "/tmp/drawbridge_trace.log";
    g_log = fopen(logfile, "w");
    if (g_log) {
        fprintf(g_log, "=== Drawbridge API Trace ===\n");
        fprintf(g_log, "PID: %d\n\n", getpid());
        fflush(g_log);
    }
}

static void trace_log(const char *fmt, ...) {
    if (!g_log) return;
    pthread_mutex_lock(&g_log_lock);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(g_log, "[%ld.%03ld] [T%d] ",
            ts.tv_sec, ts.tv_nsec / 1000000, (int)(pthread_self() & 0xFFFF));
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fflush(g_log);
    pthread_mutex_unlock(&g_log_lock);
}

/* ---- Intercepted functions ---- */

/* open / openat → NtCreateFile */
typedef int (*orig_openat_t)(int dirfd, const char *pathname, int flags, ...);
int openat(int dirfd, const char *pathname, int flags, ...) {
    trace_init();
    static orig_openat_t orig = NULL;
    if (!orig) orig = (orig_openat_t)dlsym(RTLD_NEXT, "openat");

    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    int fd = orig(dirfd, pathname, flags, mode);

    /* Only log NTUM-originated opens (skip host init noise) */
    if (1) {
        const char *op = (flags & O_WRONLY) ? "W" : (flags & O_RDWR) ? "RW" : "R";
        const char *cr = (flags & O_CREAT) ? "+CREATE" : "";
        trace_log("NtCreateFile(\"%s\", %s%s) = %d\n", pathname, op, cr, fd);
    }

    return fd;
}

/* write → NtWriteFile */
typedef ssize_t (*orig_write_t)(int fd, const void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count) {
    trace_init();
    static orig_write_t orig = NULL;
    if (!orig) orig = (orig_write_t)dlsym(RTLD_NEXT, "write");

    ssize_t ret = orig(fd, buf, count);

    if (is_from_ntum() && fd > 2) {
        trace_log("NtWriteFile(fd=%d, %zu bytes)\n", fd, count);
    } else if (fd == 1 && is_from_ntum()) {
        /* stdout from the PE app */
        char preview[64] = {0};
        size_t plen = count > 60 ? 60 : count;
        memcpy(preview, buf, plen);
        for (size_t i = 0; i < plen; i++)
            if (preview[i] < 32 && preview[i] != '\n') preview[i] = '.';
        trace_log("WriteConsole(\"%s\")\n", preview);
    }

    return ret;
}

/* pwrite → NtWriteFile with offset */
typedef ssize_t (*orig_pwrite_t)(int fd, const void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    trace_init();
    static orig_pwrite_t orig = NULL;
    if (!orig) orig = (orig_pwrite_t)dlsym(RTLD_NEXT, "pwrite");

    ssize_t ret = orig(fd, buf, count, offset);

    if (1)
        trace_log("NtWriteFile(fd=%d, %zu bytes, off=%ld)\n", fd, count, (long)offset);

    return ret;
}

/* pread → NtReadFile with offset */
typedef ssize_t (*orig_pread_t)(int fd, void *buf, size_t count, off_t offset);
ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
    trace_init();
    static orig_pread_t orig = NULL;
    if (!orig) orig = (orig_pread_t)dlsym(RTLD_NEXT, "pread");

    ssize_t ret = orig(fd, buf, count, offset);

    if (1)
        trace_log("NtReadFile(fd=%d, %zu bytes, off=%ld) = %zd\n", fd, count, (long)offset, ret);

    return ret;
}

/* close → NtClose */
typedef int (*orig_close_t)(int fd);
int close(int fd) {
    trace_init();
    static orig_close_t orig = NULL;
    if (!orig) orig = (orig_close_t)dlsym(RTLD_NEXT, "close");

    if (is_from_ntum() && fd > 2)
        trace_log("NtClose(fd=%d)\n", fd);

    return orig(fd);
}

/* mmap → NtAllocateVirtualMemory / NtMapViewOfSection */
typedef void *(*orig_mmap_t)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    trace_init();
    static orig_mmap_t orig = NULL;
    if (!orig) orig = (orig_mmap_t)dlsym(RTLD_NEXT, "mmap");

    void *ret = orig(addr, length, prot, flags, fd, offset);

    if (1) {
        char protstr[8] = "---";
        if (prot & PROT_READ)  protstr[0] = 'R';
        if (prot & PROT_WRITE) protstr[1] = 'W';
        if (prot & PROT_EXEC)  protstr[2] = 'X';

        if (flags & MAP_ANONYMOUS)
            trace_log("VirtualAlloc(%p, 0x%zx, %s) = %p\n", addr, length, protstr, ret);
        else
            trace_log("MapViewOfSection(fd=%d, %p, 0x%zx, %s) = %p\n", fd, addr, length, protstr, ret);
    }

    return ret;
}

/* mprotect → NtProtectVirtualMemory */
typedef int (*orig_mprotect_t)(void *addr, size_t len, int prot);
int mprotect(void *addr, size_t len, int prot) {
    trace_init();
    static orig_mprotect_t orig = NULL;
    if (!orig) orig = (orig_mprotect_t)dlsym(RTLD_NEXT, "mprotect");

    if (1) {
        char protstr[8] = "---";
        if (prot & PROT_READ)  protstr[0] = 'R';
        if (prot & PROT_WRITE) protstr[1] = 'W';
        if (prot & PROT_EXEC)  protstr[2] = 'X';
        trace_log("VirtualProtect(%p, 0x%zx, %s)\n", addr, len, protstr);
    }

    return orig(addr, len, prot);
}

/* socket → WSASocket */
typedef int (*orig_socket_t)(int domain, int type, int protocol);
int socket(int domain, int type, int protocol) {
    trace_init();
    static orig_socket_t orig = NULL;
    if (!orig) orig = (orig_socket_t)dlsym(RTLD_NEXT, "socket");

    int fd = orig(domain, type, protocol);

    if (1) {
        const char *fam = domain == AF_INET ? "IPv4" : domain == AF_INET6 ? "IPv6" : "other";
        const char *tp = (type & SOCK_STREAM) ? "TCP" : (type & SOCK_DGRAM) ? "UDP" : "raw";
        trace_log("WSASocket(%s, %s) = %d\n", fam, tp, fd);
    }

    return fd;
}

/* connect → Winsock connect */
typedef int (*orig_connect_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    trace_init();
    static orig_connect_t orig = NULL;
    if (!orig) orig = (orig_connect_t)dlsym(RTLD_NEXT, "connect");

    if (is_from_ntum() && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in*)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        trace_log("connect(%d, %s:%d)\n", sockfd, ip, ntohs(in->sin_port));
    }

    return orig(sockfd, addr, addrlen);
}

/* getrandom → CryptGenRandom */
typedef ssize_t (*orig_getrandom_t)(void *buf, size_t buflen, unsigned int flags);
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    trace_init();
    static orig_getrandom_t orig = NULL;
    if (!orig) orig = (orig_getrandom_t)dlsym(RTLD_NEXT, "getrandom");

    ssize_t ret = orig(buf, buflen, flags);

    if (1)
        trace_log("CryptGenRandom(%zu bytes)\n", buflen);

    return ret;
}

/* open → NtCreateFile */
typedef int (*orig_open_t)(const char *pathname, int flags, ...);
int open(const char *pathname, int flags, ...) {
    trace_init();
    static orig_open_t orig = NULL;
    if (!orig) orig = (orig_open_t)dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    int fd = orig(pathname, flags, mode);
    if (fd >= 0) {
        const char *op = (flags & O_WRONLY) ? "W" : (flags & O_RDWR) ? "RW" : "R";
        trace_log("NtCreateFile(\"%s\", %s) = %d\n", pathname, op, fd);
    }
    return fd;
}

/* pread64 */
typedef ssize_t (*orig_pread64_t)(int fd, void *buf, size_t count, off_t offset);
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    trace_init();
    static orig_pread64_t orig = NULL;
    if (!orig) orig = (orig_pread64_t)dlsym(RTLD_NEXT, "pread64");
    ssize_t ret = orig(fd, buf, count, offset);
    if (fd > 2)
        trace_log("NtReadFile(fd=%d, %zu bytes, off=%ld) = %zd\n", fd, count, (long)offset, ret);
    return ret;
}

/* pwrite64 */
typedef ssize_t (*orig_pwrite64_t)(int fd, const void *buf, size_t count, off_t offset);
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) {
    trace_init();
    static orig_pwrite64_t orig = NULL;
    if (!orig) orig = (orig_pwrite64_t)dlsym(RTLD_NEXT, "pwrite64");
    ssize_t ret = orig(fd, buf, count, offset);
    if (fd > 2)
        trace_log("NtWriteFile(fd=%d, %zu bytes, off=%ld)\n", fd, count, (long)offset);
    return ret;
}
