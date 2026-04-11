/*
 * DK PAL Implementation - Drawbridge Kernel functions on Linux
 *
 * Maps the 72 DK functions to Linux syscalls.
 * Uses __attribute__((ms_abi)) so the NTUM can call us directly
 * using Windows x64 calling convention.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/eventfd.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>

#include "dk_pal.h"

/* Handle table - maps DK_HANDLE to Linux fd/pointer */
#define MAX_HANDLES 4096
typedef struct {
    int type;       /* 0=free, 1=fd, 2=event, 3=thread, 4=mutex, 5=mapped */
    union {
        int fd;
        int eventfd;
        pthread_t thread;
        pthread_mutex_t *mutex;
        struct { void *addr; size_t size; } map;
    };
} handle_entry_t;

static handle_entry_t g_handles[MAX_HANDLES];
static pthread_mutex_t g_handle_lock = PTHREAD_MUTEX_INITIALIZER;

static DK_HANDLE alloc_handle(void) {
    pthread_mutex_lock(&g_handle_lock);
    for (int i = 16; i < MAX_HANDLES; i++) {  /* Skip 0-15 for stdio */
        if (g_handles[i].type == 0) {
            g_handles[i].type = -1;  /* Mark as reserved */
            pthread_mutex_unlock(&g_handle_lock);
            return (DK_HANDLE)i;
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    return DK_NULL_HANDLE;
}

static void free_handle(DK_HANDLE h) {
    if (h < MAX_HANDLES) {
        g_handles[h].type = 0;
    }
}

/* ================================================================
 * Stream I/O
 * ================================================================ */

DK_API uint64_t DK_StreamOpen(const void *uri, uint64_t uri_len,
                               uint64_t access, uint64_t share_mode,
                               uint64_t create_disp, uint64_t flags,
                               DK_HANDLE *out_handle) {
    (void)share_mode; (void)flags;

    /* Convert wide string URI to ASCII */
    char path[512] = {0};
    const uint16_t *w = (const uint16_t*)uri;
    for (uint64_t i = 0; i < uri_len && i < 511 && w[i]; i++)
        path[i] = (char)(w[i] & 0xFF);

    /* Handle special URIs */
    if (strncmp(path, "stdout:", 7) == 0) {
        DK_HANDLE h = alloc_handle();
        g_handles[h].type = 1;
        g_handles[h].fd = STDOUT_FILENO;
        *out_handle = h;
        return DK_STATUS_SUCCESS;
    }
    if (strncmp(path, "stderr:", 7) == 0) {
        DK_HANDLE h = alloc_handle();
        g_handles[h].type = 1;
        g_handles[h].fd = STDERR_FILENO;
        *out_handle = h;
        return DK_STATUS_SUCCESS;
    }
    if (strncmp(path, "stdin:", 6) == 0) {
        DK_HANDLE h = alloc_handle();
        g_handles[h].type = 1;
        g_handles[h].fd = STDIN_FILENO;
        *out_handle = h;
        return DK_STATUS_SUCCESS;
    }

    /* Strip Windows path prefix */
    char *p = path;
    if (p[0] == '\\') p++;
    /* Convert backslashes */
    for (char *c = p; *c; c++) if (*c == '\\') *c = '/';

    int oflags = O_RDONLY;
    if (access & 0x40000000) oflags = O_RDWR;
    if (create_disp == 2) oflags |= O_CREAT | O_TRUNC;
    if (create_disp == 4) oflags |= O_CREAT;

    int fd = open(p, oflags, 0644);
    if (fd < 0) {
        fprintf(stderr, "[DK] StreamOpen(\"%s\"): %s\n", p, strerror(errno));
        return DK_STATUS_INVALID_PARAM;
    }

    DK_HANDLE h = alloc_handle();
    g_handles[h].type = 1;
    g_handles[h].fd = fd;
    *out_handle = h;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamRead(DK_HANDLE stream, uint64_t offset,
                               void *buffer, uint64_t bytes_to_read,
                               uint64_t *bytes_read) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != 1)
        return DK_STATUS_INVALID_PARAM;
    ssize_t n = pread(g_handles[stream].fd, buffer, bytes_to_read, offset);
    if (n < 0) return DK_STATUS_INVALID_PARAM;
    if (bytes_read) *bytes_read = n;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamWrite(DK_HANDLE stream, uint64_t offset,
                                const void *buffer, uint64_t bytes_to_write,
                                uint64_t *bytes_written) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != 1)
        return DK_STATUS_INVALID_PARAM;
    ssize_t n = pwrite(g_handles[stream].fd, buffer, bytes_to_write, offset);
    if (n < 0) n = write(g_handles[stream].fd, buffer, bytes_to_write);
    if (n < 0) return DK_STATUS_INVALID_PARAM;
    if (bytes_written) *bytes_written = n;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamClose(DK_HANDLE handle) {
    return DK_ObjectClose(handle);
}

DK_API uint64_t DK_StreamFlush(DK_HANDLE stream) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != 1) return DK_STATUS_SUCCESS;
    fsync(g_handles[stream].fd);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamSetLength(DK_HANDLE stream, uint64_t length) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != 1) return DK_STATUS_INVALID_PARAM;
    ftruncate(g_handles[stream].fd, length);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamMap(DK_HANDLE stream, void *address,
                              uint64_t offset, uint64_t size,
                              uint64_t protect, void **mapped) {
    (void)protect;
    int fd = -1;
    if (stream < MAX_HANDLES && g_handles[stream].type == 1)
        fd = g_handles[stream].fd;

    int flags = MAP_PRIVATE;
    if (address) flags |= MAP_FIXED_NOREPLACE;

    void *result = mmap(address, size, PROT_READ|PROT_WRITE|PROT_EXEC,
                        flags, fd, offset);
    if (result == MAP_FAILED) return DK_STATUS_NO_MEMORY;
    if (mapped) *mapped = result;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamMapPeBinary(DK_HANDLE stream, void **base,
                                      uint64_t *entry_point) {
    /* Stub - the real implementation parses PE headers from the stream */
    (void)stream; (void)base; (void)entry_point;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamUnmap(void *address, uint64_t size) {
    munmap(address, size);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamDelete(DK_HANDLE stream) {
    (void)stream;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamControl(DK_HANDLE in_handle, uint64_t op_code,
                                  void *in_buf, uint64_t in_size,
                                  void *out_buf, uint64_t out_size) {
    (void)in_handle;(void)op_code;(void)in_buf;(void)in_size;
    (void)out_buf;(void)out_size;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamAttributesQuery(const void *uri, void *attrs) {
    (void)uri; (void)attrs;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamAttributesQueryByHandle(DK_HANDLE stream,
                                                   uint64_t flags, void *attrs) {
    (void)stream; (void)flags; (void)attrs;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamEnumerateChildren(DK_HANDLE stream, void *buf,
                                            uint64_t buf_size, uint64_t *used) {
    (void)stream;(void)buf;(void)buf_size;(void)used;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamRename(DK_HANDLE stream, const void *new_name) {
    (void)stream;(void)new_name;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamChangesRegister(DK_HANDLE stream, uint64_t filter,
                                          uint64_t watch_tree, DK_HANDLE *event) {
    (void)stream;(void)filter;(void)watch_tree;(void)event;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamChangesPoll(DK_HANDLE stream, void *buf, uint64_t *size) {
    (void)stream;(void)buf;(void)size;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamRangeLock(DK_HANDLE stream, uint64_t off, uint64_t len,
                                    uint64_t exclusive) {
    (void)stream;(void)off;(void)len;(void)exclusive;
    return DK_STATUS_SUCCESS;  /* Pretend lock succeeded */
}

DK_API uint64_t DK_StreamRangeUnlock(DK_HANDLE stream, uint64_t off, uint64_t len) {
    (void)stream;(void)off;(void)len;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamGetEvent(DK_HANDLE stream, uint64_t event_id,
                                   DK_HANDLE *event) {
    (void)stream;(void)event_id;(void)event;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamEventSelect(DK_HANDLE stream, DK_HANDLE event,
                                      uint64_t poll_events, DK_HANDLE *async) {
    (void)stream;(void)event;(void)poll_events;(void)async;
    return DK_STATUS_NOT_IMPLEMENTED;
}

/* ================================================================
 * Memory Management
 * ================================================================ */

static int dk_prot_to_linux(uint64_t dk_prot) {
    int prot = 0;
    if (dk_prot & 0x01) prot |= PROT_READ;            /* PAGE_READONLY */
    if (dk_prot & 0x02) prot |= PROT_READ|PROT_WRITE;  /* PAGE_READWRITE */
    if (dk_prot & 0x04) prot |= PROT_READ|PROT_WRITE;  /* PAGE_READWRITE */
    if (dk_prot & 0x10) prot |= PROT_EXEC;             /* PAGE_EXECUTE */
    if (dk_prot & 0x20) prot |= PROT_READ|PROT_EXEC;
    if (dk_prot & 0x40) prot |= PROT_READ|PROT_WRITE|PROT_EXEC;
    if (prot == 0) prot = PROT_READ|PROT_WRITE;  /* Default */
    return prot;
}

DK_API uint64_t DK_VirtualMemoryAllocate(void **address, uint64_t *size,
                                          uint64_t alloc_type, uint64_t protect) {
    int prot = dk_prot_to_linux(protect);
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    void *hint = address ? *address : NULL;
    size_t len = size ? *size : 4096;

    if (hint) flags |= MAP_FIXED_NOREPLACE;
    if (alloc_type & 0x2000) flags |= MAP_NORESERVE;  /* MEM_RESERVE */

    void *result = mmap(hint, len, prot, flags, -1, 0);
    if (result == MAP_FAILED) {
        if (hint) {
            result = mmap(NULL, len, prot,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        }
        if (result == MAP_FAILED) return DK_STATUS_NO_MEMORY;
    }

    if (address) *address = result;
    if (size) *size = len;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_VirtualMemoryFree(void *address, uint64_t size, uint64_t free_type) {
    (void)free_type;
    if (size == 0) size = 4096;
    munmap(address, size);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_VirtualMemoryProtect(void *address, uint64_t size,
                                         uint64_t new_protect, uint64_t *old_protect) {
    if (old_protect) *old_protect = 0x04;  /* PAGE_READWRITE */
    int prot = dk_prot_to_linux(new_protect);
    mprotect(address, size, prot);
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Threading
 * ================================================================ */

DK_API uint64_t DK_ThreadCreate(void *start_routine, void *stack_ptr,
                                 uint64_t flags, DK_HANDLE *thread) {
    (void)stack_ptr; (void)flags;
    DK_HANDLE h = alloc_handle();
    if (h == DK_NULL_HANDLE) return DK_STATUS_NO_MEMORY;

    g_handles[h].type = 3;
    int ret = pthread_create(&g_handles[h].thread, NULL,
                             (void*(*)(void*))start_routine, NULL);
    if (ret != 0) { free_handle(h); return DK_STATUS_NO_MEMORY; }
    if (thread) *thread = h;
    return DK_STATUS_SUCCESS;
}

DK_API void DK_ThreadExit(uint64_t exit_code) {
    pthread_exit((void*)(intptr_t)exit_code);
}

DK_API uint64_t DK_ThreadYieldExecution(void) {
    sched_yield();
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ThreadInterrupt(DK_HANDLE thread) {
    (void)thread;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ThreadSetAffinity(DK_HANDLE thread, uint64_t group, uint64_t mask) {
    (void)thread;(void)group;(void)mask;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Synchronization
 * ================================================================ */

DK_API uint64_t DK_NotificationEventCreate(uint64_t initial_state, DK_HANDLE *event) {
    int efd = eventfd(initial_state ? 1 : 0, EFD_NONBLOCK);
    if (efd < 0) return DK_STATUS_NO_MEMORY;
    DK_HANDLE h = alloc_handle();
    g_handles[h].type = 2;
    g_handles[h].eventfd = efd;
    if (event) *event = h;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SynchronizationEventCreate(uint64_t initial_state, DK_HANDLE *event) {
    return DK_NotificationEventCreate(initial_state, event);
}

DK_API uint64_t DK_EventSet(DK_HANDLE event) {
    if (event >= MAX_HANDLES || g_handles[event].type != 2) return DK_STATUS_INVALID_PARAM;
    uint64_t val = 1;
    write(g_handles[event].eventfd, &val, sizeof(val));
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventClear(DK_HANDLE event) {
    if (event >= MAX_HANDLES || g_handles[event].type != 2) return DK_STATUS_INVALID_PARAM;
    uint64_t val;
    read(g_handles[event].eventfd, &val, sizeof(val));
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventPeek(DK_HANDLE event, uint64_t *signaled) {
    if (event >= MAX_HANDLES || g_handles[event].type != 2) return DK_STATUS_INVALID_PARAM;
    struct pollfd pfd = { .fd = g_handles[event].eventfd, .events = POLLIN };
    int ret = poll(&pfd, 1, 0);
    if (signaled) *signaled = (ret > 0) ? 1 : 0;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ObjectsWaitAny(uint64_t count, DK_HANDLE *objects,
                                   uint64_t timeout, uint64_t *index) {
    (void)count;(void)objects;(void)timeout;
    if (index) *index = 0;
    usleep(1000);  /* 1ms yield */
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Objects
 * ================================================================ */

DK_API uint64_t DK_ObjectClose(DK_HANDLE handle) {
    if (handle >= MAX_HANDLES) return DK_STATUS_INVALID_PARAM;
    handle_entry_t *e = &g_handles[handle];
    switch (e->type) {
        case 1: if (e->fd > 2) close(e->fd); break;
        case 2: close(e->eventfd); break;
        case 4: pthread_mutex_destroy(e->mutex); free(e->mutex); break;
        case 5: munmap(e->map.addr, e->map.size); break;
    }
    free_handle(handle);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ObjectReference(DK_HANDLE handle) {
    (void)handle;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Process
 * ================================================================ */

DK_API uint64_t DK_ProcessCreate(void *params, DK_HANDLE *process) {
    (void)params;(void)process;
    fprintf(stderr, "[DK] ProcessCreate - blocked\n");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API void DK_ProcessExit(uint64_t exit_code) {
    fprintf(stderr, "[DK] ProcessExit(%lu)\n", (unsigned long)exit_code);
    _exit((int)exit_code);
}

DK_API uint64_t DK_ProcessTerminate(DK_HANDLE process, uint64_t exit_code) {
    (void)process;
    fprintf(stderr, "[DK] ProcessTerminate(%lu)\n", (unsigned long)exit_code);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ProcessGetExitCode(DK_HANDLE process, uint64_t *exit_code) {
    (void)process;
    if (exit_code) *exit_code = 0;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * System
 * ================================================================ */

DK_API uint64_t DK_SystemTimeQuery(uint64_t clock_type, uint64_t *time_val) {
    struct timespec ts;
    clockid_t clk = (clock_type == 0) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
    clock_gettime(clk, &ts);
    /* Return as Windows FILETIME (100ns intervals since 1601) */
    uint64_t ft = ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL
                  + ts.tv_nsec / 100;
    if (time_val) *time_val = ft;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_RandomBitsRead(void *buffer, uint64_t length) {
    ssize_t ret = getrandom(buffer, length, 0);
    return (ret == (ssize_t)length) ? DK_STATUS_SUCCESS : DK_STATUS_INVALID_PARAM;
}

/* ================================================================
 * Console
 * ================================================================ */

DK_API uint64_t DK_ConsoleCreate(DK_HANDLE *console) {
    (void)console;
    return DK_STATUS_NOT_IMPLEMENTED;
}

/* ================================================================
 * ABI Dispatch
 * ================================================================ */

/* Function table for DKAbiGetFunction lookups */
typedef struct {
    uint64_t id;
    void *func;
    const char *name;
} dk_func_entry_t;

static const dk_func_entry_t g_dk_functions[] = {
    /* These IDs are guesses based on the ABI negotiation protocol.
     * The real IDs need to be discovered from the NTUM's calls. */
    {0, NULL, NULL}
};

DK_API uint64_t DK_AbiGetVersion(void *in_buf, uint64_t in_size,
                                  void *out_buf, uint64_t out_size) {
    (void)in_buf;(void)in_size;(void)out_buf;(void)out_size;
    fprintf(stderr, "[DK] AbiGetVersion called\n");
    /* Return version info */
    if (out_buf && out_size >= 8) {
        *(uint64_t*)out_buf = 2;  /* Version 2 */
    }
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_AbiGetFunction(uint64_t abi_id, void **func_ptr) {
    fprintf(stderr, "[DK] AbiGetFunction(0x%lx) called\n", (unsigned long)abi_id);
    if (func_ptr) *func_ptr = NULL;
    return DK_STATUS_NOT_IMPLEMENTED;
}

/* ================================================================
 * Exception / Cache
 * ================================================================ */

DK_API uint64_t DK_ExceptionRecordFree(void *record) {
    (void)record;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_InstructionCacheFlush(void *base, uint64_t length) {
    (void)base;(void)length;
    __builtin___clear_cache(base, (char*)base + length);
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * PAL Table Construction
 * ================================================================ */

/*
 * The PAL dispatch table that gets passed to the NTUM via
 * WINDOWS_LIBOS_PARAMETERS.HostAbiTable.
 *
 * The exact structure depends on how DKAbiGetFunction indexes
 * into it. Based on the RE, the ABI table has:
 * - Header: Size=0x10, SubSize=0x38
 * - Entries at 0x20-byte intervals with {version, func_ptr}
 * - Sentinel 0xFFFFFFFF at offset 0x30
 *
 * For now, we provide a basic table. The NTUM will call
 * DKAbiGetFunction to resolve individual functions.
 */

static uint8_t g_pal_dispatch_table[4096] __attribute__((aligned(64)));

void dk_pal_init(void) {
    memset(g_pal_dispatch_table, 0, sizeof(g_pal_dispatch_table));
    memset(g_handles, 0, sizeof(g_handles));

    /* Set up stdio handles */
    g_handles[0].type = 1; g_handles[0].fd = STDIN_FILENO;
    g_handles[1].type = 1; g_handles[1].fd = STDOUT_FILENO;
    g_handles[2].type = 1; g_handles[2].fd = STDERR_FILENO;

    /* ABI table header */
    uint32_t *header = (uint32_t*)g_pal_dispatch_table;
    header[0] = 0x10;   /* Size */
    header[1] = 0x38;   /* SubSize */

    /* Sentinel */
    uint64_t *sentinel = (uint64_t*)(g_pal_dispatch_table + 0x30);
    *sentinel = 0xFFFFFFFFFFFFFFFFULL;

    printf("[DK] PAL initialized with %d DK functions\n",
           (int)(sizeof(g_dk_functions)/sizeof(g_dk_functions[0]) - 1));
}

void *dk_pal_get_table(void) {
    return g_pal_dispatch_table;
}
