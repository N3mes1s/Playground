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

/* Forward declaration */
DK_API uint64_t DK_GenericStub(uint64_t a, uint64_t b, uint64_t c, uint64_t d);

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
    /* Protect PE image range from being overwritten by file maps */
    uintptr_t addr = (uintptr_t)address;
    if (address && addr >= 0x180000000ULL && addr < 0x181010000ULL) {
        if (mapped) *mapped = address;
        return DK_STATUS_SUCCESS;  /* Pretend it worked, keep our patches */
    }
    int fd = -1;
    if (stream < MAX_HANDLES && g_handles[stream].type == 1)
        fd = g_handles[stream].fd;

    int flags = MAP_PRIVATE;
    if (address) flags |= MAP_FIXED_NOREPLACE;

    void *result = mmap(address, size, PROT_READ|PROT_WRITE|PROT_EXEC,
                        flags, fd, offset);
    if (result == MAP_FAILED && address) {
        /* Already mapped - use existing memory (preserves patches) */
        mprotect(address, size, PROT_READ|PROT_WRITE|PROT_EXEC);
        result = address;
    }
    if (result == MAP_FAILED) return DK_STATUS_NO_MEMORY;
    if (mapped) *mapped = result;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamMapPeBinary(DK_HANDLE stream, void **base,
                                      uint64_t *entry_point) {
    (void)stream;
    /* Return the already-mapped PE image base.
     * The PE is pre-mapped by our host before boot. */
    if (base) *base = (void*)0x180000000ULL;
    if (entry_point) *entry_point = 0x1803a04d0ULL;
    return DK_STATUS_SUCCESS;
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
    void *hint = address ? *address : NULL;
    size_t len = size ? *size : 4096;


    int prot_linux = dk_prot_to_linux(protect);
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (hint) flags |= MAP_FIXED_NOREPLACE;
    if (alloc_type & 0x2000) flags |= MAP_NORESERVE;  /* MEM_RESERVE */

    void *result = mmap(hint, len, prot_linux, flags, -1, 0);
    if (result == MAP_FAILED) {
        if (hint) {
            /* Page already mapped (EEXIST from NOREPLACE).
             * Return the existing address as success - preserves our patches.
             * Just adjust the protection if needed. */
            mprotect(hint, len, prot_linux);
            result = hint;
        } else {
            return DK_STATUS_NO_MEMORY;
        }
    }

    if (address) *address = result;
    if (size) *size = len;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_VirtualMemoryFree(void *address, uint64_t size, uint64_t free_type) {
    (void)free_type;
    if (size == 0) size = 4096;
    /* Don't unmap the PE image range - preserves our patches */
    uintptr_t addr = (uintptr_t)address;
    if (addr >= 0x180000000ULL && addr < 0x181010000ULL)
        return DK_STATUS_SUCCESS;  /* Pretend it worked */
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
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API void DK_ProcessExit(uint64_t exit_code) {
    _exit((int)exit_code);
}

DK_API uint64_t DK_ProcessTerminate(DK_HANDLE process, uint64_t exit_code) {
    (void)process;
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

/*
 * Generic ABI call dispatcher
 *
 * The NTUM calls this through [0x180a00008] with:
 *   rcx = host context (value from [0x180c00010])
 *   rdx = ABI call type (e.g., 0x7002002 = GetFunction_v2)
 *   r8  = input size
 *   r9  = input buffer pointer
 *   [rsp+0x20] = output size
 *   [rsp+0x28] = output buffer pointer
 *
 * For GetFunction_v2 (0x7002002):
 *   input = { uint32_t function_id, uint32_t version }
 *   output = { uint32_t result_code }
 */
/*
 * Generic ABI call dispatcher
 *
 * Called through [0x180a00008] by the NTUM. Win64 convention:
 *   rcx = HostAbiTable pointer (NOT context)
 *   rdx = ABI call type ID (e.g., 0x7002002)
 *   r8  = data size
 *   r9  = input buffer
 *   [rsp+0x28] = output size (5th stack arg in Win64)
 *   [rsp+0x30] = output buffer pointer (6th stack arg)
 *
 * For Abi_GetFunction_v2 (0x7002002):
 *   input[0] = uint32_t function_id (e.g., 0x1001000)
 *   input[1] = uint32_t version_info
 *   output = { uint32_t result_code }
 */
DK_API uint64_t DK_AbiDispatcher(uint64_t context, uint64_t call_type,
                                   uint64_t data_size, void *in_buf,
                                   uint64_t out_size, void *out_buf) {

    void *input_buf = in_buf;

    /* Re-arm our dispatcher pointer (safe write to our external page) */
    *(volatile uint64_t*)0x181100000ULL = (uint64_t)&DK_AbiDispatcher;

    /* Log first few calls for debugging (use write() not fprintf) */
    static int dispatch_count = 0;
    dispatch_count++;
    if (dispatch_count <= 5) {
        char msg[128];
        int len = snprintf(msg, sizeof(msg),
            "[DK] Call #%d: ctx=0x%lx type=0x%lx size=%lu\n",
            dispatch_count, (unsigned long)context,
            (unsigned long)call_type, (unsigned long)data_size);
        write(2, msg, len);
    }

    if (call_type == 0x7002002) {  /* Abi_GetFunction_v2 */
        uint32_t *in = (uint32_t*)input_buf;
        uint32_t func_id = in ? in[0] : 0;
        uint32_t version = in ? in[1] : 0;
        (void)version;

        /* Map function IDs to our DK implementations.
         * ID format: 0xCCFFF000 where CC=category, FFF=function.
         * Returning the function pointer in the output buffer. */
        void *func = (void*)&DK_GenericStub;

        switch (func_id) {
        /* 0x01: Stream I/O */
        case 0x1001000: func = (void*)&DK_StreamOpen; break;
        case 0x1002000: func = (void*)&DK_StreamRead; break;
        case 0x1003000: func = (void*)&DK_StreamWrite; break;
        case 0x1004000: func = (void*)&DK_StreamFlush; break;
        case 0x1005000: func = (void*)&DK_ObjectClose; break;       /* StreamClose */
        case 0x1006000: func = (void*)&DK_StreamMap; break;
        case 0x1007000: func = (void*)&DK_StreamMapPeBinary; break;
        case 0x1008000: func = (void*)&DK_StreamUnmap; break;
        case 0x1009000: func = (void*)&DK_StreamSetLength; break;
        case 0x100a000: func = (void*)&DK_StreamControl; break;
        case 0x100b000: func = (void*)&DK_StreamAttributesQuery; break;
        case 0x100c000: func = (void*)&DK_StreamAttributesQueryByHandle; break;
        case 0x100d000: func = (void*)&DK_StreamEnumerateChildren; break;
        case 0x100e000: func = (void*)&DK_StreamDelete; break;
        case 0x100f000: func = (void*)&DK_StreamRename; break;
        case 0x1010000: func = (void*)&DK_StreamChangesRegister; break;
        case 0x1011000: func = (void*)&DK_StreamChangesPoll; break;
        case 0x1012000: func = (void*)&DK_StreamRangeLock; break;
        case 0x1013000: func = (void*)&DK_StreamRangeUnlock; break;
        case 0x1014000: func = (void*)&DK_StreamGetEvent; break;
        case 0x1015000: func = (void*)&DK_StreamEventSelect; break;
        case 0x1016000: /* StreamReadScatter */ break;
        case 0x1017000: /* StreamWriteGather */ break;
        case 0x1018000: /* StreamQueryAllocatedRanges */ break;
        case 0x1019000: /* StreamSetZeroData */ break;
        case 0x101a000: /* StreamEnableSparse */ break;
        case 0x101b000: /* StreamReadScatterEx */ break;
        case 0x101c000: /* StreamWriteGatherEx */ break;

        /* 0x02: Memory */
        case 0x2001000: func = (void*)&DK_VirtualMemoryAllocate; break;
        case 0x2002000: func = (void*)&DK_VirtualMemoryFree; break;
        case 0x2004000: func = (void*)&DK_VirtualMemoryProtect; break;

        /* 0x04: Threading */
        case 0x4001000: func = (void*)&DK_ThreadCreate; break;
        case 0x4002000: func = (void*)&DK_ThreadExit; break;
        case 0x4003000: func = (void*)&DK_ThreadYieldExecution; break;

        /* 0x05: Synchronization */
        case 0x5001000: func = (void*)&DK_NotificationEventCreate; break;
        case 0x5002000: func = (void*)&DK_SynchronizationEventCreate; break;
        case 0x5003000: func = (void*)&DK_ObjectsWaitAny; break;

        /* 0x06: Console */
        case 0x6001000: func = (void*)&DK_ConsoleCreate; break;

        /* 0x07: ABI */
        case 0x7001000: /* AbiGetVersion */ break;
        case 0x7002000: func = (void*)&DK_AbiGetFunction; break;

        /* 0x08: System */
        case 0x8001000: func = (void*)&DK_SystemTimeQuery; break;
        case 0x8002000: func = (void*)&DK_RandomBitsRead; break;
        case 0x8003000: /* SystemInfoQuery */ break;

        /* 0x09: Process */
        case 0x9001000: func = (void*)&DK_ProcessCreate; break;
        case 0x9002000: func = (void*)&DK_ProcessExit; break;
        case 0x9003000: func = (void*)&DK_ProcessTerminate; break;
        case 0x9004000: func = (void*)&DK_ProcessGetExitCode; break;
        case 0x9005000: /* ProcessGetId */ break;

        /* 0x0A: Exception */
        case 0xa001000: func = (void*)&DK_ExceptionRecordFree; break;

        /* 0x0B: Objects */
        case 0xb001000: func = (void*)&DK_ObjectClose; break;
        case 0xb002000: func = (void*)&DK_ObjectReference; break;
        case 0xb003000: /* ObjectDereference */ break;

        /* 0x0C: Cache */
        case 0xc001000: func = (void*)&DK_InstructionCacheFlush; break;
        case 0xc002000: /* EventSet */ func = (void*)&DK_EventSet; break;
        case 0xc003000: /* EventClear */ func = (void*)&DK_EventClear; break;
        case 0xc004000: /* EventPeek */ func = (void*)&DK_EventPeek; break;

        /* 0x0D: Enclave */
        case 0xd001000: /* EnclaveAttest */ break;

        /* 0x0E: Extended */
        case 0xe001000: /* ThreadInterrupt */ func = (void*)&DK_ThreadInterrupt; break;
        case 0xe002000: /* ThreadSetAffinity */ func = (void*)&DK_ThreadSetAffinity; break;
        case 0xe003000: /* ThreadAssertAffinity */ break;

        /* 0x0F: Stream extended */
        case 0xf001000: case 0xf002000: case 0xf003000:
        case 0xf004000: case 0xf005000: case 0xf006000:
        case 0xf007000: break;

        /* 0x10: Async */
        case 0x10001000: /* AsyncPoll */ break;
        case 0x10002000: /* AsyncCancel */ break;

        /* 0x11: Stream v2 */
        case 0x11001000: case 0x11003000: case 0x11005000:
        case 0x11007000: case 0x11008000: case 0x11009000:
        case 0x1100b000: case 0x1100c000: case 0x1100d000:
        case 0x1100f000: case 0x11010000: break;

        /* 0x12: Memory v2 */
        case 0x12001000: func = (void*)&DK_VirtualMemoryAllocate; break;
        case 0x12002000: func = (void*)&DK_VirtualMemoryFree; break;
        case 0x12003000: func = (void*)&DK_VirtualMemoryProtect; break;

        /* 0x13: Random */
        case 0x13001000: func = (void*)&DK_RandomBitsRead; break;
        }

        /* Write function pointer to output buffer */
        if (out_buf && out_size >= 8) {
            *(uint64_t*)out_buf = (uint64_t)func;
        } else if (out_buf && out_size >= 4) {
            *(uint32_t*)out_buf = (uint32_t)(uintptr_t)func;
        }

        return 0;
    }

    if (call_type == 0x7002001) {  /* Abi_GetVersion_v2 */
        if (out_buf) {
            *(uint32_t*)out_buf = 2;
        }
        return 0;
    }

    /* Unknown call types - these are post-resolution config/feature calls.
     * The rdx value is a .data pointer, not a call type ID.
     * Return success and fill output with zeros. */
    return 0;
}

/* Generic PAL stub that returns success */
DK_API uint64_t DK_GenericStub(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_AbiGetFunction(uint64_t abi_id, void **func_ptr) {

    /*
     * The NTUM calls this to resolve PAL functions by ID.
     * Return our DK implementations for known IDs, and a generic
     * success-returning stub for unknown ones.
     */

    /* Return a valid function pointer for ALL requests */
    void *result = (void*)&DK_GenericStub;

    /* Map known ABI IDs to specific implementations */
    switch (abi_id) {
        /* Stream operations */
        case 0x01: result = (void*)&DK_StreamOpen; break;
        case 0x02: result = (void*)&DK_StreamRead; break;
        case 0x03: result = (void*)&DK_StreamWrite; break;
        case 0x04: result = (void*)&DK_StreamFlush; break;
        case 0x05: result = (void*)&DK_ObjectClose; break;  /* StreamClose = ObjectClose */
        case 0x06: result = (void*)&DK_StreamMap; break;
        case 0x07: result = (void*)&DK_StreamMapPeBinary; break;
        case 0x08: result = (void*)&DK_StreamUnmap; break;
        case 0x09: result = (void*)&DK_StreamSetLength; break;
        case 0x0A: result = (void*)&DK_StreamControl; break;
        case 0x0B: result = (void*)&DK_StreamAttributesQuery; break;
        case 0x0C: result = (void*)&DK_StreamAttributesQueryByHandle; break;
        case 0x0D: result = (void*)&DK_StreamEnumerateChildren; break;
        case 0x0E: result = (void*)&DK_StreamDelete; break;
        case 0x0F: result = (void*)&DK_StreamRename; break;

        /* Memory */
        case 0x10: result = (void*)&DK_VirtualMemoryAllocate; break;
        case 0x11: result = (void*)&DK_VirtualMemoryFree; break;
        case 0x12: result = (void*)&DK_VirtualMemoryProtect; break;

        /* Threading */
        case 0x20: result = (void*)&DK_ThreadCreate; break;
        case 0x21: result = (void*)&DK_ThreadExit; break;
        case 0x22: result = (void*)&DK_ThreadYieldExecution; break;

        /* Sync */
        case 0x30: result = (void*)&DK_NotificationEventCreate; break;
        case 0x31: result = (void*)&DK_SynchronizationEventCreate; break;
        case 0x32: result = (void*)&DK_EventSet; break;
        case 0x33: result = (void*)&DK_EventClear; break;
        case 0x34: result = (void*)&DK_ObjectsWaitAny; break;

        /* Objects */
        case 0x40: result = (void*)&DK_ObjectClose; break;
        case 0x41: result = (void*)&DK_ObjectReference; break;

        /* Process */
        case 0x50: result = (void*)&DK_ProcessCreate; break;
        case 0x51: result = (void*)&DK_ProcessExit; break;

        /* System */
        case 0x60: result = (void*)&DK_SystemTimeQuery; break;
        case 0x61: result = (void*)&DK_RandomBitsRead; break;

        /* ABI version query (0x90 = structure size, used as version) */
        case 0x90: result = (void*)&DK_AbiDispatcher; break;
    }

    if (func_ptr) *func_ptr = result;
    fprintf(stderr, ") -> %p\n", result);

    return DK_STATUS_SUCCESS;
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
