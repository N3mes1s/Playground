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

/* ================================================================
 * Handle Table
 * ================================================================ */

typedef struct {
    handle_type_t type;
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
    for (int i = 16; i < MAX_HANDLES; i++) {
        if (g_handles[i].type == HANDLE_FREE) {
            g_handles[i].type = (handle_type_t)-1;  /* Reserved */
            pthread_mutex_unlock(&g_handle_lock);
            return (DK_HANDLE)i;
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    return DK_NULL_HANDLE;
}

static void free_handle(DK_HANDLE h) {
    if (h < MAX_HANDLES) {
        g_handles[h].type = HANDLE_FREE;
    }
}

/* Forward declaration */
DK_API __attribute__((force_align_arg_pointer))
uint64_t DK_GenericStub(uint64_t a, uint64_t b, uint64_t c, uint64_t d);

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
        g_handles[h].type = HANDLE_FD;
        g_handles[h].fd = STDOUT_FILENO;
        *out_handle = h;
        return DK_STATUS_SUCCESS;
    }
    if (strncmp(path, "stderr:", 7) == 0) {
        DK_HANDLE h = alloc_handle();
        g_handles[h].type = HANDLE_FD;
        g_handles[h].fd = STDERR_FILENO;
        *out_handle = h;
        return DK_STATUS_SUCCESS;
    }
    if (strncmp(path, "stdin:", 6) == 0) {
        DK_HANDLE h = alloc_handle();
        g_handles[h].type = HANDLE_FD;
        g_handles[h].fd = STDIN_FILENO;
        *out_handle = h;
        return DK_STATUS_SUCCESS;
    }

    /* Strip Windows path prefix and convert backslashes */
    char *p = path;
    if (p[0] == '\\') p++;
    for (char *c = p; *c; c++)
        if (*c == '\\') *c = '/';

    int oflags = O_RDONLY;
    if (access & 0x40000000) oflags = O_RDWR;
    if (create_disp == 2) oflags |= O_CREAT | O_TRUNC;
    if (create_disp == 4) oflags |= O_CREAT;

    int fd = open(p, oflags, 0644);
    if (fd < 0)
        return DK_STATUS_INVALID_PARAM;

    DK_HANDLE h = alloc_handle();
    g_handles[h].type = HANDLE_FD;
    g_handles[h].fd = fd;
    *out_handle = h;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamRead(DK_HANDLE stream, uint64_t offset,
                               void *buffer, uint64_t bytes_to_read,
                               uint64_t *bytes_read) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != HANDLE_FD)
        return DK_STATUS_INVALID_PARAM;
    ssize_t n = pread(g_handles[stream].fd, buffer, bytes_to_read, (off_t)offset);
    if (n < 0) return DK_STATUS_INVALID_PARAM;
    if (bytes_read) *bytes_read = (uint64_t)n;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamWrite(DK_HANDLE stream, uint64_t offset,
                                const void *buffer, uint64_t bytes_to_write,
                                uint64_t *bytes_written) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != HANDLE_FD)
        return DK_STATUS_INVALID_PARAM;
    ssize_t n = pwrite(g_handles[stream].fd, buffer, bytes_to_write, (off_t)offset);
    if (n < 0)
        n = write(g_handles[stream].fd, buffer, bytes_to_write);
    if (n < 0) return DK_STATUS_INVALID_PARAM;
    if (bytes_written) *bytes_written = (uint64_t)n;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamClose(DK_HANDLE handle) {
    return DK_ObjectClose(handle);
}

DK_API uint64_t DK_StreamFlush(DK_HANDLE stream) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != HANDLE_FD)
        return DK_STATUS_SUCCESS;
    fsync(g_handles[stream].fd);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamSetLength(DK_HANDLE stream, uint64_t length) {
    if (stream >= MAX_HANDLES || g_handles[stream].type != HANDLE_FD)
        return DK_STATUS_INVALID_PARAM;
    if (ftruncate(g_handles[stream].fd, (off_t)length) < 0)
        return DK_STATUS_INVALID_PARAM;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamMap(DK_HANDLE stream, void *address,
                              uint64_t offset, uint64_t size,
                              uint64_t protect, void **mapped) {
    (void)protect;

    /* Protect PE image range from being overwritten by file maps */
    uintptr_t addr = (uintptr_t)address;
    if (address && addr >= PE_IMAGE_START && addr < PE_IMAGE_END) {
        if (mapped) *mapped = address;
        return DK_STATUS_SUCCESS;
    }

    int fd = -1;
    if (stream < MAX_HANDLES && g_handles[stream].type == HANDLE_FD)
        fd = g_handles[stream].fd;

    int flags = MAP_PRIVATE;
    if (address) flags |= MAP_FIXED_NOREPLACE;

    void *result = mmap(address, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        flags, fd, (off_t)offset);
    if (result == MAP_FAILED && address) {
        mprotect(address, size, PROT_READ | PROT_WRITE | PROT_EXEC);
        result = address;
    }
    if (result == MAP_FAILED) return DK_STATUS_NO_MEMORY;
    if (mapped) *mapped = result;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamMapPeBinary(DK_HANDLE stream, void **base,
                                      uint64_t *entry_point) {
    (void)stream;
    if (base) *base = (void*)PE_IMAGE_START;
    if (entry_point) *entry_point = PE_IMAGE_START + NTUM_ENTRY_RVA;
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
    (void)in_handle; (void)op_code; (void)in_buf; (void)in_size;
    (void)out_buf; (void)out_size;
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
    (void)stream; (void)buf; (void)buf_size; (void)used;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamRename(DK_HANDLE stream, const void *new_name) {
    (void)stream; (void)new_name;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamChangesRegister(DK_HANDLE stream, uint64_t filter,
                                          uint64_t watch_tree, DK_HANDLE *event) {
    (void)stream; (void)filter; (void)watch_tree; (void)event;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamChangesPoll(DK_HANDLE stream, void *buf, uint64_t *size) {
    (void)stream; (void)buf; (void)size;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamRangeLock(DK_HANDLE stream, uint64_t off, uint64_t len,
                                    uint64_t exclusive) {
    (void)stream; (void)off; (void)len; (void)exclusive;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamRangeUnlock(DK_HANDLE stream, uint64_t off, uint64_t len) {
    (void)stream; (void)off; (void)len;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamGetEvent(DK_HANDLE stream, uint64_t event_id,
                                   DK_HANDLE *event) {
    (void)stream; (void)event_id; (void)event;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamEventSelect(DK_HANDLE stream, DK_HANDLE event,
                                      uint64_t poll_events, DK_HANDLE *async) {
    (void)stream; (void)event; (void)poll_events; (void)async;
    return DK_STATUS_NOT_IMPLEMENTED;
}

/* ================================================================
 * Memory Management
 * ================================================================ */

static int dk_prot_to_linux(uint64_t dk_prot) {
    int prot = 0;
    if (dk_prot & WIN_PAGE_NOACCESS)          prot |= PROT_READ;
    if (dk_prot & WIN_PAGE_READONLY)          prot |= PROT_READ | PROT_WRITE;
    if (dk_prot & WIN_PAGE_READWRITE)         prot |= PROT_READ | PROT_WRITE;
    if (dk_prot & WIN_PAGE_EXECUTE)           prot |= PROT_EXEC;
    if (dk_prot & WIN_PAGE_EXECUTE_READ)      prot |= PROT_READ | PROT_EXEC;
    if (dk_prot & WIN_PAGE_EXECUTE_READWRITE) prot |= PROT_READ | PROT_WRITE | PROT_EXEC;
    if (prot == 0) prot = PROT_READ | PROT_WRITE;
    return prot;
}

DK_API uint64_t DK_VirtualMemoryAllocate(void **address, uint64_t *size,
                                          uint64_t alloc_type, uint64_t protect) {
    void *hint = address ? *address : NULL;
    size_t len = size ? *size : 4096;

    fprintf(stderr, "[PAL] VirtualAlloc(%p, 0x%lx, type=0x%lx, prot=0x%lx)\n",
            hint, (unsigned long)len, (unsigned long)alloc_type,
            (unsigned long)protect);

    int prot_linux = dk_prot_to_linux(protect);
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (hint) flags |= MAP_FIXED_NOREPLACE;
    if (alloc_type & WIN_MEM_RESERVE) flags |= MAP_NORESERVE;

    void *result = mmap(hint, len, prot_linux, flags, -1, 0);
    if (result == MAP_FAILED) {
        if (hint) {
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

DK_API uint64_t DK_VirtualMemoryFree(void *address, uint64_t size,
                                      uint64_t free_type) {
    (void)free_type;
    if (size == 0) size = 4096;

    /* Don't unmap the PE image range */
    uintptr_t addr = (uintptr_t)address;
    if (addr >= PE_IMAGE_START && addr < PE_IMAGE_END)
        return DK_STATUS_SUCCESS;

    munmap(address, size);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_VirtualMemoryProtect(void *address, uint64_t size,
                                         uint64_t new_protect,
                                         uint64_t *old_protect) {
    if (old_protect) *old_protect = WIN_PAGE_READWRITE;
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

    g_handles[h].type = HANDLE_THREAD;
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

DK_API uint64_t DK_ThreadSetAffinity(DK_HANDLE thread, uint64_t group,
                                      uint64_t mask) {
    (void)thread; (void)group; (void)mask;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Synchronization
 * ================================================================ */

DK_API uint64_t DK_NotificationEventCreate(uint64_t initial_state,
                                            DK_HANDLE *event) {
    int efd = eventfd(initial_state ? 1 : 0, EFD_NONBLOCK);
    if (efd < 0) return DK_STATUS_NO_MEMORY;
    DK_HANDLE h = alloc_handle();
    g_handles[h].type = HANDLE_EVENT;
    g_handles[h].eventfd = efd;
    if (event) *event = h;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SynchronizationEventCreate(uint64_t initial_state,
                                               DK_HANDLE *event) {
    return DK_NotificationEventCreate(initial_state, event);
}

DK_API uint64_t DK_EventSet(DK_HANDLE event) {
    if (event >= MAX_HANDLES || g_handles[event].type != HANDLE_EVENT)
        return DK_STATUS_INVALID_PARAM;
    uint64_t val = 1;
    ssize_t ret = write(g_handles[event].eventfd, &val, sizeof(val));
    (void)ret;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventClear(DK_HANDLE event) {
    if (event >= MAX_HANDLES || g_handles[event].type != HANDLE_EVENT)
        return DK_STATUS_INVALID_PARAM;
    uint64_t val;
    ssize_t ret = read(g_handles[event].eventfd, &val, sizeof(val));
    (void)ret;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventPeek(DK_HANDLE event, uint64_t *signaled) {
    if (event >= MAX_HANDLES || g_handles[event].type != HANDLE_EVENT)
        return DK_STATUS_INVALID_PARAM;
    struct pollfd pfd = { .fd = g_handles[event].eventfd, .events = POLLIN };
    int ret = poll(&pfd, 1, 0);
    if (signaled) *signaled = (ret > 0) ? 1 : 0;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ObjectsWaitAny(uint64_t count, DK_HANDLE *objects,
                                   uint64_t timeout, uint64_t *index) {
    (void)count; (void)objects; (void)timeout;
    if (index) *index = 0;
    usleep(1000);
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Object Management
 * ================================================================ */

DK_API uint64_t DK_ObjectClose(DK_HANDLE handle) {
    if (handle >= MAX_HANDLES) return DK_STATUS_INVALID_PARAM;
    handle_entry_t *e = &g_handles[handle];
    switch (e->type) {
        case HANDLE_FD:     if (e->fd > 2) close(e->fd); break;
        case HANDLE_EVENT:  close(e->eventfd); break;
        case HANDLE_MUTEX:  pthread_mutex_destroy(e->mutex); free(e->mutex); break;
        case HANDLE_MAPPED: munmap(e->map.addr, e->map.size); break;
        default: break;
    }
    free_handle(handle);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ObjectReference(DK_HANDLE handle) {
    (void)handle;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Process Management
 * ================================================================ */

DK_API uint64_t DK_ProcessCreate(void *params, DK_HANDLE *process) {
    (void)params; (void)process;
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API void DK_ProcessExit(uint64_t exit_code) {
    _exit((int)exit_code);
}

DK_API uint64_t DK_ProcessTerminate(DK_HANDLE process,
                                     uint64_t exit_code) {
    (void)process; (void)exit_code;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ProcessGetExitCode(DK_HANDLE process,
                                       uint64_t *exit_code) {
    (void)process;
    if (exit_code) *exit_code = 0;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * System
 * ================================================================ */

DK_API uint64_t DK_SystemTimeQuery(uint64_t clock_type,
                                    uint64_t *time_val) {
    struct timespec ts;
    clockid_t clk = (clock_type == 0) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
    clock_gettime(clk, &ts);

    /* Return as Windows FILETIME (100ns intervals since 1601) */
    uint64_t ft = ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL
                  + (uint64_t)ts.tv_nsec / 100;
    if (time_val) *time_val = ft;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_RandomBitsRead(void *buffer, uint64_t length) {
    ssize_t ret = getrandom(buffer, length, 0);
    return (ret == (ssize_t)length) ? DK_STATUS_SUCCESS
                                    : DK_STATUS_INVALID_PARAM;
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
 *
 * The NTUM calls this through [NTUM_GUARD_DISPATCH_ADDR] with Win64:
 *   rcx = HostAbiTable pointer
 *   rdx = ABI call type ID
 *   r8  = data size
 *   r9  = input buffer pointer
 *   [rsp+0x28] = output size
 *   [rsp+0x30] = output buffer pointer
 * ================================================================ */

DK_API __attribute__((force_align_arg_pointer))
uint64_t DK_AbiDispatcher(uint64_t context, uint64_t call_type,
                           uint64_t data_size, void *in_buf,
                           uint64_t out_size, void *out_buf) {
    (void)context; (void)out_size;

    /* Re-arm the ABI dispatcher pointer in .data */
    *(volatile uint64_t*)NTUM_ABI_DISPATCHER_ADDR =
        (uint64_t)&DK_AbiDispatcher;

    static int dispatch_count = 0;
    dispatch_count++;
    if (dispatch_count <= 1000) {
        fprintf(stderr, "[DK] Call #%d: type=0x%lx funcid=0x%x\n",
                dispatch_count, (unsigned long)call_type,
                (in_buf && call_type == ABI_GET_FUNCTION_V2)
                    ? *(uint32_t*)in_buf : (uint32_t)data_size);
    }

    if (call_type == ABI_GET_FUNCTION_V2) {
        uint32_t *in = (uint32_t*)in_buf;
        uint32_t func_id = in ? in[0] : 0;

        void *func = (void*)&DK_GenericStub;

        switch (func_id) {
        /* Stream I/O (category 0x01) */
        case 0x1001000: func = (void*)&DK_StreamOpen; break;
        case 0x1002000: func = (void*)&DK_StreamRead; break;
        case 0x1003000: func = (void*)&DK_StreamWrite; break;
        case 0x1004000: func = (void*)&DK_StreamFlush; break;
        case 0x1005000: func = (void*)&DK_ObjectClose; break;
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

        /* Memory (category 0x02) */
        case 0x2001000: func = (void*)&DK_VirtualMemoryAllocate; break;
        case 0x2002000: func = (void*)&DK_VirtualMemoryFree; break;
        case 0x2004000: func = (void*)&DK_VirtualMemoryProtect; break;

        /* Threading (category 0x04) */
        case 0x4001000: func = (void*)&DK_ThreadCreate; break;
        case 0x4002000: func = (void*)&DK_ThreadExit; break;
        case 0x4003000: func = (void*)&DK_ThreadYieldExecution; break;

        /* Synchronization (category 0x05) */
        case 0x5001000: func = (void*)&DK_NotificationEventCreate; break;
        case 0x5002000: func = (void*)&DK_SynchronizationEventCreate; break;
        case 0x5003000: func = (void*)&DK_ObjectsWaitAny; break;

        /* Console (category 0x06) */
        case 0x6001000: func = (void*)&DK_ConsoleCreate; break;

        /* ABI (category 0x07) */
        case 0x7002000: func = (void*)&DK_AbiGetFunction; break;

        /* System (category 0x08) */
        case 0x8001000: func = (void*)&DK_SystemTimeQuery; break;
        case 0x8002000: func = (void*)&DK_RandomBitsRead; break;

        /* Process (category 0x09) */
        case 0x9001000: func = (void*)&DK_ProcessCreate; break;
        case 0x9002000: func = (void*)&DK_ProcessExit; break;
        case 0x9003000: func = (void*)&DK_ProcessTerminate; break;
        case 0x9004000: func = (void*)&DK_ProcessGetExitCode; break;

        /* Exception (category 0x0A) */
        case 0xa001000: func = (void*)&DK_ExceptionRecordFree; break;

        /* Objects (category 0x0B) */
        case 0xb001000: func = (void*)&DK_ObjectClose; break;
        case 0xb002000: func = (void*)&DK_ObjectReference; break;

        /* Cache/Events (category 0x0C) */
        case 0xc001000: func = (void*)&DK_InstructionCacheFlush; break;
        case 0xc002000: func = (void*)&DK_EventSet; break;
        case 0xc003000: func = (void*)&DK_EventClear; break;
        case 0xc004000: func = (void*)&DK_EventPeek; break;

        /* Extended threading (category 0x0E) */
        case 0xe001000: func = (void*)&DK_ThreadInterrupt; break;
        case 0xe002000: func = (void*)&DK_ThreadSetAffinity; break;

        /* Memory v2 (category 0x12) */
        case 0x12001000: func = (void*)&DK_VirtualMemoryAllocate; break;
        case 0x12002000: func = (void*)&DK_VirtualMemoryFree; break;
        case 0x12003000: func = (void*)&DK_VirtualMemoryProtect; break;

        /* Random (category 0x13) */
        case 0x13001000: func = (void*)&DK_RandomBitsRead; break;

        default: break;
        }

        /* Write function pointer to output buffer.
         * Try both single-deref and double-deref - the NTUM expects
         * one or the other depending on how the call site was compiled.
         *
         * From decompiled FUN_00269650: the caller reads the function
         * pointer from the output area. We write to *out_buf directly
         * AND return the function pointer as the return value. */
        if (out_buf) {
            /* Single-deref: write directly to out_buf */
            *(uint64_t*)out_buf = (uint64_t)func;

            /* Also try double-deref if the pointer looks valid */
            uint64_t *slot = *(uint64_t**)out_buf;
            if (slot && (uintptr_t)slot > 0x1000 && (uintptr_t)slot < LIBOS_VM_END) {
                *slot = (uint64_t)func;
            }
        }
        return (uint64_t)func;
    }

    if (call_type == ABI_GET_VERSION_V2) {
        if (out_buf)
            *(uint32_t*)out_buf = 2;
        return DK_STATUS_NOT_IMPLEMENTED;
    }

    fprintf(stderr, "[DK] PostRes: type=0x%lx size=0x%lx in=%p\n",
            (unsigned long)call_type, (unsigned long)data_size, in_buf);
    return DK_STATUS_SUCCESS;
}

/* Generic PAL stub - returns success for unimplemented functions */
DK_API __attribute__((force_align_arg_pointer))
uint64_t DK_GenericStub(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    static int stub_count = 0;
    stub_count++;
    if (stub_count <= 20) {
        fprintf(stderr, "[STUB] #%d: a=0x%lx b=0x%lx c=0x%lx d=0x%lx\n",
                stub_count, (unsigned long)a, (unsigned long)b,
                (unsigned long)c, (unsigned long)d);
    }
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_AbiGetFunction(uint64_t abi_id, void **func_ptr) {
    void *result = (void*)&DK_GenericStub;

    switch (abi_id) {
    /* Stream */
    case 0x01: result = (void*)&DK_StreamOpen; break;
    case 0x02: result = (void*)&DK_StreamRead; break;
    case 0x03: result = (void*)&DK_StreamWrite; break;
    case 0x04: result = (void*)&DK_StreamFlush; break;
    case 0x05: result = (void*)&DK_ObjectClose; break;
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

    /* Synchronization */
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

    /* ABI version */
    case 0x90: result = (void*)&DK_AbiDispatcher; break;
    }

    if (func_ptr) *func_ptr = result;
    fprintf(stderr, "[DK] AbiGetFunction(0x%lx) -> %p\n",
            (unsigned long)abi_id, result);
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
    __builtin___clear_cache(base, (char*)base + length);
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * PAL Table Construction
 *
 * The PAL dispatch table passed to the NTUM via
 * WINDOWS_LIBOS_PARAMETERS.HostAbiTable.
 *
 * Layout (from DAT_00369ec8):
 *   +0x00: Size=0x10, SubSize=0x38
 *   +0x08: ABI dispatcher function pointer
 *   +0x30: 0xFFFFFFFFFFFFFFFF (sentinel)
 * ================================================================ */

static uint8_t g_pal_dispatch_table[4096] __attribute__((aligned(64)));

void dk_pal_init(void) {
    memset(g_pal_dispatch_table, 0, sizeof(g_pal_dispatch_table));
    memset(g_handles, 0, sizeof(g_handles));

    /* Set up stdio handles */
    g_handles[0].type = HANDLE_FD; g_handles[0].fd = STDIN_FILENO;
    g_handles[1].type = HANDLE_FD; g_handles[1].fd = STDOUT_FILENO;
    g_handles[2].type = HANDLE_FD; g_handles[2].fd = STDERR_FILENO;

    /* ABI table header */
    uint32_t *header = (uint32_t*)g_pal_dispatch_table;
    header[0] = PAL_TABLE_SIZE_FIELD;
    header[1] = PAL_TABLE_SUBSIZE_FIELD;

    /* ABI dispatcher at offset 8 */
    *(uint64_t*)(g_pal_dispatch_table + 8) = (uint64_t)&DK_AbiDispatcher;

    /* Sentinel at offset 0x30 */
    *(uint64_t*)(g_pal_dispatch_table + 0x30) = PAL_TABLE_SENTINEL;

    printf("[DK] PAL initialized with 72 DK functions\n");
}

void *dk_pal_get_table(void) {
    return g_pal_dispatch_table;
}
