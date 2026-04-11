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
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamControl(DK_HANDLE in_handle, uint64_t op_code,
                                  void *in_buf, uint64_t in_size,
                                  void *out_buf, uint64_t out_size) {
    (void)in_handle; (void)op_code; (void)in_buf; (void)in_size;
    (void)out_buf; (void)out_size;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamAttributesQuery(const void *uri, void *attrs) {
    (void)uri; (void)attrs;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamAttributesQueryByHandle(DK_HANDLE stream,
                                                   uint64_t flags, void *attrs) {
    (void)stream; (void)flags; (void)attrs;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamEnumerateChildren(DK_HANDLE stream, void *buf,
                                            uint64_t buf_size, uint64_t *used) {
    (void)stream; (void)buf; (void)buf_size; (void)used;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamRename(DK_HANDLE stream, const void *new_name) {
    (void)stream; (void)new_name;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamChangesRegister(DK_HANDLE stream, uint64_t filter,
                                          uint64_t watch_tree, DK_HANDLE *event) {
    (void)stream; (void)filter; (void)watch_tree; (void)event;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamChangesPoll(DK_HANDLE stream, void *buf, uint64_t *size) {
    (void)stream; (void)buf; (void)size;
    return DK_STATUS_SUCCESS;
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
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamEventSelect(DK_HANDLE stream, DK_HANDLE event,
                                      uint64_t poll_events, DK_HANDLE *async) {
    (void)stream; (void)event; (void)poll_events; (void)async;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Memory Management
 * ================================================================ */

/*
 * Protection flag converter - matches the REAL sqlservr implementation
 * at FUN_001d9720:
 *   return (flags & 3) | ((flags >> 1) & 6);
 *
 * This maps Drawbridge protection values to Linux PROT_* flags:
 *   DK prot 0 → Linux 0 (PROT_NONE)
 *   DK prot 1 → Linux 1 (PROT_READ)
 *   DK prot 2 → Linux 3 (PROT_READ|PROT_WRITE)
 *   DK prot 3 → Linux 3 (PROT_READ|PROT_WRITE)
 *   DK prot 4 → Linux 6 (PROT_WRITE|PROT_EXEC) - actually R+X
 *   DK prot 5 → Linux 5 (PROT_READ|PROT_EXEC)
 *   DK prot 6 → Linux 7 (PROT_READ|PROT_WRITE|PROT_EXEC)
 */
static int dk_prot_to_linux(uint64_t dk_prot) {
    uint32_t p = (uint32_t)dk_prot;
    int linux_prot = (int)((p & 3) | ((p >> 1) & 6));
    /* Ensure at least RW for non-zero protections so pages are accessible */
    if (linux_prot == 0 && p != 0) linux_prot = PROT_READ | PROT_WRITE;
    return linux_prot;
}

/*
 * DK_VirtualMemoryAllocate - based on real FUN_0024b4f0 / FUN_0024b210
 *
 * Real behavior:
 * 1. Page-aligns address down and size up
 * 2. MEM_RESERVE only → MAP_NORESERVE
 * 3. MEM_COMMIT → MAP_PRIVATE|MAP_ANONYMOUS, MAP_FIXED if address given
 * 4. Protects PE image range from remapping
 * 5. Protection flags via (p & 3) | ((p >> 1) & 6)
 */
DK_API uint64_t DK_VirtualMemoryAllocate(void **address, uint64_t *size,
                                          uint64_t alloc_type, uint64_t protect) {
    void *hint = address ? *address : NULL;
    size_t len = size ? *size : 0x1000;

    /* Page-align (real host does this) */
    uintptr_t addr_val = (uintptr_t)hint;
    uintptr_t aligned = addr_val & ~0xFFFULL;
    size_t extra = addr_val - aligned;
    size_t aligned_len = (len + extra + 0xFFF) & ~0xFFFULL;
    if (aligned_len == 0) aligned_len = 0x1000;

    static int va_count = 0;
    va_count++;
    if (va_count <= 50) {
        fprintf(stderr, "[PAL] VirtualAlloc(%p→0x%lx, 0x%lx, type=0x%lx, prot=0x%lx)\n",
                hint, (unsigned long)aligned, (unsigned long)aligned_len,
                (unsigned long)alloc_type, (unsigned long)protect);
    }

    int prot_linux = dk_prot_to_linux(protect);
    if (prot_linux == 0) prot_linux = PROT_READ | PROT_WRITE;

    /* Protect PE image range - don't remap, just adjust protection */
    if (hint && aligned >= PE_IMAGE_START && aligned < PE_IMAGE_END) {
        mprotect((void*)aligned, aligned_len, prot_linux);
        if (address) *address = hint;
        if (size) *size = aligned_len;
        return DK_STATUS_SUCCESS;
    }

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if ((alloc_type & WIN_MEM_RESERVE) && !(alloc_type & WIN_MEM_COMMIT))
        flags |= MAP_NORESERVE;

    if (hint) {
        /* Real host uses MAP_FIXED for commit with address.
         * We use NOREPLACE first to avoid clobbering, then FIXED as fallback. */
        void *result = mmap((void*)aligned, aligned_len, prot_linux,
                            flags | MAP_FIXED_NOREPLACE, -1, 0);
        if (result == MAP_FAILED) {
            /* Already mapped - just adjust protection (preserves existing data) */
            mprotect((void*)aligned, aligned_len, prot_linux);
        }
        if (address) *address = hint;
        if (size) *size = aligned_len;
        return DK_STATUS_SUCCESS;
    }

    void *result = mmap(NULL, aligned_len, prot_linux, flags, -1, 0);
    if (result == MAP_FAILED) return DK_STATUS_NO_MEMORY;

    if (address) *address = result;
    if (size) *size = aligned_len;
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

/*
 * Thread start wrapper - installs signal handler and calls NTUM function.
 * The NTUM's start_routine uses ms_abi calling convention.
 */
struct dk_thread_ctx {
    void *start_routine;
    void *stack_ptr;
};

static void *dk_thread_wrapper(void *arg) {
    struct dk_thread_ctx *ctx = (struct dk_thread_ctx *)arg;
    void *routine = ctx->start_routine;
    free(ctx);

    /* Install signal handler on this thread */
    extern void ntum_signal_init(void);
    ntum_signal_init();

    fprintf(stderr, "[PAL] Thread started, calling %p\n", routine);

    /* Call the NTUM's thread entry (ms_abi convention) */
    typedef uint64_t (__attribute__((ms_abi)) *thread_fn_t)(void*);
    thread_fn_t fn = (thread_fn_t)routine;
    fn(NULL);
    return NULL;
}

/*
 * DK_ThreadCreate - based on real FUN_00252e60
 *
 * Real behavior: allocates 0xAA0 thread block, links into global list,
 * creates pthread with entry thunk that sets up TEB via ARCH_SET_GS.
 * The NTUM's own thread entry does its TEB/GS setup internally.
 */
DK_API uint64_t DK_ThreadCreate(void *start_routine, void *stack_ptr,
                                 uint64_t flags, DK_HANDLE *thread) {
    (void)flags;
    DK_HANDLE h = alloc_handle();
    if (h == DK_NULL_HANDLE) return DK_STATUS_NO_MEMORY;

    struct dk_thread_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { free_handle(h); return DK_STATUS_NO_MEMORY; }
    ctx->start_routine = start_routine;
    ctx->stack_ptr = stack_ptr;

    g_handles[h].type = HANDLE_THREAD;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 4 * 1024 * 1024);

    int ret = pthread_create(&g_handles[h].thread, &attr,
                             dk_thread_wrapper, ctx);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        free(ctx);
        free_handle(h);
        fprintf(stderr, "[PAL] ThreadCreate(%p) FAILED: %d\n", start_routine, ret);
        return DK_STATUS_NO_MEMORY;
    }

    fprintf(stderr, "[PAL] ThreadCreate(%p, %p) → handle %lu\n",
            start_routine, stack_ptr, (unsigned long)h);

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
    return DK_STATUS_SUCCESS;
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
    /* Create a console handle backed by our stdin/stdout */
    DK_HANDLE h = alloc_handle();
    g_handles[h].type = HANDLE_FD;
    g_handles[h].fd = STDOUT_FILENO;
    if (console) *console = h;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * System Info Query
 *
 * The NTUM calls this (func_id 0x8003000) during boot to learn
 * about the system: processor count, page size, memory, etc.
 * Without it, the NTUM's internal structures remain uninitialized.
 * ================================================================ */

DK_API uint64_t DK_SystemInfoQuery(uint64_t info_class, void *buffer,
                                    uint64_t buffer_size, uint64_t *result_size) {
    (void)info_class;
    if (buffer && buffer_size >= 48) {
        /* Fill a basic SYSTEM_INFO-like structure */
        memset(buffer, 0, buffer_size > 256 ? 256 : buffer_size);
        uint32_t *info = (uint32_t*)buffer;
        info[0] = 4096;                      /* Page size */
        info[1] = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN); /* Processor count */
        info[2] = 0x8664;                    /* Processor architecture (AMD64) */
        info[3] = 6;                         /* Processor level */
        *(uint64_t*)(info + 4) = 0x10000;    /* Allocation granularity */
        *(uint64_t*)(info + 6) = (uint64_t)sysconf(_SC_PHYS_PAGES) *
                                  (uint64_t)sysconf(_SC_PAGESIZE); /* Total physical memory */
    }
    if (result_size) *result_size = 48;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Process ID
 * ================================================================ */

DK_API uint64_t DK_ProcessGetId(uint64_t *pid) {
    if (pid) *pid = (uint64_t)getpid();
    return DK_STATUS_SUCCESS;
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

    /* Re-arm ALL critical .data globals on EVERY dispatcher call.
     * The NTUM's resolution loop stores results at .data addresses that
     * overlap with our critical globals:
     *   [0x18063f8c0] = boot flag (overwritten by 0x7001000 AbiGetVersion)
     *   [0x18063f8c8] = dispatcher ptr (overwritten by 0x8001001 SystemTimeQuery v1)
     * We must re-arm these after every call to prevent them from being
     * corrupted by the resolution process. */
    *(volatile uint32_t*)NTUM_BOOT_FLAG_ADDR = 1;
    *(volatile uint64_t*)NTUM_ABI_DISPATCHER_ADDR =
        (uint64_t)&DK_AbiDispatcher;
    *(volatile uint32_t*)0x18063f5c0ULL = 2;  /* ABI version = 2 */

    /* Re-arm global TEB pointer if it was cleared */
    if (*(volatile uint64_t*)0x1806092c0ULL == 0) {
        extern uint8_t g_runtime_callback_state[];
        uint64_t teb = *(volatile uint64_t*)(g_runtime_callback_state + 0x20);
        if (teb) *(volatile uint64_t*)0x1806092c0ULL = teb;
    }

    /* Re-arm memory limit. The PE reads [0x180c00820] → ptr → [ptr+0x34].
     * If [ptr+0x34] is 0, VirtualAlloc returns NO_MEMORY for everything. */
    {
        uint64_t params_ptr = *(volatile uint64_t*)0x180c00820ULL;
        if (params_ptr && *(volatile uint32_t*)(params_ptr + 0x34) == 0) {
            *(volatile uint32_t*)(params_ptr + 0x34) = 512;  /* 512 * 6MB = 3GB */
        }
    }

    static int dispatch_count = 0;
    dispatch_count++;
    if (dispatch_count <= 500) {
        fprintf(stderr, "[DK] Call #%d: type=0x%lx size=0x%lx in=%p out=%p\n",
                dispatch_count, (unsigned long)call_type,
                (unsigned long)data_size, in_buf, out_buf);
    }

    /* Debug: check critical values */
    if (dispatch_count <= 100 || dispatch_count % 100 == 0) {
        fprintf(stderr, "[DK] #%d boot_flag=%u disp=0x%lx abi_ver=%u type=0x%lx\n",
                dispatch_count,
                *(volatile uint32_t*)NTUM_BOOT_FLAG_ADDR,
                (unsigned long)*(volatile uint64_t*)NTUM_ABI_DISPATCHER_ADDR,
                *(volatile uint32_t*)0x18063f5c0ULL,
                (unsigned long)call_type);
    }

    /* Handle ALL ABI function resolution variants:
     * 0x7002002 = GetFunction_v2 (first pass, version 0)
     * 0x7001002 = GetFunction version 2 (second pass, called by second resolver)
     * The second resolver at PE RVA 0x213ea4 calls with type=0x7001002
     * and stores the output buffer value at critical .data addresses. */
    if (call_type == ABI_GET_FUNCTION_V2 || call_type == 0x7001002) {
        uint32_t *in = (uint32_t*)in_buf;
        uint32_t func_id = in ? in[0] : 0;
        uint32_t version = in ? in[1] : 0;

        /* The second resolution pass uses version 1+ (func_ids ending in 001+).
         * These store results at critical .data addresses (boot flag, dispatcher ptr).
         * Normalize to the base func_id (version 0) to get the same function. */
        uint32_t base_func_id = func_id & 0xFFFFF000;

        void *func = (void*)&DK_GenericStub;
        int is_stub = 1;  /* Track if we're returning a real impl or generic stub */

        /* For version 0 (first pass): use base_func_id for the switch.
         * For version 1+ (second pass): use base_func_id BUT skip feature
         * flag returns (0xf/0x10 categories) - return real function instead.
         * The second resolver stores the return as a CALLABLE function pointer. */
        int original_version = func_id & 0xFFF;
        func_id = base_func_id;

        switch (func_id) {
        /* Stream I/O (category 0x01) */
        case 0x1001000: func = (void*)&DK_StreamOpen; is_stub=0; break;
        case 0x1002000: func = (void*)&DK_StreamRead; is_stub=0; break;
        case 0x1003000: func = (void*)&DK_StreamWrite; is_stub=0; break;
        case 0x1004000: func = (void*)&DK_StreamFlush; is_stub=0; break;
        case 0x1005000: func = (void*)&DK_ObjectClose; is_stub=0; break;
        case 0x1006000: func = (void*)&DK_StreamMap; is_stub=0; break;
        case 0x1007000: func = (void*)&DK_StreamMapPeBinary; is_stub=0; break;
        case 0x1008000: func = (void*)&DK_StreamUnmap; is_stub=0; break;
        case 0x1009000: func = (void*)&DK_StreamSetLength; is_stub=0; break;
        case 0x100a000: func = (void*)&DK_StreamControl; is_stub=0; break;
        case 0x100b000: func = (void*)&DK_StreamAttributesQuery; is_stub=0; break;
        case 0x100c000: func = (void*)&DK_StreamAttributesQueryByHandle; is_stub=0; break;
        case 0x100d000: func = (void*)&DK_StreamEnumerateChildren; is_stub=0; break;
        case 0x100e000: func = (void*)&DK_StreamDelete; is_stub=0; break;
        case 0x100f000: func = (void*)&DK_StreamRename; is_stub=0; break;
        case 0x1010000: func = (void*)&DK_StreamChangesRegister; is_stub=0; break;
        case 0x1011000: func = (void*)&DK_StreamChangesPoll; is_stub=0; break;
        case 0x1012000: func = (void*)&DK_StreamRangeLock; is_stub=0; break;
        case 0x1013000: func = (void*)&DK_StreamRangeUnlock; is_stub=0; break;
        case 0x1014000: func = (void*)&DK_StreamGetEvent; is_stub=0; break;
        case 0x1015000: func = (void*)&DK_StreamEventSelect; is_stub=0; break;

        /* Memory (category 0x02) */
        case 0x2001000: func = (void*)&DK_VirtualMemoryAllocate; is_stub=0; break;
        case 0x2002000: func = (void*)&DK_VirtualMemoryFree; is_stub=0; break;
        case 0x2004000: func = (void*)&DK_VirtualMemoryProtect; is_stub=0; break;

        /* Threading (category 0x04) */
        case 0x4001000: func = (void*)&DK_ThreadCreate; is_stub=0; break;
        case 0x4002000: func = (void*)&DK_ThreadExit; is_stub=0; break;
        case 0x4003000: func = (void*)&DK_ThreadYieldExecution; is_stub=0; break;

        /* Synchronization (category 0x05) */
        case 0x5001000: func = (void*)&DK_NotificationEventCreate; is_stub=0; break;
        case 0x5002000: func = (void*)&DK_SynchronizationEventCreate; is_stub=0; break;
        case 0x5003000: func = (void*)&DK_ObjectsWaitAny; is_stub=0; break;

        /* Console (category 0x06) */
        case 0x6001000: func = (void*)&DK_ConsoleCreate; is_stub=0; break;

        /* ABI (category 0x07) - these store version/flag values, not function ptrs.
         * 0x7001000 (AbiGetVersion): stored at boot flag [0x63f8c0], must be 1
         * 0x7002000 (AbiGetFunction): stored at [0x63f5c0], must be 2 (ABI v2)
         *   The second resolver at RVA 0x213ea4 checks [0x63f5c0] == 2
         *   and returns 0xC0000002 if not equal. */
        case 0x7001000:
            func = (original_version == 0) ? (void*)1 : (void*)&DK_GenericStub;
            is_stub = (original_version != 0); break;
        case 0x7002000:
            func = (original_version == 0) ? (void*)2 : (void*)&DK_AbiGetFunction;
            is_stub=0; break;

        /* System (category 0x08) */
        case 0x8001000: func = (void*)&DK_SystemTimeQuery; is_stub=0; break;
        case 0x8002000: func = (void*)&DK_RandomBitsRead; is_stub=0; break;
        case 0x8003000: func = (void*)&DK_SystemInfoQuery; is_stub=0; break;

        /* Process (category 0x09) */
        case 0x9001000: func = (void*)&DK_ProcessCreate; is_stub=0; break;
        case 0x9002000: func = (void*)&DK_ProcessExit; is_stub=0; break;
        case 0x9003000: func = (void*)&DK_ProcessTerminate; is_stub=0; break;
        case 0x9004000: func = (void*)&DK_ProcessGetExitCode; is_stub=0; break;
        case 0x9005000: func = (void*)&DK_ProcessGetId; is_stub=0; break;

        /* Exception (category 0x0A) */
        case 0xa001000: func = (void*)&DK_ExceptionRecordFree; is_stub=0; break;

        /* Objects (category 0x0B) */
        case 0xb001000: func = (void*)&DK_ObjectClose; is_stub=0; break;
        case 0xb002000: func = (void*)&DK_ObjectReference; is_stub=0; break;
        case 0xb003000: func = (void*)&DK_ObjectReference; is_stub=0; break; /* Dereference = same as Reference for now */

        /* Cache/Events (category 0x0C) */
        case 0xc001000: func = (void*)&DK_InstructionCacheFlush; is_stub=0; break;
        case 0xc002000: func = (void*)&DK_EventSet; is_stub=0; break;
        case 0xc003000: func = (void*)&DK_EventClear; is_stub=0; break;
        case 0xc004000: func = (void*)&DK_EventPeek; is_stub=0; break;

        /* Extended threading (category 0x0E) */
        case 0xe001000: func = (void*)&DK_ThreadInterrupt; is_stub=0; break;
        case 0xe002000: func = (void*)&DK_ThreadSetAffinity; is_stub=0; break;
        case 0xe003000: func = (void*)&DK_ThreadSetAffinity; is_stub=0; break; /* AssertAffinity */

        /* Stream extended (category 0x0F):
         * First pass (version 0, func_id ends in 000) = feature flags.
         * The PE checks if result == 1 to determine support.
         * Second pass (version 1+, func_id ends in 001+) = actual function pointers.
         * Discovered from PE disassembly:
         *   RVA 0x2133bf: 0xf005000 → [0x63f4f0] (flag, checked == 1)
         *   RVA 0x213ba2: 0xf005001 → [0x63f4f8] (func ptr, called via jmp *rax)
         */
        case 0xf001000: case 0xf002000: case 0xf003000:
        case 0xf004000: case 0xf005000: case 0xf006000:
        case 0xf007000:
            func = (original_version == 0) ? (void*)1 : (void*)&DK_GenericStub;
            is_stub = (original_version != 0); break;

        /* Async (category 0x10) */
        case 0x10001000: case 0x10002000:
            func = (original_version == 0) ? (void*)1 : (void*)&DK_GenericStub;
            is_stub = (original_version != 0); break;

        /* Memory v2 (category 0x12) */
        case 0x12001000: func = (void*)&DK_VirtualMemoryAllocate; is_stub=0; break;
        case 0x12002000: func = (void*)&DK_VirtualMemoryFree; is_stub=0; break;
        case 0x12003000: func = (void*)&DK_VirtualMemoryProtect; is_stub=0; break;

        /* Random (category 0x13) */
        case 0x13001000: func = (void*)&DK_RandomBitsRead; is_stub=0; break;

        default: break;
        }

        /* Log stub vs real resolution */
        if (dispatch_count <= 100) {
            fprintf(stderr, "[DK] Resolve 0x%x v%u → %p %s\n",
                    func_id, version, func, is_stub ? "(STUB)" : "(impl)");
        }

        /* Write function pointer to output via double-deref.
         *
         * Confirmed from debug: out_buf=0x18063ae70, *out_buf=0x18063aeb0.
         * The NTUM's call site at RVA 0x213e50:
         *   out_buf points to a .data slot containing a pointer to the
         *   result area. We must write to **out_buf, NOT *out_buf.
         *   Writing to *out_buf would destroy the NTUM's internal pointer.
         */
        if (out_buf) {
            uint64_t *result_ptr = *(uint64_t**)out_buf;
            if (result_ptr) {
                *result_ptr = (uint64_t)func;
            }
        }

        /* Monitor 0x18063ae88 for when the error appears */
        {
            uint64_t err_val = *(volatile uint64_t*)0x18063ae88ULL;
            if (err_val != 0 && dispatch_count <= 100) {
                fprintf(stderr, "[DK] !!! [0x18063ae88]=0x%lx after resolving funcid 0x%x (#%d)\n",
                        (unsigned long)err_val, func_id, dispatch_count);
            }
        }

        /* After call #84, dump PE code around config call sites */
        if (dispatch_count == 84) {
            fprintf(stderr, "[DK] === PE code at config call return addresses ===\n");
            /* The 'out' param in config calls is the return address.
             * Dump bytes BEFORE each return addr to see the call instruction. */
            uint64_t sites[] = {0x180204818ULL, 0x180204850ULL, 0x1802048e2ULL, 0x1802049d5ULL};
            const char *names[] = {"#85", "#86", "#87", "#88"};
            for (int a = 0; a < 4; a++) {
                volatile uint8_t *p = (uint8_t*)(sites[a] - 32);
                fprintf(stderr, "[DK] Call %s (ret=0x%lx) [-32]:\n  ", names[a], (unsigned long)sites[a]);
                for (int j = 0; j < 48; j++) {
                    fprintf(stderr, "%02x ", p[j]);
                    if (j == 15 || j == 31) fprintf(stderr, "\n  ");
                }
                fprintf(stderr, "\n");
            }
            /* Dump dispatch table */
            fprintf(stderr, "[DK] Dispatch table 0x18063ae50-0x18063af50:\n");
            for (uint64_t addr = 0x18063ae50ULL; addr < 0x18063af50ULL; addr += 16) {
                volatile uint8_t *p = (uint8_t*)addr;
                fprintf(stderr, "  %lx: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                        (unsigned long)addr,
                        p[0],p[1],p[2],p[3], p[4],p[5],p[6],p[7],
                        p[8],p[9],p[10],p[11], p[12],p[13],p[14],p[15]);
            }
        }
        return 0;  /* STATUS_SUCCESS */
    }

    if (call_type == ABI_GET_VERSION_V2) {
        /* Return ABI version 2. Must return SUCCESS, not NOT_IMPLEMENTED. */
        if (out_buf)
            *(uint32_t*)out_buf = 2;
        return DK_STATUS_SUCCESS;
    }

    /* Config calls: type is a .data address pointing to config structure.
     * These are NOT indirect function calls (the .data contains line numbers
     * and config data, not function pointers). Just return SUCCESS. */
    static int post_count = 0;
    post_count++;
    if (post_count <= 50) {
        fprintf(stderr, "[DK] PostRes: type=0x%lx size=0x%lx in=%p\n",
                (unsigned long)call_type, (unsigned long)data_size, in_buf);
    }
    return DK_STATUS_SUCCESS;
}

/*
 * Pool allocator function - called from the NTUM kernel pool via vtable.
 * Different calling convention from DK_VirtualMemoryAllocate:
 *   rcx = pool object (this pointer)
 *   rdx = size to allocate
 *   r8  = flags/type
 *   r9  = tag or additional params
 * Returns allocated pointer in rax.
 */
DK_API __attribute__((force_align_arg_pointer))
uint64_t pool_allocator_fn(void *pool_obj, uint64_t alloc_size,
                            uint64_t flags, void *param4,
                            uint64_t param5, void *param6) {
    (void)pool_obj; (void)flags; (void)param4; (void)param5; (void)param6;

    if (alloc_size == 0) alloc_size = 0x1000;
    size_t aligned = (alloc_size + 0xFFF) & ~0xFFFULL;

    /* Allocate in LibOS address range. The NTUM expects all kernel
     * allocations to be within 0x10000 - 0x400000000000.
     * Use the kernel heap at 0x300000000 for pool allocations. */
    size_t total = aligned < 0x1000 ? 0x1000 : aligned;
    /* Allocate within the kernel heap (0x300000000, already MAP_NORESERVE).
     * Use MAP_FIXED to commit pages within the reserved range. */
    static uint64_t pool_heap_next = LIBOS_KERNEL_HEAP + 0x10000000ULL; /* Start at +256MB */
    uint64_t alloc_addr = __atomic_fetch_add(&pool_heap_next, total, __ATOMIC_SEQ_CST);
    void *result = mmap((void*)alloc_addr, total, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (result == MAP_FAILED) return 0;

    /* Pre-fill a stack descriptor at offset +0x10 of the allocation.
     * The stack descriptor MUST be in LibOS space.
     * Use the boot stack descriptor from our LibOS structs. */
    uint8_t *sd = (uint8_t*)(BOOT_STRUCTS_ADDR + 0x16000);
    if (*(uint64_t*)(sd + 0x30) == 0)
        *(uint64_t*)(sd + 0x30) = NTUM_STACK_TOP;
    *(uint64_t*)((uint8_t*)result + 0x10) = (uint64_t)sd;

    static int pool_count = 0;
    pool_count++;
    if (pool_count <= 50) {
        fprintf(stderr, "[POOL] #%d alloc(%lu) → %p\n",
                pool_count, (unsigned long)alloc_size, result);
    }
    return (uint64_t)result;
}

/* Generic PAL stub - returns success for unimplemented functions */
DK_API __attribute__((force_align_arg_pointer))
uint64_t DK_GenericStub(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    static int stub_count = 0;
    stub_count++;
    if (stub_count <= 100) {
        fprintf(stderr, "[STUB] #%d: a=0x%lx b=0x%lx c=0x%lx d=0x%lx RET=0x%lx\n",
                stub_count, (unsigned long)a, (unsigned long)b,
                (unsigned long)c, (unsigned long)d,
                (unsigned long)__builtin_return_address(0));
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
