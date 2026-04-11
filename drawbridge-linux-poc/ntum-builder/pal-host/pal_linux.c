/*
 * PAL Linux Implementation
 *
 * Maps the ~30 PAL operations to Linux syscalls.
 * This is the equivalent of what sqlservr (the ELF host) does.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/random.h>
#include <sys/eventfd.h>

#include "../include/ntum_pal.h"

/* ---- Memory Management ---- */

static void *pal_linux_mem_alloc(void *addr, size_t size, int prot) {
    int linux_prot = PROT_NONE;
    if (prot & PAL_PROT_READ)  linux_prot |= PROT_READ;
    if (prot & PAL_PROT_WRITE) linux_prot |= PROT_WRITE;
    if (prot & PAL_PROT_EXEC)  linux_prot |= PROT_EXEC;

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (addr) flags |= MAP_FIXED_NOREPLACE;

    void *result = mmap(addr, size, linux_prot, flags, -1, 0);
    if (result == MAP_FAILED) return NULL;
    return result;
}

static int pal_linux_mem_free(void *addr, size_t size) {
    return munmap(addr, size) == 0 ? PAL_SUCCESS : PAL_ERROR;
}

static int pal_linux_mem_protect(void *addr, size_t size, int prot) {
    int linux_prot = PROT_NONE;
    if (prot & PAL_PROT_READ)  linux_prot |= PROT_READ;
    if (prot & PAL_PROT_WRITE) linux_prot |= PROT_WRITE;
    if (prot & PAL_PROT_EXEC)  linux_prot |= PROT_EXEC;
    return mprotect(addr, size, linux_prot) == 0 ? PAL_SUCCESS : PAL_ERROR;
}

/* ---- I/O Streams ---- */

static PAL_HANDLE pal_linux_stream_open(const char *uri, int mode) {
    int flags = 0;
    if ((mode & PAL_STREAM_READ) && (mode & PAL_STREAM_WRITE))
        flags = O_RDWR;
    else if (mode & PAL_STREAM_WRITE)
        flags = O_WRONLY;
    else
        flags = O_RDONLY;

    if (mode & PAL_STREAM_CREATE) flags |= O_CREAT;
    if (mode & PAL_STREAM_APPEND) flags |= O_APPEND;

    /* Strip file:// prefix if present */
    const char *path = uri;
    if (strncmp(uri, "file://", 7) == 0) path = uri + 7;

    int fd = open(path, flags, 0644);
    if (fd < 0) return PAL_INVALID_HANDLE;
    return (PAL_HANDLE)fd;
}

static int64_t pal_linux_stream_read(PAL_HANDLE stream, void *buf, size_t count) {
    return read((int)stream, buf, count);
}

static int64_t pal_linux_stream_write(PAL_HANDLE stream, const void *buf, size_t count) {
    return write((int)stream, buf, count);
}

static int pal_linux_stream_close(PAL_HANDLE stream) {
    return close((int)stream) == 0 ? PAL_SUCCESS : PAL_ERROR;
}

static int pal_linux_stream_flush(PAL_HANDLE stream) {
    return fsync((int)stream) == 0 ? PAL_SUCCESS : PAL_ERROR;
}

static int64_t pal_linux_stream_size(PAL_HANDLE stream) {
    struct stat st;
    if (fstat((int)stream, &st) < 0) return -1;
    return st.st_size;
}

static void *pal_linux_stream_map(PAL_HANDLE stream, size_t offset,
                                   size_t size, int prot) {
    int linux_prot = PROT_NONE;
    if (prot & PAL_PROT_READ)  linux_prot |= PROT_READ;
    if (prot & PAL_PROT_WRITE) linux_prot |= PROT_WRITE;
    if (prot & PAL_PROT_EXEC)  linux_prot |= PROT_EXEC;

    void *result = mmap(NULL, size, linux_prot, MAP_PRIVATE, (int)stream, offset);
    if (result == MAP_FAILED) return NULL;
    return result;
}

/* ---- Threading ---- */

typedef struct {
    void (*fn)(void*);
    void *arg;
} thread_wrapper_t;

static void *thread_trampoline(void *arg) {
    thread_wrapper_t *tw = (thread_wrapper_t*)arg;
    tw->fn(tw->arg);
    free(tw);
    return NULL;
}

static PAL_HANDLE pal_linux_thread_create(void (*fn)(void*), void *arg,
                                           size_t stack_size) {
    pthread_t *t = malloc(sizeof(pthread_t));
    if (!t) return PAL_INVALID_HANDLE;

    thread_wrapper_t *tw = malloc(sizeof(thread_wrapper_t));
    if (!tw) { free(t); return PAL_INVALID_HANDLE; }
    tw->fn = fn;
    tw->arg = arg;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (stack_size > 0) pthread_attr_setstacksize(&attr, stack_size);

    if (pthread_create(t, &attr, thread_trampoline, tw) != 0) {
        free(tw);
        free(t);
        pthread_attr_destroy(&attr);
        return PAL_INVALID_HANDLE;
    }
    pthread_attr_destroy(&attr);
    return (PAL_HANDLE)t;
}

static void pal_linux_thread_exit(int code) {
    pthread_exit((void*)(intptr_t)code);
}

static int pal_linux_thread_join(PAL_HANDLE thread) {
    pthread_t *t = (pthread_t*)thread;
    int result = pthread_join(*t, NULL);
    free(t);
    return result == 0 ? PAL_SUCCESS : PAL_ERROR;
}

static uint64_t pal_linux_thread_id(void) {
    return (uint64_t)pthread_self();
}

/* ---- Synchronization ---- */

static PAL_HANDLE pal_linux_event_create(int initial_state) {
    int efd = eventfd(initial_state ? 1 : 0, EFD_SEMAPHORE);
    if (efd < 0) return PAL_INVALID_HANDLE;
    return (PAL_HANDLE)efd;
}

static int pal_linux_event_set(PAL_HANDLE event) {
    uint64_t val = 1;
    return write((int)event, &val, sizeof(val)) == sizeof(val) ? PAL_SUCCESS : PAL_ERROR;
}

static int pal_linux_event_reset(PAL_HANDLE event) {
    uint64_t val;
    ssize_t ret = read((int)event, &val, sizeof(val));  /* Drain */
    (void)ret;
    return PAL_SUCCESS;
}

static int pal_linux_event_wait(PAL_HANDLE event, int timeout_ms) {
    if (timeout_ms < 0) {
        uint64_t val;
        return read((int)event, &val, sizeof(val)) == sizeof(val) ? PAL_SUCCESS : PAL_ERROR;
    }
    /* TODO: use poll() for timeout */
    uint64_t val;
    return read((int)event, &val, sizeof(val)) == sizeof(val) ? PAL_SUCCESS : PAL_ERROR;
}

static PAL_HANDLE pal_linux_mutex_create(void) {
    pthread_mutex_t *m = malloc(sizeof(pthread_mutex_t));
    if (!m) return PAL_INVALID_HANDLE;
    pthread_mutex_init(m, NULL);
    return (PAL_HANDLE)m;
}

static int pal_linux_mutex_lock(PAL_HANDLE mutex) {
    return pthread_mutex_lock((pthread_mutex_t*)mutex) == 0 ? PAL_SUCCESS : PAL_ERROR;
}

static int pal_linux_mutex_unlock(PAL_HANDLE mutex) {
    return pthread_mutex_unlock((pthread_mutex_t*)mutex) == 0 ? PAL_SUCCESS : PAL_ERROR;
}

static void pal_linux_mutex_destroy(PAL_HANDLE mutex) {
    pthread_mutex_destroy((pthread_mutex_t*)mutex);
    free((void*)mutex);
}

/* ---- Process ---- */

static void pal_linux_process_exit(int code) {
    _exit(code);
}

static uint64_t pal_linux_process_id(void) {
    return (uint64_t)getpid();
}

/* ---- Time ---- */

static uint64_t pal_linux_time_query(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

static uint64_t pal_linux_time_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

static void pal_linux_time_sleep(uint64_t us) {
    usleep(us);
}

/* ---- System Info ---- */

static int pal_linux_cpu_count(void) {
    return get_nprocs();
}

static uint64_t pal_linux_memory_total(void) {
    struct sysinfo si;
    sysinfo(&si);
    return (uint64_t)si.totalram * si.mem_unit;
}

/* ---- Entropy ---- */

static int pal_linux_random_read(void *buf, size_t count) {
    ssize_t ret = getrandom(buf, count, 0);
    return ret == (ssize_t)count ? PAL_SUCCESS : PAL_ERROR;
}

/* ---- Console ---- */

static int64_t pal_linux_console_write(const void *buf, size_t count) {
    return write(STDOUT_FILENO, buf, count);
}

static int64_t pal_linux_console_error(const void *buf, size_t count) {
    return write(STDERR_FILENO, buf, count);
}

/* ---- Debug ---- */

static void pal_linux_debug_print(const char *msg) {
    fprintf(stderr, "[PAL] %s\n", msg);
}

/* ---- PAL Table Construction ---- */

PAL_TABLE *pal_linux_create(void) {
    PAL_TABLE *pal = calloc(1, sizeof(PAL_TABLE));
    if (!pal) return NULL;

    pal->version = 1;
    pal->num_entries = sizeof(PAL_TABLE) / sizeof(void*);

    /* Memory */
    pal->mem_alloc = pal_linux_mem_alloc;
    pal->mem_free = pal_linux_mem_free;
    pal->mem_protect = pal_linux_mem_protect;

    /* I/O */
    pal->stream_open = pal_linux_stream_open;
    pal->stream_read = pal_linux_stream_read;
    pal->stream_write = pal_linux_stream_write;
    pal->stream_close = pal_linux_stream_close;
    pal->stream_flush = pal_linux_stream_flush;
    pal->stream_size = pal_linux_stream_size;
    pal->stream_map = pal_linux_stream_map;

    /* Threading */
    pal->thread_create = pal_linux_thread_create;
    pal->thread_exit = pal_linux_thread_exit;
    pal->thread_join = pal_linux_thread_join;
    pal->thread_id = pal_linux_thread_id;

    /* Sync */
    pal->event_create = pal_linux_event_create;
    pal->event_set = pal_linux_event_set;
    pal->event_reset = pal_linux_event_reset;
    pal->event_wait = pal_linux_event_wait;
    pal->mutex_create = pal_linux_mutex_create;
    pal->mutex_lock = pal_linux_mutex_lock;
    pal->mutex_unlock = pal_linux_mutex_unlock;
    pal->mutex_destroy = pal_linux_mutex_destroy;

    /* Process */
    pal->process_exit = pal_linux_process_exit;
    pal->process_id = pal_linux_process_id;

    /* Time */
    pal->time_query = pal_linux_time_query;
    pal->time_monotonic = pal_linux_time_monotonic;
    pal->time_sleep = pal_linux_time_sleep;

    /* System */
    pal->cpu_count = pal_linux_cpu_count;
    pal->memory_total = pal_linux_memory_total;

    /* Entropy */
    pal->random_read = pal_linux_random_read;

    /* Console */
    pal->console_write = pal_linux_console_write;
    pal->console_error = pal_linux_console_error;

    /* PE loading - set by host */
    pal->load_pe = NULL;
    pal->resolve_import = NULL;

    /* Debug */
    pal->debug_print = pal_linux_debug_print;

    return pal;
}
