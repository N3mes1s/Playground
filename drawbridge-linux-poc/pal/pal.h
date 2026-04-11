#ifndef PAL_H
#define PAL_H

#include <stdint.h>
#include <stddef.h>

/*
 * Platform Abstraction Layer (PAL)
 *
 * This is the narrow interface between the library OS and the host.
 * Inspired by Microsoft's Drawbridge, which uses ~45 operations.
 *
 * On Linux, these map to standard POSIX/Linux syscalls.
 * On a different host, only this file needs to be reimplemented.
 */

/* ---- Handle types ---- */
typedef void *pal_handle_t;

#define PAL_INVALID_HANDLE  ((pal_handle_t)(intptr_t)-1)

/* ---- Memory management ---- */

/* Memory protection flags (matching Windows PAGE_* constants concept) */
#define PAL_MEM_READ        0x01
#define PAL_MEM_WRITE       0x02
#define PAL_MEM_EXECUTE     0x04

/*
 * Allocate virtual memory.
 * If addr is NULL, the system chooses the address.
 * Returns pointer to allocated memory, or NULL on failure.
 */
void *pal_mem_alloc(void *addr, size_t size, int prot);

/*
 * Free virtual memory previously allocated with pal_mem_alloc.
 */
int pal_mem_free(void *addr, size_t size);

/*
 * Change memory protection flags.
 */
int pal_mem_protect(void *addr, size_t size, int prot);

/* ---- Threading ---- */

typedef void (*pal_thread_fn)(void *arg);

/*
 * Create a new thread.
 * Returns a handle to the thread, or PAL_INVALID_HANDLE on failure.
 */
pal_handle_t pal_thread_create(pal_thread_fn fn, void *arg);

/*
 * Exit the current thread.
 */
void pal_thread_exit(int exit_code) __attribute__((noreturn));

/*
 * Wait for a thread to finish.
 */
int pal_thread_join(pal_handle_t thread);

/*
 * Get the current thread ID.
 */
uint64_t pal_thread_id(void);

/* ---- I/O Streams ---- */

/* Stream open modes */
#define PAL_STREAM_READ     0x01
#define PAL_STREAM_WRITE    0x02
#define PAL_STREAM_CREATE   0x04
#define PAL_STREAM_APPEND   0x08
#define PAL_STREAM_TRUNCATE 0x10

/*
 * Open an I/O stream (file, pipe, etc).
 * uri format: "file:<path>" or "pipe:<name>" or "console:out"/"console:err"
 */
pal_handle_t pal_stream_open(const char *uri, int mode);

/*
 * Read from a stream.
 * Returns number of bytes read, or -1 on error.
 */
int64_t pal_stream_read(pal_handle_t stream, void *buf, size_t count);

/*
 * Write to a stream.
 * Returns number of bytes written, or -1 on error.
 */
int64_t pal_stream_write(pal_handle_t stream, const void *buf, size_t count);

/*
 * Close a stream.
 */
int pal_stream_close(pal_handle_t stream);

/*
 * Flush a stream.
 */
int pal_stream_flush(pal_handle_t stream);

/*
 * Get the size of a stream (for files).
 * Returns size, or -1 if not applicable.
 */
int64_t pal_stream_size(pal_handle_t stream);

/* ---- Synchronization ---- */

/*
 * Create a mutex. Returns handle or PAL_INVALID_HANDLE.
 */
pal_handle_t pal_mutex_create(void);

/*
 * Lock a mutex.
 */
int pal_mutex_lock(pal_handle_t mutex);

/*
 * Unlock a mutex.
 */
int pal_mutex_unlock(pal_handle_t mutex);

/*
 * Destroy a mutex.
 */
void pal_mutex_destroy(pal_handle_t mutex);

/*
 * Create an event (manual-reset signaling object).
 */
pal_handle_t pal_event_create(int initial_state);

/*
 * Signal an event.
 */
int pal_event_set(pal_handle_t event);

/*
 * Reset (unsignal) an event.
 */
int pal_event_reset(pal_handle_t event);

/*
 * Wait for an event to be signaled.
 * timeout_ms: -1 for infinite wait.
 * Returns 0 on success, -1 on timeout.
 */
int pal_event_wait(pal_handle_t event, int timeout_ms);

/* ---- Process management ---- */

/*
 * Exit the current process.
 */
void pal_process_exit(int exit_code) __attribute__((noreturn));

/*
 * Get the current process ID.
 */
uint64_t pal_process_id(void);

/* ---- Time ---- */

/*
 * Get current system time in microseconds since epoch.
 */
uint64_t pal_time_query(void);

/*
 * Get monotonic time in microseconds (for performance measurement).
 */
uint64_t pal_time_monotonic(void);

/*
 * Sleep for the specified number of microseconds.
 */
void pal_sleep(uint64_t microseconds);

/* ---- System info ---- */

/*
 * Get the number of available CPUs.
 */
int pal_cpu_count(void);

/*
 * Get total physical memory in bytes.
 */
uint64_t pal_memory_total(void);

/* ---- Cryptography / Entropy ---- */

/*
 * Fill buffer with cryptographically secure random bytes.
 */
int pal_random_read(void *buf, size_t count);

/* ---- Console ---- */

/*
 * Write to the console (stdout).
 */
int64_t pal_console_write(const void *buf, size_t count);

/*
 * Write to the error console (stderr).
 */
int64_t pal_console_error(const void *buf, size_t count);

/* ---- PAL initialization ---- */

/*
 * Initialize the PAL subsystem.
 * Must be called before any other PAL function.
 */
int pal_init(void);

/*
 * Shutdown the PAL subsystem.
 */
void pal_shutdown(void);

#endif /* PAL_H */
