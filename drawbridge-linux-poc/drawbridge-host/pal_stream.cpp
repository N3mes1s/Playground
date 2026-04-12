/*
 * pal_stream.cpp — Component C5: Stream I/O (file) bring-up.
 *
 * This translation unit holds strong, final definitions of the 21
 * DK_Stream* entry points exposed to the NTUM through the DK PAL.
 * Linked BEFORE dk_pal.cpp so the loader picks these (the Makefile
 * uses -Wl,--allow-multiple-definition and link order wins). The
 * legacy implementations in dk_pal.cpp remain as a safety net for
 * any caller that resolves them through the older stub table.
 *
 * Scope for this drop (minimal): real impls of the two critical
 * entries that "hello from drawbridge" needs on the write path —
 *   DK_StreamWrite  (stdout/stderr passthrough)
 *   DK_StreamOpen   (file: scheme + std{out,err,in} scheme URIs)
 * All other DK_Stream* entries fail loud so that any accidental
 * dependency surfaces immediately instead of corrupting guest state.
 *
 * Decompiled references (see analysis/sqlservr_FULL.c):
 *   FUN_00353d80 (pread)     line 318931
 *   FUN_00353d90 (pwrite)    line 318938
 *   FUN_003538e0 (ftruncate) line 318720
 */

#include "pal_stream.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

/* Local, small handle pool for file: streams. Handles 1/2 are reserved
 * for the host's stdout/stderr (matching Linux's POSIX fd numbering so
 * DK_StreamWrite can branch on handle == 1 || handle == 2 directly).
 * Allocated handles start above STDERR_FILENO. */
#define PAL_STREAM_POOL_BASE 16u
#define PAL_STREAM_POOL_MAX  256u

static pal_stream_handle_t g_pool[PAL_STREAM_POOL_MAX];

static void pal_stream_fail(const char *fn) {
    fprintf(stderr, "[pal_stream] FAIL-LOUD: %s not implemented\n", fn);
}

pal_stream_handle_t *pal_stream_from_handle(DK_HANDLE h) {
    if (h < PAL_STREAM_POOL_BASE) return 0;
    uint64_t idx = h - PAL_STREAM_POOL_BASE;
    if (idx >= PAL_STREAM_POOL_MAX) return 0;
    if (g_pool[idx].fd < 0) return 0;
    return &g_pool[idx];
}

uint64_t pal_stream_errno_to_status(int err) {
    switch (err) {
        case 0:       return DK_STATUS_SUCCESS;
        case ENOMEM:  return DK_STATUS_NO_MEMORY;
        case EINVAL:  return DK_STATUS_INVALID_PARAM;
        default:      return DK_STATUS_INVALID_PARAM;
    }
}

DK_HANDLE pal_stream_wrap_fd(int fd, int owns_fd) {
    /* stdout/stderr/stdin are passed through as their raw fd so
     * DK_StreamWrite's fast path ("handle is 1 or 2") works without
     * a pool lookup. Other descriptors go into the pool. */
    if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
        return (DK_HANDLE)fd;
    }
    for (uint64_t i = 0; i < PAL_STREAM_POOL_MAX; i++) {
        if (g_pool[i].fd == 0 /* never initialised */ ||
            g_pool[i].fd == -1 /* freed */) {
            memset(&g_pool[i], 0, sizeof(g_pool[i]));
            g_pool[i].fd = fd;
            g_pool[i].owns_fd = owns_fd;
            return (DK_HANDLE)(PAL_STREAM_POOL_BASE + i);
        }
    }
    return DK_NULL_HANDLE;
}

/* Decode a UTF-16LE URI (uri_len is character count) into ASCII. */
static void pal_stream_decode_uri(const void *uri, uint64_t uri_len,
                                   char *out, size_t out_sz) {
    const uint16_t *w = (const uint16_t *)uri;
    size_t n = (uri_len < out_sz - 1) ? (size_t)uri_len : out_sz - 1;
    size_t i;
    for (i = 0; i < n && w[i]; i++) {
        out[i] = (char)(w[i] & 0xFF);
    }
    out[i] = '\0';
}

extern "C" {

/* ================================================================
 * DK_StreamWrite — real override.
 *
 * Contract: if the handle is host stdout (1) or stderr (2), pipe
 * through write(2). Offset is ignored for character devices (it has
 * no meaning on a TTY/pipe, matches LinuxFile's behaviour when its
 * m_isSeekable flag is clear, see decomp FUN_00353d90 + caller).
 * ================================================================ */
DK_API uint64_t DK_StreamWrite(DK_HANDLE stream, uint64_t offset,
                                const void *buffer, uint64_t bytes_to_write,
                                uint64_t *bytes_written_out) {
    (void)offset;
    if (stream == (DK_HANDLE)STDOUT_FILENO ||
        stream == (DK_HANDLE)STDERR_FILENO) {
        ssize_t n = write((int)stream, buffer, (size_t)bytes_to_write);
        if (n < 0) {
            if (bytes_written_out) *bytes_written_out = 0;
            return pal_stream_errno_to_status(errno);
        }
        if (bytes_written_out) *bytes_written_out = (uint64_t)n;
        return DK_STATUS_SUCCESS;
    }

    pal_stream_handle_t *s = pal_stream_from_handle(stream);
    if (!s) {
        fprintf(stderr,
                "[pal_stream] FAIL-LOUD: DK_StreamWrite on non-console "
                "handle 0x%lx (pool unpopulated)\n",
                (unsigned long)stream);
        if (bytes_written_out) *bytes_written_out = 0;
        return DK_STATUS_NOT_IMPLEMENTED;
    }

    ssize_t n = pwrite(s->fd, buffer, (size_t)bytes_to_write, (off_t)offset);
    if (n < 0) {
        if (bytes_written_out) *bytes_written_out = 0;
        return pal_stream_errno_to_status(errno);
    }
    if (bytes_written_out) *bytes_written_out = (uint64_t)n;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * DK_StreamOpen — real override for the "file:" scheme.
 *
 * URIs arrive as UTF-16LE from the NTUM. We handle:
 *   stdout: / stderr: / stdin:  → wrap raw fd
 *   file:...                    → open via POSIX
 * Anything else fails loud.
 * ================================================================ */
DK_API uint64_t DK_StreamOpen(const void *uri, uint64_t uri_len,
                               uint64_t access, uint64_t share_mode,
                               uint64_t create_disp, uint64_t flags,
                               DK_HANDLE *out_handle) {
    (void)share_mode; (void)flags;
    if (!out_handle || !uri) return DK_STATUS_INVALID_PARAM;

    char path[512];
    pal_stream_decode_uri(uri, uri_len, path, sizeof(path));

    if (strncmp(path, "stdout:", 7) == 0) {
        *out_handle = pal_stream_wrap_fd(STDOUT_FILENO, 0);
        return DK_STATUS_SUCCESS;
    }
    if (strncmp(path, "stderr:", 7) == 0) {
        *out_handle = pal_stream_wrap_fd(STDERR_FILENO, 0);
        return DK_STATUS_SUCCESS;
    }
    if (strncmp(path, "stdin:", 6) == 0) {
        *out_handle = pal_stream_wrap_fd(STDIN_FILENO, 0);
        return DK_STATUS_SUCCESS;
    }

    const char *posix_path = 0;
    if (strncmp(path, "file:", 5) == 0) {
        posix_path = path + 5;
        /* Strip a leading backslash or slash so "file:\foo" and
         * "file:/foo" both work. */
        if (*posix_path == '\\' || *posix_path == '/') posix_path++;
        for (char *c = (char *)posix_path; *c; c++)
            if (*c == '\\') *c = '/';
    } else {
        fprintf(stderr,
                "[pal_stream] FAIL-LOUD: DK_StreamOpen unsupported scheme '%s'\n",
                path);
        return DK_STATUS_NOT_IMPLEMENTED;
    }

    int oflags = O_RDONLY;
    /* Windows access bits: GENERIC_WRITE is 0x40000000. */
    if (access & 0x40000000) oflags = O_RDWR;
    /* create_disp: 1=OPEN, 2=CREATE_ALWAYS, 3=OPEN_EXISTING, 4=OPEN_ALWAYS,
     * 5=TRUNCATE_EXISTING. */
    if (create_disp == 2) oflags |= O_CREAT | O_TRUNC;
    if (create_disp == 4) oflags |= O_CREAT;
    if (create_disp == 5) oflags |= O_TRUNC;

    int fd = open(posix_path, oflags, 0644);
    if (fd < 0) return pal_stream_errno_to_status(errno);

    DK_HANDLE h = pal_stream_wrap_fd(fd, 1);
    if (h == DK_NULL_HANDLE) {
        close(fd);
        return DK_STATUS_NO_MEMORY;
    }
    *out_handle = h;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * The remaining 19 DK_Stream* entries are fail-loud stubs. They log
 * and return DK_STATUS_NOT_IMPLEMENTED so that the first real caller
 * surfaces itself rather than hiding behind silent zeros.
 * ================================================================ */

DK_API uint64_t DK_StreamRead(DK_HANDLE stream, uint64_t offset,
                               void *buffer, uint64_t bytes_to_read,
                               uint64_t *bytes_read) {
    (void)stream; (void)offset; (void)buffer; (void)bytes_to_read; (void)bytes_read;
    pal_stream_fail("DK_StreamRead");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamClose(DK_HANDLE handle) {
    pal_stream_handle_t *s = pal_stream_from_handle(handle);
    if (s) {
        if (s->owns_fd && s->fd >= 0) close(s->fd);
        s->fd = -1;
        return DK_STATUS_SUCCESS;
    }
    /* stdout/stderr/stdin handles are no-ops. */
    if (handle == (DK_HANDLE)STDIN_FILENO ||
        handle == (DK_HANDLE)STDOUT_FILENO ||
        handle == (DK_HANDLE)STDERR_FILENO) {
        return DK_STATUS_SUCCESS;
    }
    pal_stream_fail("DK_StreamClose");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamFlush(DK_HANDLE stream) {
    (void)stream;
    pal_stream_fail("DK_StreamFlush");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamSetLength(DK_HANDLE stream, uint64_t length) {
    (void)stream; (void)length;
    pal_stream_fail("DK_StreamSetLength");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamMap(DK_HANDLE stream, void *address,
                              uint64_t offset, uint64_t size,
                              uint64_t protect, void **mapped) {
    (void)stream; (void)address; (void)offset; (void)size;
    (void)protect; (void)mapped;
    pal_stream_fail("DK_StreamMap");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamMapPeBinary(DK_HANDLE stream, void **base,
                                      uint64_t *entry_point) {
    (void)stream; (void)base; (void)entry_point;
    pal_stream_fail("DK_StreamMapPeBinary");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamUnmap(void *address, uint64_t size) {
    (void)address; (void)size;
    pal_stream_fail("DK_StreamUnmap");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamDelete(DK_HANDLE stream) {
    (void)stream;
    pal_stream_fail("DK_StreamDelete");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamControl(DK_HANDLE in_handle, uint64_t op_code,
                                  void *in_buf, uint64_t in_size,
                                  void *out_buf, uint64_t out_size) {
    (void)in_handle; (void)op_code; (void)in_buf; (void)in_size;
    (void)out_buf; (void)out_size;
    pal_stream_fail("DK_StreamControl");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamAttributesQuery(const void *uri, void *attrs) {
    (void)uri; (void)attrs;
    pal_stream_fail("DK_StreamAttributesQuery");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamAttributesQueryByHandle(DK_HANDLE stream,
                                                   uint64_t flags, void *attrs) {
    (void)stream; (void)flags; (void)attrs;
    pal_stream_fail("DK_StreamAttributesQueryByHandle");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamEnumerateChildren(DK_HANDLE stream, void *buf,
                                            uint64_t buf_size, uint64_t *used) {
    (void)stream; (void)buf; (void)buf_size; (void)used;
    pal_stream_fail("DK_StreamEnumerateChildren");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamRename(DK_HANDLE stream, const void *new_name) {
    (void)stream; (void)new_name;
    pal_stream_fail("DK_StreamRename");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamChangesRegister(DK_HANDLE stream, uint64_t filter,
                                          uint64_t watch_tree, DK_HANDLE *event) {
    (void)stream; (void)filter; (void)watch_tree; (void)event;
    pal_stream_fail("DK_StreamChangesRegister");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamChangesPoll(DK_HANDLE stream, void *buf, uint64_t *size) {
    (void)stream; (void)buf; (void)size;
    pal_stream_fail("DK_StreamChangesPoll");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamRangeLock(DK_HANDLE stream, uint64_t off, uint64_t len,
                                    uint64_t exclusive) {
    (void)stream; (void)off; (void)len; (void)exclusive;
    pal_stream_fail("DK_StreamRangeLock");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamRangeUnlock(DK_HANDLE stream, uint64_t off, uint64_t len) {
    (void)stream; (void)off; (void)len;
    pal_stream_fail("DK_StreamRangeUnlock");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamGetEvent(DK_HANDLE stream, uint64_t event_id,
                                   DK_HANDLE *event) {
    (void)stream; (void)event_id; (void)event;
    pal_stream_fail("DK_StreamGetEvent");
    return DK_STATUS_NOT_IMPLEMENTED;
}

DK_API uint64_t DK_StreamEventSelect(DK_HANDLE stream, DK_HANDLE event,
                                      uint64_t poll_events, DK_HANDLE *async) {
    (void)stream; (void)event; (void)poll_events; (void)async;
    pal_stream_fail("DK_StreamEventSelect");
    return DK_STATUS_NOT_IMPLEMENTED;
}

} /* extern "C" */
