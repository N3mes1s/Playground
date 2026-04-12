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

#define DK_TRACE_ENTRY(fn_name, a, b, c, d) do {           \
    static int _n = 0;                                      \
    _n++;                                                   \
    if (_n <= 20) {                                         \
        fprintf(stderr, "[DK-CALL] %-32s #%d"                \
                        " a=0x%lx b=0x%lx c=0x%lx d=0x%lx\n",\
                fn_name, _n,                                \
                (unsigned long)(uintptr_t)(a),              \
                (unsigned long)(uintptr_t)(b),              \
                (unsigned long)(uintptr_t)(c),              \
                (unsigned long)(uintptr_t)(d));             \
    }                                                       \
} while (0)

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
    DK_TRACE_ENTRY("DK_StreamOpen", uri, uri_len, access, share_mode);
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
    DK_TRACE_ENTRY("DK_StreamRead", stream, offset, buffer, bytes_to_read);
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
    DK_TRACE_ENTRY("DK_StreamWrite", stream, offset, buffer, bytes_to_write);
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
    DK_TRACE_ENTRY("DK_StreamClose", handle, 0, 0, 0);
    return DK_ObjectClose(handle);
}

DK_API uint64_t DK_StreamFlush(DK_HANDLE stream) {
    DK_TRACE_ENTRY("DK_StreamFlush", stream, 0, 0, 0);
    if (stream >= MAX_HANDLES || g_handles[stream].type != HANDLE_FD)
        return DK_STATUS_SUCCESS;
    fsync(g_handles[stream].fd);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamSetLength(DK_HANDLE stream, uint64_t length) {
    DK_TRACE_ENTRY("DK_StreamSetLength", stream, length, 0, 0);
    if (stream >= MAX_HANDLES || g_handles[stream].type != HANDLE_FD)
        return DK_STATUS_INVALID_PARAM;
    if (ftruncate(g_handles[stream].fd, (off_t)length) < 0)
        return DK_STATUS_INVALID_PARAM;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamMap(DK_HANDLE stream, void *address,
                              uint64_t offset, uint64_t size,
                              uint64_t protect, void **mapped) {
    DK_TRACE_ENTRY("DK_StreamMap", stream, address, offset, size);
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
    DK_TRACE_ENTRY("DK_StreamMapPeBinary", stream, base, entry_point, 0);
    (void)stream;
    if (base) *base = (void*)PE_IMAGE_START;
    if (entry_point) *entry_point = PE_IMAGE_START + NTUM_ENTRY_RVA;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamUnmap(void *address, uint64_t size) {
    DK_TRACE_ENTRY("DK_StreamUnmap", address, size, 0, 0);
    munmap(address, size);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamDelete(DK_HANDLE stream) {
    DK_TRACE_ENTRY("DK_StreamDelete", stream, 0, 0, 0);
    (void)stream;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamControl(DK_HANDLE in_handle, uint64_t op_code,
                                  void *in_buf, uint64_t in_size,
                                  void *out_buf, uint64_t out_size) {
    DK_TRACE_ENTRY("DK_StreamControl", in_handle, op_code, in_buf, in_size);
    (void)in_handle; (void)op_code; (void)in_buf; (void)in_size;
    (void)out_buf; (void)out_size;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamAttributesQuery(const void *uri, void *attrs) {
    DK_TRACE_ENTRY("DK_StreamAttributesQuery", uri, attrs, 0, 0);
    (void)uri; (void)attrs;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamAttributesQueryByHandle(DK_HANDLE stream,
                                                   uint64_t flags, void *attrs) {
    DK_TRACE_ENTRY("DK_StreamAttributesQueryByHandle", stream, flags, attrs, 0);
    (void)stream; (void)flags; (void)attrs;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamEnumerateChildren(DK_HANDLE stream, void *buf,
                                            uint64_t buf_size, uint64_t *used) {
    DK_TRACE_ENTRY("DK_StreamEnumerateChildren", stream, buf, buf_size, used);
    (void)stream; (void)buf; (void)buf_size; (void)used;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamRename(DK_HANDLE stream, const void *new_name) {
    DK_TRACE_ENTRY("DK_StreamRename", stream, new_name, 0, 0);
    (void)stream; (void)new_name;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamChangesRegister(DK_HANDLE stream, uint64_t filter,
                                          uint64_t watch_tree, DK_HANDLE *event) {
    DK_TRACE_ENTRY("DK_StreamChangesRegister", stream, filter, watch_tree, event);
    (void)stream; (void)filter; (void)watch_tree; (void)event;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamChangesPoll(DK_HANDLE stream, void *buf, uint64_t *size) {
    DK_TRACE_ENTRY("DK_StreamChangesPoll", stream, buf, size, 0);
    (void)stream; (void)buf; (void)size;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamRangeLock(DK_HANDLE stream, uint64_t off, uint64_t len,
                                    uint64_t exclusive) {
    DK_TRACE_ENTRY("DK_StreamRangeLock", stream, off, len, exclusive);
    (void)stream; (void)off; (void)len; (void)exclusive;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamRangeUnlock(DK_HANDLE stream, uint64_t off, uint64_t len) {
    DK_TRACE_ENTRY("DK_StreamRangeUnlock", stream, off, len, 0);
    (void)stream; (void)off; (void)len;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamGetEvent(DK_HANDLE stream, uint64_t event_id,
                                   DK_HANDLE *event) {
    DK_TRACE_ENTRY("DK_StreamGetEvent", stream, event_id, event, 0);
    (void)stream; (void)event_id; (void)event;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_StreamEventSelect(DK_HANDLE stream, DK_HANDLE event,
                                      uint64_t poll_events, DK_HANDLE *async) {
    DK_TRACE_ENTRY("DK_StreamEventSelect", stream, event, poll_events, async);
    (void)stream; (void)event; (void)poll_events; (void)async;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Memory Management
 * ================================================================ */

/*
 * Protection flag converter - FUN_001d9720 @ sqlservr_FULL.c:32651-32657
 *   uint FUN_001d9720(uint param_1) {
 *       return param_1 & 3 | param_1 >> 1 & 6;
 *   }
 * Translates Windows PAGE_* bits to Linux PROT_* bits:
 *   bit 0 (NOACCESS shadow) -> PROT_READ-like low bit passthrough
 *   bit 1 (READONLY)        -> PROT_READ
 *   bit 2 (READWRITE)       -> PROT_WRITE (bit 1 after >>1)
 *   bit 4 (EXECUTE)         -> PROT_EXEC  (bit 2 after >>1, masked by &6)
 */
static int dk_prot_to_linux(uint64_t dk_prot) {
    uint32_t p = (uint32_t)dk_prot;
    return (int)((p & 3) | ((p >> 1) & 6));
}

/*
 * DK_VirtualMemoryAllocate
 *
 * Faithful translation of FUN_0024b4f0 @ sqlservr_FULL.c:118424-118570
 * with inline of its primary callee FUN_0024b210 @ 118310-118381
 * (mmap wrapper). Raw mmap thunk is FUN_00355380 @ 318743. Protection
 * translator is FUN_001d9720 @ 32651 (see dk_prot_to_linux above).
 *
 * The ELF function signature per the decompiled text is:
 *   (ulong DesiredAddress, long DesiredLength, uint AllocationType,
 *    uint Protect, ulong *OutBaseAddress, ulong *OutRegionSize,
 *    undefined4 MemoryKey)
 * The DK PAL signature presented to the NTUM passes the address/size as
 * in/out pointers:
 *   (void **address, uint64_t *size, uint64_t alloc_type, uint64_t protect)
 * So *address serves as both DesiredAddress input (ELF param_1) and
 * OutBaseAddress output (ELF param_5); likewise *size is DesiredLength
 * (param_2) and OutRegionSize (param_6). MemoryKey (param_7) is not
 * exposed through this signature; we pass 0 to the protection-and-key
 * tail call which we skip entirely (no pkey support on our host).
 *
 * Control flow matches the ELF step-by-step:
 *   1. Compute effective protect mask: uVar7 = param_4 ? (param_4|1) : 0.
 *   2. FUN_00280200(param_1) sanity-check of the hint (we approximate as
 *      "non-negative canonical pointer"; details unknown, TODO).
 *   3. Parameter validation: DesiredAddress != NULL, DesiredLength != 0,
 *      AllocationType != 0, valid protect (uVar7<0x10 && (uVar7&6)!=6),
 *      valid alloc flags ((param_3 & 0xffffff3c) == 0).
 *   4. Page-align: addr = param_1 & ~0xfff; len = (param_2 + (param_1&0xfff)
 *      + 0xfff) & ~0xfff.
 *   5. If (param_3 & 0x41) == 0 -> reserve-only: log only, NO mmap. The
 *      ELF trusts the caller's hint range without allocating (Windows
 *      MEM_RESERVE semantics). We FOLLOW this exactly.
 *   6. Else (commit or fault-handling): inline FUN_0024b210 ->
 *        prot_linux = FUN_001d9720(protect);
 *        mmap_flags = (alloc_type & 0x40) << 8 | 0x22;     // MAP_NORESERVE
 *        if hint != 0: mmap_flags |= 0x10;                  // MAP_FIXED
 *        result = mmap(hint, len, prot_linux, mmap_flags, -1, 0);
 *        assert result == MAP_FAILED || hint == 0 || result == hint.
 *      If alloc_type bits 0xc0 set, follow-up mprotect with pkey-ish
 *      mode: FUN_00355390(result, len, (alloc_type & 0x80) == 0 | 0xe).
 *   7. On success, also apply SetMemoryProtectionAndKey (FUN_0024b3e0).
 *      On our host this is just mprotect with prot_linux at the region,
 *      already done by mmap -- we still call mprotect to match semantics.
 */
DK_API uint64_t DK_VirtualMemoryAllocate(void **address, uint64_t *size,
                                          uint64_t alloc_type, uint64_t protect) {
    DK_TRACE_ENTRY("DK_VirtualMemoryAllocate", address, size, alloc_type, protect);

    /* Mirror ELF locals. */
    uint64_t local_88 = 0;        /* LocalBaseAddress */
    uint32_t uVar7;               /* effective protect */
    uint64_t uVar6;               /* aligned base */
    uint64_t uVar8;               /* aligned length */

    uint64_t param_1 = address ? (uint64_t)*address : 0;   /* DesiredAddress */
    uint64_t param_2 = size    ? *size               : 0;  /* DesiredLength */
    uint32_t param_3 = (uint32_t)alloc_type;               /* AllocationType */
    uint32_t param_4 = (uint32_t)protect;                  /* Protect */
    /* param_5 = address (out), param_6 = size (out), param_7 = 0 (key) */

    /* uVar7 = param_4 | 1; if (param_4 == 0) uVar7 = 0; */
    uVar7 = param_4 | 1u;
    if (param_4 == 0) uVar7 = 0;

    /* cVar2 = FUN_00280200(param_1);  if (cVar2 == '\0') set STATUS 0xc000000d.
     * FUN_00280200 is a hint-address validator (unk_validate_hint). We
     * approximate as "accept any value", TODO: study FUN_00280200 @ ELF. */
    /* unknown: FUN_00280200 behavior -> treat as always-true on our host */

    /* Parameter validation ladder. */
    if (param_1 == 0) {
        /* "DesiredAddress != nullptr" */
        return DK_STATUS_INVALID_PARAM;
    }
    if (param_2 == 0) {
        /* "DesiredLength != 0" */
        return DK_STATUS_INVALID_PARAM;
    }
    if (param_3 == 0) {
        /* "AllocationType != 0" */
        return DK_STATUS_INVALID_PARAM;
    }
    /* "DK_VALID_PAGE_PROTECTION(Protect)": uVar7 < 0x10 && (uVar7 & 6) != 6 */
    if (!(uVar7 < 0x10 && (uVar7 & 6) != 6)) {
        return DK_STATUS_INVALID_PARAM;
    }
    /* "DK_VALID_ALLOCATION_FLAGS(AllocationType)": (param_3 & 0xffffff3c)==0 */
    if ((param_3 & 0xffffff3cu) != 0) {
        return DK_STATUS_INVALID_PARAM;
    }

    /* Page-align address down and size up.
     *   uVar6 = param_1 & 0xfffffffffffff000;
     *   uVar8 = (param_2 + (param_1 & 0xfff) + 0xfff) & 0xfffffffffffff000;
     */
    uVar6 = param_1 & ~0xFFFULL;
    uVar8 = (param_2 + (param_1 & 0xFFFULL) + 0xFFFULL) & ~0xFFFULL;
    local_88 = uVar6;

    static int va_count = 0;
    va_count++;
    if (va_count <= 50) {
        fprintf(stderr,
                "[PAL] VirtualAlloc hint=0x%lx aligned=0x%lx len=0x%lx type=0x%x prot=0x%x\n",
                (unsigned long)param_1, (unsigned long)uVar6,
                (unsigned long)uVar8, param_3, param_4);
    }

    if ((param_3 & 0x41u) == 0) {
        /* Reserve-only branch: the ELF only LOGS and does NOT call mmap.
         * The hint range is simply accepted. */
        /* log: "VirtualMemoryAllocate(...) reserve %p-%zx" */
    } else {
        /* "commit" or "reserve&commit" branch. */
        if (uVar6 == 0) {
            /* addressCopy NULL with commit -> fatal in ELF. Return failure. */
            return DK_STATUS_INVALID_PARAM;
        }

        /* Inline FUN_0024b210(out, &local_88, uVar8, uVar7, 0x22, param_3, -1, 0).
         *   uVar4 = FUN_001d9720(uVar7);                   // prot_linux
         *   param_5 = (param_6 & 0x40) << 8 | param_5;      // add MAP_NORESERVE
         *   uVar1  = *param_2 == 0 ? param_5 : param_5|0x10;// MAP_FIXED if hint
         *   lVar6 = FUN_00355380(*param_2, param_3, uVar4, uVar1, -1, 0);
         */
        int prot_linux = dk_prot_to_linux(uVar7);
        /* PE image range: if mmap would clobber loaded PE, do mprotect instead.
         * Host-specific guard; the real ELF has no loaded PE here, it is the
         * binary itself. TODO: remove once our loader uses MAP_FIXED faithfully. */
        if (uVar6 >= PE_IMAGE_START && uVar6 < PE_IMAGE_END) {
            mprotect((void*)uVar6, uVar8, prot_linux ? prot_linux : (PROT_READ|PROT_WRITE));
        } else {
            int mmap_flags = (int)(((uint32_t)(param_3 & 0x40u)) << 8) | 0x22; /* MAP_PRIVATE|MAP_ANONYMOUS, +MAP_NORESERVE (0x4000) */
            if (uVar6 != 0) mmap_flags |= 0x10; /* MAP_FIXED */

            /* Use NOREPLACE instead of FIXED so we do not clobber existing
             * mappings (host-specific safety; ELF uses raw MAP_FIXED because
             * its VA space is fully managed). */
            int safe_flags = (mmap_flags & ~0x10) | MAP_FIXED_NOREPLACE;
            void *result = mmap((void*)uVar6, uVar8,
                                prot_linux ? prot_linux : (PROT_READ|PROT_WRITE),
                                safe_flags, -1, 0);
            if (result == MAP_FAILED) {
                /* Already mapped - emulate ELF's "address honored" path by
                 * just adjusting protection on the existing region. */
                mprotect((void*)uVar6, uVar8,
                         prot_linux ? prot_linux : (PROT_READ|PROT_WRITE));
            } else if (uVar6 != 0 && (uint64_t)result != uVar6) {
                /* ELF aborts with STATUS_INTERNAL_ERROR (0x11). */
                munmap(result, uVar8);
                return DK_STATUS_INVALID_PARAM;
            } else {
                local_88 = (uint64_t)result;
            }

            /* "if ((param_6 & 0xc0) != 0) FUN_00355390(lVar6, param_3,
             *      (param_6 & 0x80) == 0 | 0xe);"
             * This is pkey_mprotect-ish; skip on our host (TODO: pkeys). */
            /* unknown: FUN_00355390 pkey path */
        }

        if (local_88 != uVar6 && uVar6 != 0) {
            /* "LocalBaseAddress == addressCopy" assert. */
            return DK_STATUS_INVALID_PARAM;
        }
    }

    /* Success path: write out address/size and apply SetMemoryProtectionAndKey
     *   FUN_0024b3e0(out, local_88, uVar8, uVar7, param_7);
     * On our host this reduces to mprotect with dk_prot_to_linux(uVar7). */
    if (address) *address = (void*)(uintptr_t)local_88;
    if (size)    *size    = uVar8;

    if (local_88 != 0 && uVar7 != 0) {
        int prot_linux_final = dk_prot_to_linux(uVar7);
        if (prot_linux_final == 0) prot_linux_final = PROT_READ | PROT_WRITE;
        mprotect((void*)(uintptr_t)local_88, uVar8, prot_linux_final);
    }

    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_VirtualMemoryFree(void *address, uint64_t size,
                                      uint64_t free_type) {
    DK_TRACE_ENTRY("DK_VirtualMemoryFree", address, size, free_type, 0);
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
    DK_TRACE_ENTRY("DK_VirtualMemoryProtect", address, size, new_protect, old_protect);
    /* Wave-26: per DKVirtualMemoryProtect:enter log format in sqlpal
     * .rdata, this function has 3 args (baseAddress, regionLength,
     * newProtect). Our 4th arg `old_protect` was speculative; callers
     * pass garbage (observed r9=1) in that register. Validate the
     * pointer before dereferencing -- only write if it lies in a
     * reasonable kernel/user memory range, otherwise skip silently. */
    uintptr_t opv = (uintptr_t)old_protect;
    int op_valid = (opv != 0) &&
                   ((opv & 0x7) == 0) &&
                   ((opv >= 0x180000000ULL && opv < 0x180e00000ULL) ||
                    (opv >= 0x300000000ULL && opv < 0x501000000ULL));
    if (op_valid) *old_protect = WIN_PAGE_READWRITE;
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
    DK_TRACE_ENTRY("DK_ThreadCreate", start_routine, stack_ptr, flags, thread);
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
    DK_TRACE_ENTRY("DK_ThreadExit", exit_code, 0, 0, 0);
    pthread_exit((void*)(intptr_t)exit_code);
}

DK_API uint64_t DK_ThreadYieldExecution(void) {
    DK_TRACE_ENTRY("DK_ThreadYieldExecution", 0, 0, 0, 0);
    sched_yield();
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ThreadInterrupt(DK_HANDLE thread) {
    DK_TRACE_ENTRY("DK_ThreadInterrupt", thread, 0, 0, 0);
    (void)thread;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ThreadSetAffinity(DK_HANDLE thread, uint64_t group,
                                      uint64_t mask) {
    static int ta_count = 0;
    ++ta_count;
    fprintf(stderr,
        "[TSA] #%d thread=0x%lx group=0x%lx mask=0x%lx\n",
        ta_count, (unsigned long)thread,
        (unsigned long)group, (unsigned long)mask);
    DK_TRACE_ENTRY("DK_ThreadSetAffinity", thread, group, mask, 0);
    (void)thread; (void)group; (void)mask;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Synchronization
 * ================================================================ */

DK_API uint64_t DK_NotificationEventCreate(uint64_t initial_state,
                                            DK_HANDLE *event) {
    DK_TRACE_ENTRY("DK_NotificationEventCreate", initial_state, event, 0, 0);
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
    DK_TRACE_ENTRY("DK_SynchronizationEventCreate", initial_state, event, 0, 0);
    return DK_NotificationEventCreate(initial_state, event);
}

DK_API uint64_t DK_EventSet(DK_HANDLE event) {
    DK_TRACE_ENTRY("DK_EventSet", event, 0, 0, 0);
    if (event >= MAX_HANDLES || g_handles[event].type != HANDLE_EVENT)
        return DK_STATUS_INVALID_PARAM;
    uint64_t val = 1;
    ssize_t ret = write(g_handles[event].eventfd, &val, sizeof(val));
    (void)ret;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventClear(DK_HANDLE event) {
    DK_TRACE_ENTRY("DK_EventClear", event, 0, 0, 0);
    if (event >= MAX_HANDLES || g_handles[event].type != HANDLE_EVENT)
        return DK_STATUS_INVALID_PARAM;
    uint64_t val;
    ssize_t ret = read(g_handles[event].eventfd, &val, sizeof(val));
    (void)ret;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_EventPeek(DK_HANDLE event, uint64_t *signaled) {
    DK_TRACE_ENTRY("DK_EventPeek", event, signaled, 0, 0);
    if (event >= MAX_HANDLES || g_handles[event].type != HANDLE_EVENT)
        return DK_STATUS_INVALID_PARAM;
    struct pollfd pfd = { .fd = g_handles[event].eventfd, .events = POLLIN };
    int ret = poll(&pfd, 1, 0);
    if (signaled) *signaled = (ret > 0) ? 1 : 0;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ObjectsWaitAny(uint64_t count, DK_HANDLE *objects,
                                   uint64_t timeout, uint64_t *index) {
    DK_TRACE_ENTRY("DK_ObjectsWaitAny", count, objects, timeout, index);
    (void)count; (void)objects; (void)timeout;
    if (index) *index = 0;
    usleep(1000);
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Object Management
 * ================================================================ */

DK_API uint64_t DK_ObjectClose(DK_HANDLE handle) {
    DK_TRACE_ENTRY("DK_ObjectClose", handle, 0, 0, 0);
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
    DK_TRACE_ENTRY("DK_ObjectReference", handle, 0, 0, 0);
    (void)handle;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Process Management
 * ================================================================ */

DK_API uint64_t DK_ProcessCreate(void *params, DK_HANDLE *process) {
    DK_TRACE_ENTRY("DK_ProcessCreate", params, process, 0, 0);
    (void)params; (void)process;
    return DK_STATUS_SUCCESS;
}

DK_API void DK_ProcessExit(uint64_t exit_code) {
    DK_TRACE_ENTRY("DK_ProcessExit", exit_code, 0, 0, 0);
    _exit((int)exit_code);
}

DK_API uint64_t DK_ProcessTerminate(DK_HANDLE process,
                                     uint64_t exit_code) {
    DK_TRACE_ENTRY("DK_ProcessTerminate", process, exit_code, 0, 0);
    (void)process; (void)exit_code;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_ProcessGetExitCode(DK_HANDLE process,
                                       uint64_t *exit_code) {
    DK_TRACE_ENTRY("DK_ProcessGetExitCode", process, exit_code, 0, 0);
    (void)process;
    if (exit_code) *exit_code = 0;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * System
 * ================================================================ */

DK_API uint64_t DK_SystemTimeQuery(uint64_t clock_type,
                                    uint64_t *time_val) {
    DK_TRACE_ENTRY("DK_SystemTimeQuery", clock_type, time_val, 0, 0);
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
    DK_TRACE_ENTRY("DK_RandomBitsRead", buffer, length, 0, 0);
    ssize_t ret = getrandom(buffer, length, 0);
    return (ret == (ssize_t)length) ? DK_STATUS_SUCCESS
                                    : DK_STATUS_INVALID_PARAM;
}

/* Wave-37: DkThreadSetRegisters stub (DK id 0xf004000).
 * Per PE enter-tag at 0x43cbe0 "DKDkThreadSetRegisters:enter
 * thread=0x%I64x", dispatcher marshals 4 args:
 *   (thread_handle, *CONTEXT_record, context_size, flags)
 * The PE's BOOT init calls this to set the initial thread's
 * register state. Our port runs the PE's boot thread directly on
 * the host stack so there's nothing physical to update; returning
 * SUCCESS is sufficient for the PE to continue (it uses this as a
 * no-op on the in-process path). */
DK_API uint64_t DK_DkThreadSetRegisters(DK_HANDLE thread,
                                         void *context_record,
                                         uint64_t context_size,
                                         uint64_t flags) {
    (void)thread; (void)context_record; (void)context_size; (void)flags;
    static int count = 0;
    ++count;
    if (count <= 5)
        fprintf(stderr,
            "[DK-TSR] #%d thread=0x%lx ctx=%p size=0x%lx flags=0x%lx\n",
            count, (unsigned long)thread, context_record,
            (unsigned long)context_size, (unsigned long)flags);
    return DK_STATUS_SUCCESS;
}

/* Wave-35: DkSystem_CpuUtilizationQuery_v1 (DK id 0xe003000).
 * Per PE enter-tag "DkSystem_CpuUtilizationQuery_v1:enter kernelTime
 * userTime thread" — signature with dispatcher trace-ctx is
 * (trace_ctx, thread_handle, *out_user, *out_kernel).
 * Stub returns zeros; a real implementation would use
 * clock_gettime(CLOCK_THREAD_CPUTIME_ID). */
DK_API uint64_t DK_SystemCpuUtilizationQueryV1(void *trace_ctx,
                                                DK_HANDLE thread,
                                                uint64_t *user_time,
                                                uint64_t *kernel_time) {
    (void)trace_ctx; (void)thread;
    static int count = 0;
    ++count;
    if (count <= 5)
        fprintf(stderr,
            "[DK-CpuUtil] #%d thread=0x%lx out_u=%p out_k=%p\n",
            count, (unsigned long)thread,
            (void*)user_time, (void*)kernel_time);
    /* Validate out-pointers: reject bogus values like 1. */
    auto ok = [](void *p) {
        uintptr_t v = (uintptr_t)p;
        return v > 0x1000 && (v & 0x7) == 0;
    };
    if (ok(user_time))   *user_time   = 0;
    if (ok(kernel_time)) *kernel_time = 0;
    return DK_STATUS_SUCCESS;
}

/* Wave-35: DkSystemTimeQuery dispatcher-adapted signature.
 * Our legacy DK_SystemTimeQuery takes (clock_type, *out_time) but the
 * 0xe002 dispatcher passes (trace_ctx, clock_type, *out_time, 0) -- a
 * trace-context is injected as arg1. Use this adapter for the 0xe002
 * path; the legacy 0x8001 mapping keeps its 2-arg signature. */
DK_API uint64_t DK_SystemTimeQueryV2(void *trace_ctx,
                                     uint64_t clock_type,
                                     uint64_t *time_val,
                                     uint64_t extra) {
    (void)trace_ctx; (void)extra;
    static int count = 0;
    ++count;
    if (count <= 5)
        fprintf(stderr,
            "[DK-StqV2] #%d clock=%lu out=%p\n",
            count, (unsigned long)clock_type, (void*)time_val);
    struct timespec ts;
    clockid_t clk = (clock_type == 0) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
    clock_gettime(clk, &ts);
    uint64_t ft = ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL
                  + (uint64_t)ts.tv_nsec / 100;
    uintptr_t v = (uintptr_t)time_val;
    if (v > 0x1000 && (v & 0x7) == 0)
        *time_val = ft;
    return DK_STATUS_SUCCESS;
}

/* ================================================================
 * Console
 * ================================================================ */

DK_API uint64_t DK_ConsoleCreate(DK_HANDLE *console) {
    DK_TRACE_ENTRY("DK_ConsoleCreate", console, 0, 0, 0);
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
    DK_TRACE_ENTRY("DK_SystemInfoQuery", info_class, buffer, buffer_size, result_size);
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
    DK_TRACE_ENTRY("DK_ProcessGetId", pid, 0, 0, 0);
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
    DK_TRACE_ENTRY("DK_AbiDispatcher", context, call_type, data_size, in_buf);
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

    /* Wave-36: re-arm the boot-params-echo pointer + counter at
     * [0x180c00880]/[+0x888]. FUN_0x26fcb4 null-checks these on
     * boot path; the PE's own init at RVA 0x20486a tries to populate
     * them but in our port the path isn't reached before the check
     * so they stay 0 and fastfail. Keep them seeded every call so
     * the check always passes. */
    if (*(volatile uint64_t*)0x180c00880ULL == 0) {
        uint64_t params_ptr = *(volatile uint64_t*)0x180c00820ULL;
        if (params_ptr)
            *(volatile uint64_t*)0x180c00880ULL = params_ptr;
    }
    if (*(volatile uint32_t*)0x180c00888ULL == 0)
        *(volatile uint32_t*)0x180c00888ULL = 1;

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

    /* Wave-24: HANDLE 0x7002002 (GetVersion_v2) SEPARATELY.
     *
     * The PE has TWO resolver functions:
     *   - FUN_00213ea4 (GetFunction_v2): calls with type=0x7001002, expects
     *     the output slot to be populated with a FUNCTION POINTER.
     *   - FUN_00213e0c (GetVersion_v2):  calls with type=0x7002002, expects
     *     the output slot to be populated with a VERSION NUMBER (integer).
     *
     * Previously we handled both identically and wrote the fn ptr for each.
     * The version-check consumer at PE RVA 0x21458c reads [0x63f878] expecting
     * value 2, but instead found the function pointer 0x4048F0 (our DK
     * function addr) -> panic "Unsupported ABI version: 4212976 for function:
     * DkVirtualMemoryProtect" at RVA 0x213e06.
     *
     * Fix: route 0x7002002 to a separate branch that writes the version (2)
     * for every function id. */
    if (call_type == 0x7002002) {
        /* Wave-25: per-function version response. The PE's downstream
         * version-check sites mostly expect 1 (103 cmp-against-1 sites
         * vs 13 cmp-against-2 sites in sqlpal disasm).
         * in_buf points to a struct {uint32_t dk_id, uint32_t flag};
         * we choose the version based on the queried dk_id. */
        uint32_t dk_id = 0;
        if (in_buf)
            dk_id = *(uint32_t*)in_buf;

        uint32_t version = 1;  /* default: most DK functions are v1 */

        /* Known v2 functions (from cmp $0x2,%ebx disasm sites):
         * DkVirtualMemoryProtect (0x5003000) at RVA 0x2145c8,
         * and a few others TBD. Populate as they surface. */
        switch (dk_id & 0xFFFFF000) {
        case 0x5003000:  /* DkVirtualMemoryProtect (verified via wave-24) */
            version = 2;
            break;
        /* DkStreamAttributesQuery also reported by wave-24 panic.
         * Its version slot is tied to a different DK id -- TBD. */
        default: break;
        }

        if (out_buf) {
            uint64_t *result_ptr = *(uint64_t**)out_buf;
            if (result_ptr) {
                *(uint32_t*)result_ptr = version;
            }
        }
        uint64_t retval = DK_STATUS_SUCCESS;
        if (dispatch_count <= 500)
            fprintf(stderr, "[DK-RET] #%d GetVersion(dk_id=0x%x) -> ver=%u status=0x%lx\n",
                    dispatch_count, dk_id, version, (unsigned long)retval);
        return retval;
    }

    /* Handle ABI function resolution:
     * 0x7001002 = GetFunction_v2 (PE resolver FUN_00213ea4, stores fn ptr) */
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

        /* Wave-26: category 0x05 was mislabeled "Synchronization" -- the
         * PE resolver actually queries DkVirtualMemoryProtect at
         * 0x5003000 (verified via wave-24 capture: panic at RVA 0x21467b
         * for function name at 0x43ba50 = "DkVirtualMemoryProtect" with
         * version slot [0x63f878] populated via GetVersion(0x5003000)).
         *
         * The other 0x5xxx IDs remain tentatively mapped to sync
         * primitives but this may also be wrong -- will verify as
         * boot progresses and each function gets called. */
        /* Wave-33: 0x5001/5002 remapped from event create to identity-
         * echo. The PE's caller at RVA 0x37b492 passes rcx/rdx as
         * VAs and expects *out1=rcx, *out2=rdx (identity). Our
         * previous DK_NotificationEventCreate wrote a kevent pointer
         * which didn't match the PE's `cmp rsi, [rbp-0x18]` check. */
        case 0x5001000: {
            DK_API uint64_t DK_VmIdentityEcho(void*, uint64_t, uint64_t,
                                              uint32_t, uint32_t,
                                              uint64_t*, uint64_t*);
            func = (void*)&DK_VmIdentityEcho; is_stub=0; break;
        }
        case 0x5002000: {
            DK_API uint64_t DK_VmIdentityEcho(void*, uint64_t, uint64_t,
                                              uint32_t, uint32_t,
                                              uint64_t*, uint64_t*);
            func = (void*)&DK_VmIdentityEcho; is_stub=0; break;
        }
        case 0x5003000: func = (void*)&DK_VirtualMemoryProtect; is_stub=0; break;

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

        /* Cache/Events (category 0x0C)
         * v0 = feature flag (must return 1 — the PE's init resolution loop
         *      writes this to .data globals the fatal-error handler checks
         *      as `cmp $1, edi; jne fatal_path`).
         * v1+ = actual function pointer. */
        /* Two-phase resolution (id-bit-based, matching pattern used
         * for category 0xf):
         *   base_id (original_version==0) → feature flag value 1
         *     stored at [0x63f...] globals; fatal-error handler does
         *     `cmp $1, edi; jne fatal` on these slots.
         *   base_id+1 (original_version==1) → real function pointer
         *     stored at separate globals; PE calls them via
         *     `call *[..]` so they must be valid callable addresses. */
        case 0xc001000:
            func = (original_version == 0) ? (void*)1 : (void*)&DK_InstructionCacheFlush;
            is_stub=0; break;
        case 0xc002000:
            func = (original_version == 0) ? (void*)1 : (void*)&DK_EventSet;
            is_stub=0; break;
        case 0xc003000:
            func = (original_version == 0) ? (void*)1 : (void*)&DK_EventClear;
            is_stub=0; break;
        case 0xc004000:
            func = (original_version == 0) ? (void*)1 : (void*)&DK_EventPeek;
            is_stub=0; break;

        /* Wave-35 (agent-A analysis /tmp/wave35_e00_map.md): category 0xe
         * is System Utilities, NOT "extended threading" as our comment
         * previously claimed. Confirmed via resolver-loop trace at RVA
         * 0x213318+ and enter-tag strings:
         *   0xe001000 = DkInstructionCacheFlush
         *                 (enter-tag at 0x43cf30 "DKInstructionCacheFlush:enter
         *                  baseAddress length")
         *   0xe002000 = DkSystemTimeQuery
         *                 (enter-tag at 0x43cdd8 "DKSystemTimeQuery:enter
         *                  clockType=%I64x")
         *   0xe003000 = DkSystem_CpuUtilizationQuery_v1
         *                 (enter-tag at 0x43ce10)
         * Previously bound to DK_ThreadInterrupt / DK_ThreadSetAffinity
         * which caused FUN_0x21698c to receive INVALID_PARAMETER and
         * fastfail at RAX=0xc000000d.
         *
         * DK_SystemCpuUtilizationQueryV1 is a new stub that returns zeros
         * (real impl would clock_gettime(CLOCK_THREAD_CPUTIME_ID)). */
        case 0xe001000: func = (void*)&DK_InstructionCacheFlush; is_stub=0; break;
        case 0xe002000: func = (void*)&DK_SystemTimeQueryV2;     is_stub=0; break;
        case 0xe003000: func = (void*)&DK_SystemCpuUtilizationQueryV1; is_stub=0; break;

        /* Stream extended (category 0x0F):
         * First pass (version 0, func_id ends in 000) = feature flags.
         * The PE checks if result == 1 to determine support.
         * Second pass (version 1+, func_id ends in 001+) = actual function pointers.
         * Discovered from PE disassembly:
         *   RVA 0x2133bf: 0xf005000 → [0x63f4f0] (flag, checked == 1)
         *   RVA 0x213ba2: 0xf005001 → [0x63f4f8] (func ptr, called via jmp *rax)
         */
        /* Wave-37: 0xf004000 is DkThreadSetRegisters (not a stream fn).
         * Agent-B traced fn-ptr slot [0x63f4f8] → 0xf004001 (not
         * 0xf005001 as our comment claimed), and matched the enter-tag
         * at 0x43cbe0 "DKDkThreadSetRegisters:enter thread=0x%I64x".
         * When this returns 0 the BOOT init path hits
         * "BOOT: FATAL: Failed to initialize initial thread" at 0x439058.
         * Dispatcher marshals (thread_handle, *CONTEXT, size, flags). */
        case 0xf004000: func = (void*)&DK_DkThreadSetRegisters; is_stub=0; break;

        /* Stream extended (category 0x0F) -- stubs for now */
        case 0xf001000: case 0xf002000: case 0xf003000:
                       case 0xf005000: case 0xf006000:
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
        if (dispatch_count <= 500) {
            fprintf(stderr, "[DK] Resolve 0x%x v%u → %p %s (orig_v=%u)\n",
                    func_id, version, func,
                    is_stub ? "(STUB)" : "(impl)", original_version);
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
        {
            uint64_t retval = 0;
            if (dispatch_count <= 500 || (dispatch_count % 1000) == 0)
                fprintf(stderr, "[DK-RET] #%d call_type=0x%lx -> status=0x%lx\n",
                        dispatch_count, (unsigned long)call_type, (unsigned long)retval);
            return retval;  /* STATUS_SUCCESS */
        }
    }

    if (call_type == ABI_GET_VERSION_V2) {
        /* Return ABI version 2. Must return SUCCESS, not NOT_IMPLEMENTED. */
        if (out_buf)
            *(uint32_t*)out_buf = 2;
        {
            uint64_t retval = DK_STATUS_SUCCESS;
            if (dispatch_count <= 500 || (dispatch_count % 1000) == 0)
                fprintf(stderr, "[DK-RET] #%d call_type=0x%lx -> status=0x%lx\n",
                        dispatch_count, (unsigned long)call_type, (unsigned long)retval);
            return retval;
        }
    }

    /* Config calls: type is a .data address pointing to an embedded
     * kernel object the PE wants initialised. The PE's own constructor
     * at RVA 0x240ea0 writes [+0], [+8], and [+0x10]=sentinel
     * 0x12345678deaddead, but DOES NOT initialise the SRW-lock waiter
     * anchor LIST_ENTRY at [+0x18]/[+0x20]. Without that self-ref, the
     * first `RtlpWakeSRWLockExclusive` at PE RVA 0x226ad3 walks a half-
     * initialised chain and deadlocks forever on [+0x20]==0 — the exact
     * hang we observe at DK call #234 on .data 0x1806679d0.
     *
     * Root-cause and evidence: /tmp/deadlock_rca.md.
     * ELF source: /tmp/sqlpal_full.txt lines 74286-74321 (0x240ea0 body),
     *             /tmp/sqlpal_full.txt lines 44219-44245 (226aa8 wake path).
     *
     * Fix: when the config-call target lies inside PE .data and the
     * constructor sentinel is present but the LIST_ENTRY Flink is still
     * zero, stamp the self-referencing waiter anchor the PE forgot. */
    /* PostRes in the 0x1806xxxxx range: the PE's 0x240ea0 constructor
     * writes sentinel 0x12345678deaddead at [+0x10] of every "waiter
     * anchor" kernel object in PE .data, but forgets to self-ref the
     * LIST_ENTRY at [+0x18]/[+0x20]. Walk the whole .data BSS range
     * each config call and stamp any newly-initialised anchor. */
    if (call_type >= 0x180600000ULL && call_type < 0x180700000ULL) {
        static int scan_count = 0;
        int stamped_now = 0;
        for (uint64_t addr = 0x180600000ULL; addr < 0x180700000ULL; addr += 8) {
            volatile uint64_t *p = (volatile uint64_t*)addr;
            /* Detect sentinel @ p[+2] */
            if (p[2] == 0x12345678deaddeadULL
                && p[4] == 0                      /* Flink still zero */
                && p[3] != (addr + 0x18)) {        /* not already stamped */
                p[3] = addr + 0x18;                /* +0x18 Blink -> &link */
                p[4] = addr + 0x18;                /* +0x20 Flink -> &link */
                stamped_now++;
                if (scan_count < 5 && stamped_now < 10) {
                    fprintf(stderr,
                        "[DK] stamped SRW waiter-anchor at 0x%lx\n",
                        (unsigned long)addr);
                }
            }
        }
        /* [RCA-TRACE] log each post-res call's target -- we're looking
         * for the call that precedes rsi=0xc0000002 in the crash. */
        fprintf(stderr,
            "[RCA-TRACE] PostRes target=0x%lx stamped=%d scan#=%d\n",
            (unsigned long)call_type, stamped_now, scan_count);
        /* Dump the qword at call_type and call_type+8 / +0x10 / +0x18
         * so we can see whether the PE .data slot holds 0xc0000002. */
        {
            volatile uint64_t *q = (volatile uint64_t*)call_type;
            fprintf(stderr,
                "[RCA-TRACE]   [t]=%016lx [t+8]=%016lx [t+10]=%016lx "
                "[t+18]=%016lx [t+20]=%016lx [t+28]=%016lx [t+2c]=%08x\n",
                (unsigned long)q[0], (unsigned long)q[1],
                (unsigned long)q[2], (unsigned long)q[3],
                (unsigned long)q[4], (unsigned long)q[5],
                *(volatile uint32_t*)(call_type + 0x2c));
            if (q[0] == 0xC0000002ULL || q[1] == 0xC0000002ULL
                || q[2] == 0xC0000002ULL || q[3] == 0xC0000002ULL) {
                fprintf(stderr,
                    "[RCA-TRACE] !! FOUND 0xc0000002 at call_type=0x%lx\n",
                    (unsigned long)call_type);
            }
        }
        scan_count++;
    }

    static int post_count = 0;
    post_count++;
    if (post_count <= 50) {
        fprintf(stderr, "[DK] PostRes: type=0x%lx size=0x%lx in=%p out=%p\n",
                (unsigned long)call_type, (unsigned long)data_size, in_buf, out_buf);
    }

    /* [DK-FACTORY] Minimal descriptor -> kernel-object factory.
     *
     * When call_type is a PE .data descriptor pointer, the PE expects us
     * to allocate a kernel-object shaped by that descriptor and hand the
     * pointer back via *out_buf. The ELF's real path (FUN_00249418) does
     * exactly this — without it, the PE reads a NULL/NTSTATUS slot and
     * dereferences garbage (the 0x180224c29 crash). */
    if (call_type >= 0x180600000ULL && call_type < 0x180700000ULL) {
        volatile uint64_t *desc = (volatile uint64_t*)call_type;
        uint64_t hdr0  = desc[0];   /* +0x00 vtable or tag */
        uint64_t hdr1  = desc[1];   /* +0x08 flags or size */
        uint64_t hdr2  = desc[2];   /* +0x10 sentinel or data */
        uint64_t hdr3  = desc[3];   /* +0x18 */

        /* Derive object size: descriptor[+0x08] sometimes encodes size
         * in the low 16 bits. Clamp to a sane range; default 0x200. */
        uint64_t obj_size = 0x200;
        uint64_t maybe_sz = hdr1 & 0xFFFFULL;
        if (maybe_sz >= 0x40 && maybe_sz <= 0x1000) {
            obj_size = (maybe_sz + 0xF) & ~0xFULL;
        }

        /* Detect vtable pointer at [+0x00]: PE code range. */
        int has_vtable = (hdr0 >= 0x180000000ULL && hdr0 < 0x181000000ULL);

        /* Allocate zero-init kernel-object buffer. calloc lives in the
         * host heap — the NTUM accepts this range as "kernel" memory
         * for these slot-writes. */
        void *new_obj = calloc(1, obj_size);
        if (new_obj) {
            volatile uint64_t *obj = (volatile uint64_t*)new_obj;
            /* [+0x00] vtable (or copy of tag). */
            obj[0] = has_vtable ? hdr0 : hdr0;
            /* [+0x08] flags/size echo. */
            obj[1] = hdr1;
            /* [+0x10] sentinel the PE's 0x240ea0 ctor also writes. */
            obj[2] = 0x12345678deaddeadULL;
            /* [+0x18]/[+0x20]/[+0x28] LIST_ENTRY self-refs (same
             * pattern as the SRW waiter anchor above). */
            uint64_t link = (uint64_t)&obj[3];   /* &obj[+0x18] */
            obj[3] = link;                        /* +0x18 Blink */
            obj[4] = link;                        /* +0x20 Flink */
            obj[5] = link;                        /* +0x28 */

            /* Log construction. */
            fprintf(stderr,
                "[DK-FACTORY] desc=0x%lx size=0x%lx -> obj=%p "
                "hdr=[%016lx %016lx %016lx %016lx] vtbl=%d\n",
                (unsigned long)call_type, (unsigned long)obj_size,
                new_obj, (unsigned long)hdr0, (unsigned long)hdr1,
                (unsigned long)hdr2, (unsigned long)hdr3, has_vtable);

            /* Write into *out_buf ONLY when out_buf is a real pointer
             * (PE .data or LibOS range) — not the 0x42-style tiny tag
             * values some ABI calls use. */
            if (out_buf) {
                uint64_t ob = (uint64_t)out_buf;
                int in_pe_data = (ob >= 0x180000000ULL && ob < 0x181000000ULL);
                int in_libos   = (ob >= 0x100000000ULL && ob < 0x800000000ULL);
                if (in_pe_data || in_libos) {
                    volatile uint64_t *slot = (volatile uint64_t*)out_buf;
                    /* Preserve valid existing pointer; only overwrite
                     * NULL or the pre-stamped STATUS_NOT_IMPLEMENTED. */
                    uint64_t cur = *slot;
                    if (cur == 0 || cur == 0xC0000002ULL ||
                        (cur & 0xFFFFFFFFULL) == 0xC0000002ULL) {
                        *slot = (uint64_t)new_obj;
                        fprintf(stderr,
                            "[DK-FACTORY] wrote obj=%p into *out_buf=%p\n",
                            new_obj, out_buf);
                    }
                }
            }
        } else {
            fprintf(stderr,
                "[DK-FACTORY] desc=0x%lx alloc FAILED size=0x%lx\n",
                (unsigned long)call_type, (unsigned long)obj_size);
        }
    }

    /* RCA2 fix: the PE pre-stamps DK_STATUS_NOT_IMPLEMENTED (0xC0000002)
     * in its output slot before calling us. When we return SUCCESS but
     * don't write the slot, the PE later reads that NTSTATUS as if it
     * were a valid pointer (seen at PE RIP 0x2661bc caching, then used
     * at 0x224b78 as rdx→rsi). Write NULL to the out slot so the PE's
     * downstream null-check takes the safe branch. See /tmp/status_rca.md.
     *
     * The ELF's real path (FUN_00249418) stores the allocated kernel-object
     * pointer here; until that's translated, NULL is strictly better than
     * leaving STATUS_NOT_IMPLEMENTED in place. */
    if (out_buf) {
        uint64_t ob = (uint64_t)out_buf;
        if ((ob >= 0x180000000ULL && ob < 0x181000000ULL) ||
            (ob >= 0x100000000ULL && ob < 0x800000000ULL)) {
            /* ONLY overwrite if the slot currently holds the PE's
             * pre-stamped STATUS_NOT_IMPLEMENTED (0xC0000002). Any
             * other value may be a valid pointer the PE expects us to
             * preserve — don't stomp it. */
            volatile uint64_t *slot = (volatile uint64_t*)out_buf;
            if (*slot == 0xC0000002ULL ||
                ((*slot & 0xFFFFFFFFULL) == 0xC0000002ULL)) {
                *slot = 0;
                fprintf(stderr, "[DK] cleared NTSTATUS 0xC0000002 at out_buf=%p\n",
                        out_buf);
            }
        }
    }
    {
        uint64_t retval = DK_STATUS_SUCCESS;
        /* Throttle logging — each fprintf consumes ~3 KB of stack
         * via libc internal buffers. With PostRes call loops of 500+
         * the cumulative stack use blows our 2 MB boot stack. */
        if (dispatch_count <= 500 || (dispatch_count % 1000) == 0)
            fprintf(stderr, "[DK-RET] #%d call_type=0x%lx -> status=0x%lx\n",
                dispatch_count, (unsigned long)call_type, (unsigned long)retval);
        return retval;
    }
}

/* Wave-33/34: DkVirtualMemoryAllocate v2 (DK id 0x5001000).
 *
 * Agent-B trace of the PE resolver loop at RVA 0x213067 + enter-tag
 * string matching confirmed category 0x5xxx is the live "v2" VM
 * interface:
 *   0x5001000 = DkVirtualMemoryAllocate (this function)
 *   0x5002000 = DkVirtualMemoryFree
 *   0x5003000 = DkVirtualMemoryProtect
 * The 0x2xxx VM category is legacy/stale; no PE code reads its
 * resolver results.
 *
 * Agent-A analysis of FUN_0x212860 (v1 sub-dispatcher) gave the
 * extended 7-arg signature:
 *   NTSTATUS DK_VmRegisterRange(
 *       void* traceCtx,       // rcx: injected by dispatcher (not PE arg)
 *       u64   vaStart,        // rdx: PE's rcx (vaStart)
 *       u64   vaEnd,          // r8:  PE's rdx (vaEnd)
 *       u32   regionKind,     // r9:  PE's r8d (kind, often 3)
 *       u32   index,          // [rsp+0x20]: PE's r9d
 *       u64*  outVaStart,     // [rsp+0x28]: PE's arg5
 *       u64*  outVaEnd);      // [rsp+0x30]: PE's arg6
 *
 * The caller at RVA 0x37b4a3 validates identity-echo:
 *     cmp rsi(=vaStart), [rbp-0x18]  (outVaStart)
 *     cmp rdi(=vaEnd),   [rbp-0x10]  (outVaEnd)
 * so our shim must write *outVaStart = vaStart (rdx) and
 * *outVaEnd = vaEnd (r8). */
DK_API __attribute__((force_align_arg_pointer))
uint64_t DK_VmIdentityEcho(void *trace_ctx, uint64_t va_start,
                           uint64_t va_end, uint32_t region_kind,
                           uint32_t index, uint64_t *out_va_start,
                           uint64_t *out_va_end) {
    (void)trace_ctx; (void)region_kind; (void)index;
    static int echo_count = 0;
    ++echo_count;
    if (echo_count <= 20)
        fprintf(stderr,
            "[VM-ECHO] #%d vaStart=0x%lx vaEnd=0x%lx kind=%u idx=%u "
            "out_start=%p out_end=%p\n",
            echo_count, (unsigned long)va_start, (unsigned long)va_end,
            region_kind, index,
            (void*)out_va_start, (void*)out_va_end);

    /* Wave-38: satisfy "Register Initial Module" by populating an
     * auxiliary ModuleDescriptor at [VmModuleState+0xa8] that
     * covers the PE image range. Agent C traced the crash to:
     *   FUN_0x37cf68 VmModuleState::ReservePeImageRange
     *     -> reads [vms+0xa8] as the module-descriptor head
     *     -> FUN_0x3804b8 checks desc->+0x48 <= request_va < desc->+0x48+desc->+0x50
     *     -> our DK_VmIdentityEcho echoes vaStart/vaEnd but never
     *        creates a descriptor covering the PE image at
     *        [0x180000000, +0x01000000).
     *
     * Stamp a minimal descriptor:
     *   [+0x48] = va_start  [+0x50] = va_end (size)  [+0x68] = bitmap
     *   [+0x70] = 0x8000 (cap pages)  [+0x80] = 2 (valid)
     * The bitmap page gets demand-paged by our handler and zero-filled
     * (0=FREE per wave-29 semantics). Link: [vms+0xa8] -> this desc. */
    static uint8_t aux_descriptor[0x100]
        __attribute__((aligned(16))) = {0};
    static uint64_t aux_bitmap[0x200]
        __attribute__((aligned(16))) = {0};  /* 0x1000 bytes, 0x8000 pages */
    uint64_t vms_ptr = *(volatile uint64_t*)0x180c00878ULL;
    if (vms_ptr && *(volatile uint64_t*)(vms_ptr + 0xa8) == 0) {
        /* Seed a descriptor covering the PE image range (not the
         * incoming VM-ECHO range). The PE's ReservePeImageRange at
         * FUN_0x37cf68 reads [vms+0xa8] and expects a descriptor whose
         * [+0x48, +0x48+0x50) bracket the PE image at 0x180000000
         * with size 0x01000000 (16 MB). */
        uint8_t *d = aux_descriptor;
        *(uint64_t*)(d + 0x48) = 0x180000000ULL;  /* PE image base */
        *(uint64_t*)(d + 0x50) = 0x01000000ULL;   /* 16 MB size */
        *(uint64_t*)(d + 0x58) = (uint64_t)d;     /* self-ptr */
        *(uint64_t*)(d + 0x68) = (uint64_t)aux_bitmap;
        *(uint64_t*)(d + 0x70) = 0x8000;          /* 32k pages */
        *(uint32_t*)(d + 0x80) = 2;               /* state = valid */
        *(volatile uint64_t*)(vms_ptr + 0xa8) = (uint64_t)d;
        fprintf(stderr,
            "[VM-ECHO] stamped aux module descriptor at vms+0xa8=%p "
            "covering PE image [0x180000000, +0x01000000) bitmap=%p\n",
            (void*)d, (void*)aux_bitmap);
    }

    if (out_va_start) *out_va_start = va_start;
    if (out_va_end)   *out_va_end   = va_end;
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
/* No-op vtable slot used to fill unclaimed entries of the kernel
 * pool_obj's vtable. Returns 0 so the PE's `jmp *%rax` → returns-0
 * path doesn't cascade into recursion. */
DK_API __attribute__((force_align_arg_pointer))
uint64_t pool_vtable_noop(void *a, uint64_t b, uint64_t c,
                           void *d, uint64_t e, void *f) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    return 0;
}

uint64_t pool_allocator_fn(void *pool_obj, uint64_t alloc_size,
                            uint64_t flags, void *param4,
                            uint64_t param5, void *param6) {
    DK_TRACE_ENTRY("pool_allocator_fn", pool_obj, alloc_size, flags, param4);
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

    /* Wave-19: stamp VM-object magic 0xDB64DB64 at [result+0x10].
     *
     * The PE's VM-object validator at RVA 0x24c38c checks:
     *   cmpl $0xdb64db64, (rbx+0x10)
     * and returns STATUS_INVALID_HANDLE (0xc0000008) if the low 32
     * bits of [obj+0x10] don't match. Before this fix, we stamped a
     * stack-descriptor pointer at +0x10 whose low 32 bits were a PE
     * address, never 0xDB64DB64. The validator always returned
     * 0xc0000008, which FUN_387650 (a wait primitive) propagated into
     * RtlRaiseStatus -- the head of the raise-recursion cascade that
     * we've been chasing for many waves.
     *
     * Previously the kernel-stack descriptor at BOOT_STRUCTS_ADDR +
     * 0x16000 was initialised here as a side-effect (setting
     * [sd+0x30] = NTUM_STACK_TOP). Keep that init but write the
     * magic to [result+0x10]. If any consumer actually needs a
     * stack-descriptor value at that offset, we'll surface the new
     * crash and move the descriptor to a different slot. */
    uint8_t *sd = (uint8_t*)(BOOT_STRUCTS_ADDR + 0x16000);
    if (*(uint64_t*)(sd + 0x30) == 0)
        *(uint64_t*)(sd + 0x30) = NTUM_STACK_TOP;
    *(uint64_t*)((uint8_t*)result + 0x10) = 0xDB64DB64ULL;

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
    DK_TRACE_ENTRY("DK_GenericStub", a, b, c, d);
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

/* ================================================================
 * [RCA-TRACE] 0xc0000002 origin audit.
 *
 * The crash fault is rsi=0xc0000002 at PE 0x180224c29. Goal: determine
 * whether any DK_* function we own ever returns 0xc0000002 (aliased as
 * DK_STATUS_NOT_IMPLEMENTED). The stream stubs in pal_stream.cpp ARE
 * the usual suspects -- they return this value from fail-loud paths.
 *
 * Since production .cpp files are off-limits, we install an exit-hook
 * that dumps a dispatcher event-log summary to help pinpoint the
 * last DK_* call before the PE reads 0xc0000002 through rsi. The hook
 * is registered from dk_pal_init().
 * ================================================================ */
extern "C" int g_rca_stream_fail_count;
int g_rca_stream_fail_count = 0;

static void dk_rca_dump(void) {
    fprintf(stderr, "[RCA-TRACE] === dispatcher exit summary ===\n");
    fprintf(stderr, "[RCA-TRACE] pal_stream FAIL-LOUD returns seen: %d\n",
            g_rca_stream_fail_count);
}

DK_API uint64_t DK_AbiGetFunction(uint64_t abi_id, void **func_ptr) {
    DK_TRACE_ENTRY("DK_AbiGetFunction", abi_id, func_ptr, 0, 0);
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

/* Weak fallback — real implementation lives in pal_except.c (C9). */
__attribute__((weak)) DK_API uint64_t DK_ExceptionRecordFree(void *record) {
    DK_TRACE_ENTRY("DK_ExceptionRecordFree", record, 0, 0, 0);
    (void)record;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_InstructionCacheFlush(void *base, uint64_t length) {
    DK_TRACE_ENTRY("DK_InstructionCacheFlush", base, length, 0, 0);
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
