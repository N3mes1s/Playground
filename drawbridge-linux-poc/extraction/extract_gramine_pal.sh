#!/bin/bash
#
# Extract the real PAL (Platform Abstraction Layer) from Gramine
#
# Gramine's PAL is the open-source equivalent of Microsoft's Drawbridge PAL.
# It implements ~50 operations that abstract the host OS.
#
# What we extract:
#   - PAL API headers (the interface definition)
#   - Linux PAL implementation (the syscall mappings)
#   - Common PAL utilities
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GRAMINE_DIR="$PROJECT_DIR/deps/gramine"
OUTPUT_DIR="$PROJECT_DIR/extracted/gramine-pal"

if [ ! -d "$GRAMINE_DIR" ]; then
    echo "ERROR: Gramine source not found at $GRAMINE_DIR"
    echo "Run setup_environment.sh first"
    exit 1
fi

echo "Extracting Gramine PAL to $OUTPUT_DIR..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"/{api,linux-pal,linux-common,common,loader}

# ---- 1. PAL API Headers (the ~50 operation interface) ----
echo "  [1/5] PAL API headers..."
cp -r "$GRAMINE_DIR/pal/include/pal/" "$OUTPUT_DIR/api/"
# Also grab the internal headers
cp "$GRAMINE_DIR/pal/include/pal_internal.h" "$OUTPUT_DIR/api/" 2>/dev/null || true
cp "$GRAMINE_DIR/pal/include/pal_rtld.h" "$OUTPUT_DIR/api/" 2>/dev/null || true

# Architecture-specific headers
if [ -d "$GRAMINE_DIR/pal/include/arch/x86_64" ]; then
    mkdir -p "$OUTPUT_DIR/api/arch"
    cp -r "$GRAMINE_DIR/pal/include/arch/x86_64/" "$OUTPUT_DIR/api/arch/"
fi

# ---- 2. Linux PAL Implementation (the real syscall mappings) ----
echo "  [2/5] Linux PAL implementation..."
if [ -d "$GRAMINE_DIR/pal/src/host/linux" ]; then
    cp "$GRAMINE_DIR/pal/src/host/linux/"*.c "$OUTPUT_DIR/linux-pal/" 2>/dev/null || true
    cp "$GRAMINE_DIR/pal/src/host/linux/"*.h "$OUTPUT_DIR/linux-pal/" 2>/dev/null || true
    cp "$GRAMINE_DIR/pal/src/host/linux/"*.S "$OUTPUT_DIR/linux-pal/" 2>/dev/null || true
fi

# ---- 3. Linux Common (shared between linux and linux-sgx) ----
echo "  [3/5] Linux common utilities..."
if [ -d "$GRAMINE_DIR/pal/src/host/linux-common" ]; then
    cp "$GRAMINE_DIR/pal/src/host/linux-common/"*.c "$OUTPUT_DIR/linux-common/" 2>/dev/null || true
    cp "$GRAMINE_DIR/pal/src/host/linux-common/"*.h "$OUTPUT_DIR/linux-common/" 2>/dev/null || true
fi

# ---- 4. Common PAL source (shared across all hosts) ----
echo "  [4/5] Common PAL source..."
cp "$GRAMINE_DIR/pal/src/"*.c "$OUTPUT_DIR/common/" 2>/dev/null || true
cp "$GRAMINE_DIR/pal/src/"*.h "$OUTPUT_DIR/common/" 2>/dev/null || true

# ---- 5. ELF Loader (we'll study this to understand what to replace with PE) ----
echo "  [5/5] ELF loader (for reference)..."
cp "$GRAMINE_DIR/pal/src/pal_rtld.c" "$OUTPUT_DIR/loader/" 2>/dev/null || true
if [ -f "$GRAMINE_DIR/pal/src/host/linux/pal_rtld.c" ]; then
    cp "$GRAMINE_DIR/pal/src/host/linux/pal_rtld.c" "$OUTPUT_DIR/loader/pal_rtld_linux.c"
fi

# ---- Generate PAL operation summary ----
echo ""
echo "  Generating PAL operation summary..."

cat > "$OUTPUT_DIR/PAL_OPERATIONS.md" << 'PALEOF'
# Gramine PAL Operations - Extracted from Real Source

These are the REAL PAL operations from Gramine's source code.
Each one maps to Linux syscalls in the linux-pal/ directory.

## Memory Management
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalVirtualMemoryAlloc` | `pal_memory.c` | `mmap(MAP_ANONYMOUS\|MAP_PRIVATE)` |
| `PalVirtualMemoryFree` | `pal_memory.c` | `munmap()` |
| `PalVirtualMemoryProtect` | `pal_memory.c` | `mprotect()` |

## Stream/File I/O
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalStreamOpen` | `pal_files.c` | `open()` |
| `PalStreamRead` | `pal_files.c` | `read()` / `pread64()` |
| `PalStreamWrite` | `pal_files.c` | `write()` / `pwrite64()` |
| `PalStreamDelete` | `pal_files.c` | `unlink()` / `rmdir()` |
| `PalStreamSetLength` | `pal_files.c` | `ftruncate()` |
| `PalStreamFlush` | `pal_files.c` | `fsync()` |
| `PalStreamAttributesQuery` | `pal_files.c` | `stat()` |
| `PalStreamAttributesQueryByHandle` | `pal_files.c` | `fstat()` |
| `PalStreamChangeName` | `pal_files.c` | `rename()` |

## Sockets
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalSocketCreate` | `pal_sockets.c` | `socket()` |
| `PalSocketBind` | `pal_sockets.c` | `bind()` |
| `PalSocketListen` | `pal_sockets.c` | `listen()` |
| `PalSocketAccept` | `pal_sockets.c` | `accept4()` |
| `PalSocketConnect` | `pal_sockets.c` | `connect()` |
| `PalSocketSend` | `pal_sockets.c` | `sendmsg()` |
| `PalSocketRecv` | `pal_sockets.c` | `recvmsg()` |

## Pipes
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalStreamWaitForClient` | `pal_pipes.c` | `accept()` |
| `PalSendHandle` | `pal_streams.c` | `sendmsg(SCM_RIGHTS)` |
| `PalReceiveHandle` | `pal_streams.c` | `recvmsg(SCM_RIGHTS)` |

## Process Management
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalProcessCreate` | `pal_process.c` | `vfork()` + `execve()` |
| `PalProcessExit` | `pal_process.c` | `exit_group()` |

## Thread Management
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalThreadCreate` | `pal_threading.c` | `clone()` |
| `PalThreadResume` | `pal_threading.c` | (signals) |
| `PalThreadExit` | `pal_threading.c` | `exit()` |
| `PalThreadYieldExecution` | `pal_threading.c` | `sched_yield()` |
| `PalThreadSetCpuAffinity` | `pal_threading.c` | `sched_setaffinity()` |
| `PalThreadGetCpuAffinity` | `pal_threading.c` | `sched_getaffinity()` |

## Synchronization
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalEventCreate` | `pal_events.c` | `eventfd()` |
| `PalEventSet` | `pal_events.c` | `eventfd_write()` |
| `PalEventClear` | `pal_events.c` | `eventfd_read()` |
| `PalEventWait` | `pal_events.c` | `eventfd_read()` + `ppoll()` |
| `PalStreamsWaitEvents` | `pal_events.c` | `ppoll()` |

## Device
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalDeviceMap` | `pal_devices.c` | `mmap()` |
| `PalDeviceIoControl` | `pal_devices.c` | `ioctl()` |

## System / Misc
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalSystemTimeQuery` | `pal_misc.c` | `clock_gettime(CLOCK_REALTIME)` |
| `PalRandomBitsRead` | `pal_misc.c` | `getrandom()` |
| `PalCpuIdRetrieve` | `pal_misc.c` | `cpuid` instruction |
| `PalSegmentBaseGet` | `pal_misc.c` | `arch_prctl(ARCH_GET_FS/GS)` |
| `PalSegmentBaseSet` | `pal_misc.c` | `arch_prctl(ARCH_SET_FS/GS)` |

## Exception Handling
| Function | File | Linux Syscall |
|----------|------|---------------|
| `PalSetExceptionHandler` | `pal_exception.c` | `rt_sigaction()` |

## Total: ~50 operations
PALEOF

# Count extracted files
FILE_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l)
echo ""
echo "=== Extraction complete ==="
echo "  Output: $OUTPUT_DIR"
echo "  Files:  $FILE_COUNT"
echo "  Key file: $OUTPUT_DIR/PAL_OPERATIONS.md"
