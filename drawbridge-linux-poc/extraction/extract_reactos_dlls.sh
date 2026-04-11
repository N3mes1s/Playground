#!/bin/bash
#
# Extract real Windows DLL implementations from ReactOS
#
# ReactOS provides open-source, clean-room implementations of:
#   - kernel32.dll  (Win32 base API)
#   - ntdll.dll     (NT native API)
#   - msvcrt.dll    (C runtime)
#   - advapi32.dll  (Advanced API - registry, services, security)
#
# These are REAL Windows API implementations, not stubs.
# They implement the actual semantics of CreateFile, VirtualAlloc,
# WriteConsole, etc.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REACTOS_DIR="$PROJECT_DIR/deps/reactos"
OUTPUT_DIR="$PROJECT_DIR/extracted/reactos-dlls"

if [ ! -d "$REACTOS_DIR" ]; then
    echo "WARNING: ReactOS source not found at $REACTOS_DIR"
    echo "Creating placeholder with documentation..."

    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/REACTOS_EXTRACTION.md" << 'EOF'
# ReactOS DLL Extraction Guide

ReactOS source was not downloaded (it's very large: ~2GB).
Here's how to extract the relevant DLLs manually.

## Manual Extraction

```bash
# Clone only the DLL directories we need
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/nicedreams/reactos.git reactos
cd reactos
git sparse-checkout set \
    dll/win32/kernel32 \
    dll/ntdll \
    dll/crt \
    sdk/include/reactos \
    sdk/include/ndk \
    sdk/lib/rtl
```

## Key ReactOS DLL Source Locations

### kernel32.dll (`dll/win32/kernel32/`)
- `client/file/` - CreateFile, ReadFile, WriteFile
- `client/proc/` - CreateProcess, ExitProcess
- `client/vdm/` - Virtual memory (VirtualAlloc, VirtualFree)
- `client/thread/` - CreateThread, ExitThread
- `client/synch/` - CreateEvent, WaitForSingleObject, CreateMutex
- `client/console/` - WriteConsole, GetStdHandle

### ntdll.dll (`dll/ntdll/`)
- `ldr/` - PE loader (LdrLoadDll)
- `rtl/` - Runtime library (memory, string, etc.)
- `csr/` - Client-Server Runtime (CSRSS)
- `def/` - NT API definitions

### msvcrt.dll (`dll/crt/`)
- Standard C library implementation
- printf, malloc, free, memcpy, etc.

## Why ReactOS DLLs Are Important

These are real, complete implementations of Windows APIs.
Unlike Wine (which translates Win32 -> POSIX), ReactOS DLLs
implement the actual Windows behavior, calling down to the
NT native API layer.

In our Drawbridge PoC, these DLLs sit between the Windows
application and our PAL:

```
Application -> kernel32.dll (ReactOS) -> ntdll.dll (ReactOS)
    -> PAL operations -> Linux syscalls
```

The ntdll.dll layer is where we intercept: instead of making
real NT syscalls, we redirect to our PAL.
EOF

    echo "Created extraction guide at $OUTPUT_DIR/REACTOS_EXTRACTION.md"
    exit 0
fi

echo "Extracting ReactOS DLLs to $OUTPUT_DIR..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"/{kernel32,ntdll,msvcrt,headers}

# ---- 1. kernel32.dll source ----
echo "  [1/4] kernel32.dll..."
if [ -d "$REACTOS_DIR/dll/win32/kernel32" ]; then
    cp -r "$REACTOS_DIR/dll/win32/kernel32/" "$OUTPUT_DIR/kernel32/"
fi

# ---- 2. ntdll.dll source ----
echo "  [2/4] ntdll.dll..."
if [ -d "$REACTOS_DIR/dll/ntdll" ]; then
    cp -r "$REACTOS_DIR/dll/ntdll/" "$OUTPUT_DIR/ntdll/"
fi

# ---- 3. msvcrt.dll source ----
echo "  [3/4] msvcrt.dll..."
if [ -d "$REACTOS_DIR/dll/crt" ]; then
    # Only copy the msvcrt part, not the full CRT
    cp -r "$REACTOS_DIR/dll/crt/" "$OUTPUT_DIR/msvcrt/" 2>/dev/null || true
fi

# ---- 4. SDK headers ----
echo "  [4/4] SDK headers..."
if [ -d "$REACTOS_DIR/sdk/include" ]; then
    # Copy key headers
    for dir in ndk reactos; do
        if [ -d "$REACTOS_DIR/sdk/include/$dir" ]; then
            cp -r "$REACTOS_DIR/sdk/include/$dir" "$OUTPUT_DIR/headers/" 2>/dev/null || true
        fi
    done
fi

cat > "$OUTPUT_DIR/REACTOS_COMPONENTS.md" << 'DLEOF'
# ReactOS DLL Components - Extracted

## Component Map

### kernel32.dll - Win32 Base API
The bridge between Win32 API and NT Native API.
Applications call kernel32 functions, which translate to ntdll calls.

Key APIs implemented:
- **File I/O**: CreateFileA/W, ReadFile, WriteFile, CloseHandle
- **Process**: CreateProcess, ExitProcess, GetCurrentProcess
- **Thread**: CreateThread, ExitThread, GetCurrentThreadId
- **Memory**: VirtualAlloc, VirtualFree, VirtualProtect
- **Sync**: CreateEvent, CreateMutex, WaitForSingleObject
- **Console**: GetStdHandle, WriteConsoleA, ReadConsoleA
- **Module**: GetModuleHandle, GetProcAddress, LoadLibrary

### ntdll.dll - NT Native API
The lowest-level user-mode DLL. All kernel32 calls eventually
reach ntdll, which makes the actual system calls.

**This is where we intercept for Drawbridge**: instead of
issuing real NT syscalls (int 2e / syscall), we redirect
to PAL operations.

Key APIs:
- **Memory**: NtAllocateVirtualMemory, NtFreeVirtualMemory
- **File**: NtCreateFile, NtReadFile, NtWriteFile
- **Process**: NtCreateProcess, NtTerminateProcess
- **Thread**: NtCreateThread, NtTerminateThread
- **Sync**: NtCreateEvent, NtWaitForSingleObject

### msvcrt.dll - C Runtime
Standard C library for Windows.
- printf, sprintf, fprintf
- malloc, free, realloc
- memcpy, memset, strlen, strcmp
- File operations (fopen, fread, fwrite)
- Math functions

## The Interception Point

In the original Drawbridge/SQLPAL:
```
ntdll.dll -> NT syscall instruction -> [INTERCEPTED] -> PAL -> Host OS
```

In our PoC:
```
ReactOS ntdll.dll (modified) -> PAL calls -> Gramine Linux PAL -> Linux syscalls
```

We modify ReactOS's ntdll to call our PAL instead of issuing NT syscalls.
This is a much smaller change than reimplementing all of kernel32.
DLEOF

FILE_COUNT=$(find "$OUTPUT_DIR" -type f 2>/dev/null | wc -l)
echo ""
echo "=== Extraction complete ==="
echo "  Output: $OUTPUT_DIR"
echo "  Files:  $FILE_COUNT"
