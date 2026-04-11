# Custom NTUM Builder Architecture

## Goal

Build a custom NTUM (NT User-Mode kernel) that can run arbitrary Windows
PE executables on Linux, using:
- **ReactOS ntoskrnl** code for the kernel implementation
- **ReactOS DLLs** for Win32 API (kernel32, user32, advapi32, etc.)
- **A custom PAL host** (Linux ELF) based on what we learned from sqlservr

## Reverse Engineering Findings from sqlpal.dll

### Key Discovery: The NTUM is a Single DLL

sqlpal.dll (2.7MB) is a **native subsystem DLL** that:
- Exports 1409 functions (the complete NT kernel API)
- Has **zero imports** (completely self-contained)
- Is loaded at base 0x180000000
- Entry point at 0x3a04d0 (DllMain-like initialization)
- Contains all of: ntdll, kernel, executive, I/O, memory, security, objects

### Subsystem Breakdown

| Subsystem | Exports | ReactOS Source |
|-----------|---------|----------------|
| NT Syscalls (Nt*/Zw*) | 345 | ntoskrnl/ntdll |
| RTL Runtime | 235 | ntoskrnl/rtl |
| Executive | 121 | ntoskrnl/ex |
| Process/Thread | 119 | ntoskrnl/ps |
| I/O Manager | 114 | ntoskrnl/io |
| Kernel Core | 113 | ntoskrnl/ke |
| Memory Manager | 53 | ntoskrnl/mm |
| Security | 44 | ntoskrnl/se |
| Object Manager | 35 | ntoskrnl/ob |
| Filesystem | 14 | ntoskrnl/fsrtl |
| Drawbridge | 13 | Custom (PAL bridge) |

### How sqlpal.dll boots (decompiled)

1. **Entry**: DllMain at 0x3a04d0
2. **NtCreateFile**: Thin wrapper -> fcn.18025e034 (I/O subsystem)
3. **NtAllocateVirtualMemory**: Tags as 'User', delegates to MmAllocateVirtualMemory
4. **NtWaitForSingleObject**: ObjectManager lookup -> wait subsystem
5. **NtStreamControl**: Bridge to PAL for stream I/O (files, network, pipes)

### The PAL Interface (from sqlservr ELF)

The ELF host provides these PAL operations (from strings analysis):
```
BinaryPeParser       - PE loader
PalMemoryMapPeBinary - mmap() sections with correct protections
VfsStream            - Virtual filesystem (stream I/O)
ObjectManager        - Windows handle table
PalSemaphore         - futex/pthread synchronization
ImagePageProtector   - mprotect() for PE sections
ArchiveDirectory     - SFP archive handler
Logger               - Debug tracing
```

## Build Plan

### Phase 1: Minimal NTUM (stub kernel)

Build a PE DLL that exports the core Nt* functions as stubs,
delegating to PAL calls for actual work.

```
custom_ntum.dll
  ├── NtCreateFile      -> PAL: pal_stream_open()
  ├── NtReadFile        -> PAL: pal_stream_read()
  ├── NtWriteFile       -> PAL: pal_stream_write()
  ├── NtClose           -> PAL: pal_stream_close()
  ├── NtAllocateVirtualMemory -> PAL: pal_mem_alloc()
  ├── NtFreeVirtualMemory     -> PAL: pal_mem_free()
  ├── NtCreateEvent     -> PAL: pal_event_create()
  ├── NtWaitForSingleObject   -> PAL: pal_event_wait()
  ├── NtCreateThread    -> PAL: pal_thread_create()
  └── ... (124 Nt* functions)
```

### Phase 2: ReactOS DLLs

Cross-compile key ReactOS DLLs with MinGW, linking against our NTUM:

```
kernel32.dll (110 .c files from ReactOS)
  ├── CreateFileA/W     -> NtCreateFile
  ├── ReadFile           -> NtReadFile
  ├── VirtualAlloc       -> NtAllocateVirtualMemory
  └── ...

advapi32.dll (29 .c files from ReactOS)
  ├── RegOpenKeyA/W     -> NtOpenKey
  ├── OpenProcessToken  -> NtOpenProcessToken
  └── ...

user32.dll (from ReactOS win32ss/user/user32)
  ├── MessageBoxA/W     -> stub (no GUI)
  └── ...

ws2_32.dll (36 .c files from ReactOS)
  ├── socket/connect/send/recv -> NtStreamControl
  └── ...
```

### Phase 3: PAL Host (Linux ELF)

Build a Linux executable that:
1. Opens the NTUM DLL (our custom_ntum.dll)
2. Maps it into memory (PE loader)
3. Loads ReactOS DLLs (kernel32.dll, etc.)
4. Loads the target Windows .exe
5. Resolves imports
6. Implements PAL operations using Linux syscalls
7. Transfers control to the target .exe entry point

## File Structure

```
ntum-builder/
├── ARCHITECTURE.md       # This file
├── Makefile              # Build everything
├── src/
│   ├── ntum_stub.c       # Minimal NTUM kernel (exports Nt* functions)
│   ├── ntum_pal.h        # PAL interface definition
│   ├── ntum_pal.c        # PAL implementation (calls back to host)
│   └── ntum_exports.def  # Export definition file
├── include/
│   ├── ntddk.h           # NT kernel types
│   └── ntstatus.h        # Status codes
├── reactos-dlls/
│   ├── build_kernel32.sh # Build kernel32 from ReactOS source
│   ├── build_advapi32.sh
│   └── ...
└── pal-host/
    ├── host.c            # Linux PAL host (ELF executable)
    ├── pe_loader.c       # PE/COFF loader
    └── pal_linux.c       # PAL -> Linux syscall mapping
```
