# Drawbridge Linux PoC - Development Context

## Project Overview
Reimplementation of Microsoft's Drawbridge architecture (Library OS) on Linux.
The real NTUM kernel (sqlpal.dll from MSSQL Server) runs Windows PE executables
by providing a user-mode Windows kernel with ~72 PAL (Platform Abstraction Layer)
functions mapped to Linux syscalls.

## Architecture
```
Windows PE App → ntdll.dll → sqlpal.dll (NTUM) → DK PAL (our code) → Linux syscalls
```

## Two Host Implementations

### 1. drawbridge-host/ (Real NTUM approach)
- Loads actual sqlpal.dll from MSSQL Server SFP archives
- Located at: deps/mssql-extracted/opt/mssql/lib/system.sfp
- Currently boots through 84 DK function resolutions + boot sync
- BLOCKED on NTUM internal init failure (see analysis/BOOT_SEQUENCE_DEBUG.md)

### 2. ntum-builder/ (Standalone PE loader)
- Direct PE loading + Win32 API stubs (no sqlpal.dll needed)
- WORKING: runs hello_drawbridge.exe end-to-end
- Uses __attribute__((ms_abi)) for ABI translation

## Critical Knowledge (DO NOT FORGET)

### GetFunction_v2 Output Protocol
```c
// CORRECT: Double-deref. out_buf points to a pointer to the result slot.
uint64_t *result_ptr = *(uint64_t**)out_buf;
*result_ptr = (uint64_t)func;

// WRONG: Single-deref. This DESTROYS the NTUM's internal pointer!
// *(uint64_t*)out_buf = func;  // DO NOT DO THIS
```

### The 0xC0000002 Error is NTUM-Internal
- It is NOT from our DK function returns
- It is NOT from our output protocol
- It IS generated inside the NTUM's C++ initialization code
- Specifically in FUN_001f1c50 (FileIoCompletionPort init)
- Zero DK stubs are ever called during boot - the failure is before any PAL call

### Boot Sync vs Exception int3
- `CC EB FD` preceded by `74` (je) = boot sync spin loop → patch to nops + set flag
- `CC EB FD` preceded by anything else = debug assertion → need exception forwarding
- Standalone `CC` = regular int3 → forward to NTUM exception dispatcher

### KiUserExceptionDispatcher Location
- Stored at: RuntimeCallbackState + 0x10 (= DAT_003b2148 in ELF)
- Set by NTUM during boot (initially 0)
- Must be non-zero before exception forwarding works

### Key Files
- `drawbridge_types.h` - Central type definitions (all structures)
- `analysis/EXCEPTION_DISPATCH_RE.md` - Exception forwarding protocol
- `analysis/BOOT_SEQUENCE_DEBUG.md` - Full boot debug log & findings
- `analysis/sqlservr_FULL.c` - 321K lines decompiled sqlservr (Ghidra)
- `analysis/sqlservr_boot.c` - Decompiled boot functions

## Build Commands
```bash
# drawbridge-host (real NTUM)
cd drawbridge-host && make

# Run with real sqlpal.dll
./drawbridge-host <target.exe> --sfp-dir ../deps/mssql-extracted/opt/mssql/lib

# ntum-builder (standalone)
cd ntum-builder && make

# Build test PE
x86_64-w64-mingw32-gcc -o test/hello_drawbridge.exe ../test-apps/hello_drawbridge.c -ladvapi32 -mconsole

# Run standalone
./drawbridge-run test/hello_drawbridge.exe
```
