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
- Specifically in FUN_001f1c50 (FileIoCompletionPort init) → io_setup failure
- Zero DK stubs are ever called during boot - the failure is before any PAL call
- Root cause: The NTUM needs io_setup (Linux AIO syscall 0xce=206) which is
  normally provided by the ELF host's FUN_00354180 (raw syscall wrapper)

### CORRECTION: PE and ELF Share RVAs but Have DIFFERENT Code
- Ghidra decompiled the ELF (sqlservr), NOT the PE (sqlpal.dll)
- Functions at same RVAs have DIFFERENT implementations:
  - ELF's FUN_00354180: raw Linux syscall wrapper (mov rax,nr; syscall)
  - PE's RVA 0x354180: different code (30 03 00 00 48 3b...)
  - ELF's FUN_00202100: calls io_setup via syscall
  - PE's RVA 0x202100: sub rsp,0x28; lea rcx,... (calls through PAL)
- The PE goes through our ABI dispatcher for ALL host operations
- Post-resolution config calls (#85-90) are the PE's PAL requests
- We need to handle these config types properly (they're NOT just status reports)

### ParameterBuffer Has TWO DIFFERENT Checks
- `[0x180c00820]` → ptr → `[ptr] == 0x190` (LIBOS params size check at RVA 0x20e51d)
- `ParameterBuffer[0:4:8]` = `{0x10, 0x38, callback}` (ABI header at RVA 0x204a37)
- These are TWO SEPARATE buffers. Don't use one for both.

### TEB Thread Chain (from PE RVA 0x244cd0)
```
gs:0x30 → TEB[0x1838] → KTHREAD[0x70] → SCHED + 0xF0
```
- The NTUM creates its OWN TEB during init (overrides our GS base)
- TEB[0x1838] = pointer to kernel thread info (set during NTUM thread creation)
- Without working VirtualMemoryAllocate, the thread structures aren't created
- This causes the crash at RVA 0x387809 (DrtlDelayCurrentThreadExecute)

### Error Handling Pattern (used throughout NTUM)
```c
struct pal_result {
    char    *source_file;  // +0x00
    int32_t  status;       // +0x08 (HRESULT: negative = error)
    uint16_t line;         // +0x0C
    int32_t  extended;     // +0x10
};
// FUN_0028e530(r) = r->status >= 0  // success check
// FUN_0028e0d0(r, status, file, line) = set error
```

### Resolution Results Overlap Critical .data Globals
- 0x7001000 (AbiGetVersion) v0 → [0x63f8c0] (boot flag, must be 1)
- 0x7002000 (AbiGetFunction) v0 → [0x63f5c0] (ABI version, must be 2)  
- 0x8001001 (SystemTimeQuery v1) → [0x63f8c8] (dispatcher ptr!)
- 0xf005000 (StreamExt) v0 → [0x63f4f0] (feature flag, must be 1)
- Re-arm ALL these values on every dispatcher call
- Version 0 = flag values (1, 2), Version 1+ = real function pointers

### AbiGetVersion (0x7001000) Overwrites Boot Flag
- Resolution of func_id 0x7001000 stores result at [0x18063f8c0]
- This IS the boot flag address! Must return (void*)1 to keep flag valid
- If the flag ≠ 1, the ABI dispatch wrapper enters int3 spin loop
- The PE's resolution loop at RVA 0x212e0c stores ALL resolved function
  pointers at specific .data addresses via `mov [rip+offset], eax`

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
