# Drawbridge Component Matrix

## The Full Stack

To run a Windows executable on Linux using Drawbridge architecture,
you need these layers. For each layer, we map the available real components.

```
Layer 4: Windows Application (.exe)
         The unmodified PE binary we want to run
         |
Layer 3: Win32 DLLs (kernel32.dll, user32.dll, msvcrt.dll)
         Implement Windows API, call down to ntdll
         |
Layer 2: NT User-Mode Kernel (ntdll.dll / ntoskrnl user-mode)
         The Library OS core - implements NT syscalls
         INTERCEPT POINT: NT syscalls -> PAL calls
         |
Layer 1: PAL (Platform Abstraction Layer)
         ~50 primitive operations
         |
Layer 0: Linux Kernel
         Host OS providing real syscalls
```

## Component Availability Matrix

| Layer | Component | Microsoft (SQLPAL) | Gramine | Wine | ReactOS | Status |
|-------|-----------|-------------------|---------|------|---------|--------|
| **L1: PAL** | Memory mgmt | Proprietary | `PalVirtualMemory*` | N/A | N/A | **Gramine: READY** |
| | Thread mgmt | Proprietary | `PalThread*` | N/A | N/A | **Gramine: READY** |
| | I/O streams | Proprietary | `PalStream*` | N/A | N/A | **Gramine: READY** |
| | Sockets | Proprietary | `PalSocket*` | N/A | N/A | **Gramine: READY** |
| | Sync | Proprietary | `PalEvent*` | N/A | N/A | **Gramine: READY** |
| | Time/Misc | Proprietary | `PalSystemTime*` | N/A | N/A | **Gramine: READY** |
| **L2: NTUM** | NT syscall dispatch | .dbpatch mechanism | N/A | `ntdll/unix/` | `dll/ntdll/` | **MISSING** |
| | PE loader | In ntoskrnl.dll.bin | ELF only | `ntdll/loader.c` | `dll/ntdll/ldr/` | **Wine: EXTRACTABLE** |
| | Registry | windows.hiv | N/A | Wine registry | ReactOS registry | **Wine: EXTRACTABLE** |
| | Object manager | ntoskrnl.dll.bin | N/A | Wine server | ReactOS kernel | Partial |
| **L3: Win32** | kernel32.dll | In system.sfp | N/A | `dlls/kernel32/` | `dll/win32/kernel32/` | **Wine: READY** |
| | user32.dll | In system.sfp | N/A | `dlls/user32/` | `dll/win32/user32/` | Wine: READY |
| | msvcrt.dll | In system.sfp | N/A | `dlls/msvcrt/` | `dll/crt/` | **Wine: READY** |
| | ws2_32.dll | In system.sfp | N/A | `dlls/ws2_32/` | `dll/win32/ws2_32/` | Wine: READY |

## The Critical Gap: Layer 2 (NT User-Mode Kernel)

### What Microsoft Has (Proprietary)
- **ntoskrnl.dll.bin**: A full user-mode NT kernel from Windows 8
- **.dbpatch files**: Binary patches that redirect syscall instructions to PAL
- The patched ntdll.dll routes all NT syscalls through the PAL

### What's Available (Open Source)

**Wine's approach** (most promising):
```
Wine's ntdll (dlls/ntdll/unix/) already translates:
  NT syscalls -> Linux syscalls

We need to change this to:
  NT syscalls -> PAL calls -> Linux syscalls

This is a surgical modification, not a full rewrite.
Wine already does 90% of the work.
```

**ReactOS approach** (harder):
```
ReactOS ntdll issues real NT syscalls (int 2e / syscall).
We would need to:
1. Replace the syscall dispatch mechanism
2. Route to PAL calls instead
3. This is the .dbpatch approach but at source level
```

## Recommended Architecture: Wine-on-PAL

The most realistic path to a working Drawbridge-like system:

```
Windows .exe (unmodified)
    |
    v
Wine's DLLs (kernel32, msvcrt, etc.)  <-- Already open source
    |
    v
Wine's ntdll (modified)               <-- Key change: route to PAL
    |                                      instead of Linux syscalls
    v
Gramine PAL (~50 operations)           <-- Already open source
    |
    v
Linux kernel
```

### Why This Works

1. **Wine's DLLs are battle-tested**: They run thousands of Windows apps
2. **Wine's ntdll already translates NT -> host OS**: We just change
   which host OS interface it targets (PAL instead of raw Linux)
3. **Gramine's PAL provides the abstraction**: ~50 clean operations
4. **The PE loader comes from Wine**: Already handles PE32, PE32+,
   imports, relocations, TLS, exception handling

### What We Modify

| Wine Component | Current Behavior | Drawbridge Modification |
|---------------|-----------------|------------------------|
| `ntdll/unix/virtual.c` | Calls `mmap()` directly | Call `PalVirtualMemoryAlloc()` |
| `ntdll/unix/loader.c` | Opens files with `open()` | Call `PalStreamOpen()` |
| `ntdll/unix/thread.c` | Creates threads with `clone()` | Call `PalThreadCreate()` |
| `ntdll/unix/signal_x86_64.c` | Installs signal handlers | Call `PalSetExceptionHandler()` |
| `ntdll/unix/sync.c` | Uses `futex()` for sync | Call `PalEventWait()` |

### Effort Estimate

| Task | Complexity | Description |
|------|-----------|-------------|
| Extract Wine PE loader | Low | Copy and adapt `ntdll/unix/loader.c` + `virtual.c` |
| Build PAL shim for Wine | Medium | Replace ~20 Linux syscall sites in Wine's unix layer |
| Integrate Gramine PAL | Low | Link against Gramine's libpal |
| Test with simple .exe | Low | Cross-compile hello world with MinGW |
| Run real application | High | Debug API coverage gaps |

## SFP Extraction (for Reference)

To study how Microsoft does it (proprietary, analysis only):

```bash
# Install sfpack
git clone https://github.com/nta/sfpack && cd sfpack && make

# Extract Library OS
./sfpack /opt/mssql/lib/system.sfp
# -> ntoskrnl.dll.bin, ntdll.dll, ntdll.dll.dbpatch, etc.

# Extract SQL Server
./sfpack /opt/mssql/lib/sqlservr.sfp
# -> sqlservr.exe, SqlDK.dll, sqllang.dll, etc.
```

## Key References

| Resource | URL |
|----------|-----|
| Drawbridge paper (ASPLOS 2011) | microsoft.com/en-us/research/publication/rethinking-the-library-os-from-the-top-down/ |
| Gramine PAL API | gramine.readthedocs.io/en/stable/pal/host-abi.html |
| Wine PE loader | gitlab.winehq.org/wine/wine/-/tree/master/dlls/ntdll |
| sfpack (SFP extractor) | github.com/nta/sfpack |
| SQLPAL internals | tomdu.github.io/2018/06/30/SQLPAL-and-Drawbridge/ |
| DrawBridge research repo | github.com/thinkcz/DrawBridge |
