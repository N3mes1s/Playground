# Real NTUM Findings - Extracted from mssql-server 16.0.4245.2

## Architecture Confirmed

The real SQLPAL architecture, confirmed by extraction:

```
sqlservr (ELF, 2.5MB)        <-- Linux PAL host (AbiHost)
    |
    +-- Opens system.sfp (13MB)
    |     +-- sqlpal.dll (2.7MB, 1407 exports) <-- NTUM kernel!
    |     +-- DkDll.dll (35KB, 10 exports)     <-- Dk PAL bridge
    |     +-- AppLoader.exe (112KB)            <-- PE application loader
    |     +-- vcruntime140.dll, msvcp140.dll   <-- Real MSVC runtime
    |     +-- windows.hiv                      <-- Registry hive
    |     +-- Afd.sys, ndis.sys, netio.sys     <-- Network drivers
    |
    +-- Opens sqlservr.sfp (566MB)
          +-- sqlservr.exe                     <-- SQL Server engine (PE)
          +-- SqlDK.dll, sqllang.dll, etc.
```

## Key Discovery: package.manifest

```ini
[OS Entry Point]
StartModule=file://windows/system32/sqlpal.dll

[Registry Hives]
hive1=file://windows/windows.hiv
hive2=file://windows/ipv6.hiv
hive3=file://windows/msdtc.hiv
```

**sqlpal.dll IS the entry point** - not ntoskrnl.dll.bin as previously assumed.

## sqlpal.dll = The NTUM Kernel

- 2.7MB PE32+ DLL (native, x86-64)
- **1407 exported functions** including:
  - 345 Nt/Zw functions (full NT syscall surface)
  - 235 Rtl functions (runtime library)
  - 121 Ex functions (executive)
  - 119 Ps functions (process/thread)
  - 114 Io functions (I/O manager)
  - 113 Ke functions (kernel core)
  - 53 Mm functions (memory manager)
  - 44 Se functions (security)
  - 35 Ob functions (object manager)

This is a **real user-mode Windows kernel** - it implements:
- NtCreateFile, NtReadFile, NtWriteFile
- NtAllocateVirtualMemory, NtFreeVirtualMemory
- NtCreateEvent, NtWaitForSingleObject
- NtCreateSection, NtMapViewOfSection
- Full process/thread management
- Registry operations (NtCreateKey, NtQueryValueKey)
- Security (NtOpenProcessToken, NtDuplicateToken)

## DkDll.dll = Drawbridge PAL Bridge

10 exports - the thin PAL interface to the host:
- DBEtwPrint (debug tracing)
- NtCreateSwitchTebEvent
- NtGenerateRandomData
- NtGetEnclaveAttestationReport
- NtGetExternalPid
- NtMapViewOfFileExNumaProtection
- NtReportUnimplemented
- NtServiceSwitchTeb
- NtSwitchPowerSavingMode
- NtSwitchTeb

## ELF sqlservr = The Linux PAL Host

Source paths revealed by strings:
```
/mnt/vss/_work/1/s/sqlpal/UtilLibs/AbiHost/BinaryPeParser.cpp
/mnt/vss/_work/1/s/sqlpal/UtilLibs/AbiHost/PalMemoryMapPeBinary.cpp
/mnt/vss/_work/1/s/sqlpal/UtilLibs/AbiHost/VfsStream.cpp
/mnt/vss/_work/1/s/sqlpal/UtilLibs/AbiHost/ObjectManager.cpp
```

Key components inside the ELF:
- **BinaryPeParser** - Parses and loads PE binaries
- **PalMemoryMapPeBinary** - Maps PE sections into memory
- **VfsStream** - Virtual filesystem for stream I/O
- **ObjectManager** - Windows-style object management
- **ImagePageProtector** - Memory protection for PE images

Boot messages:
- `LoadPeBinary failed. File: %s. ErrorCode: %d.`
- `Error loading guest (%s): %x`
- `Parsing LibOS regions`
- `Processing modules loaded in LibOs`
- `BOOT: FATAL: Incompatible ABI:`

## How It Actually Boots

1. Linux starts `sqlservr` (ELF)
2. ELF opens `system.sfp`, reads `package.manifest`
3. Reads `[OS Entry Point] StartModule=sqlpal.dll`
4. Loads `sqlpal.dll` (the NTUM) into memory using `PalMemoryMapPeBinary`
5. Loads registry hives (`windows.hiv`, `ipv6.hiv`, `msdtc.hiv`)
6. NTUM initializes: kernel objects, security, I/O
7. Loads `AppLoader.exe` which loads the target app
8. DkDll.dll provides the thin PAL bridge for specific operations
9. Stream I/O mapped: `stdin:=stdin:`, `stdout:=stdout:`, etc.

## No .dbpatch Files!

Contrary to earlier research, the modern SQLPAL (2022/2024) does NOT use
.dbpatch files. Instead, `sqlpal.dll` IS the complete NTUM kernel - it
already implements all Nt* functions internally without needing to patch
a separate ntdll.dll.

The older Drawbridge (pre-2020) used ntoskrnl.dll.bin + .dbpatch.
The modern approach compiles everything into sqlpal.dll directly.
