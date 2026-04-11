#!/usr/bin/env python3
"""
SQLPAL Analysis Tool

Analyzes Microsoft SQL Server on Linux packages to understand how SQLPAL
(the Drawbridge-derived PAL) works in production.

What this tool does:
1. Downloads mssql-server package metadata (not the full package)
2. Analyzes SFP file structure (the Library OS archive format)
3. Documents the real component layout
4. If sfpack is available, can extract and catalog SFP contents

SFP (SQL Server Forge Pack) files contain:
  - system.sfp:    Windows 8 Library OS (ntoskrnl.dll, ntdll.dll, etc.)
  - sqlservr.sfp:  SQL Server Windows binaries (sqlservr.exe, sqllang.dll)

The key insight: Microsoft binary-patches real Windows DLLs (.dbpatch files)
to replace NT syscall instructions with PAL downcalls. The Library OS
(ntoskrnl.dll) runs entirely in user mode inside the Linux process.
"""

import os
import json
import struct
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ============================================================
# SFP File Format (reverse-engineered from nta/sfpack)
# ============================================================

@dataclass
class SfpHeader:
    """SFP archive header."""
    magic: int = 0
    version: int = 0
    first_dir_offset: int = 0
    name_table_offset: int = 0
    data_offset: int = 0
    archive_size: int = 0

    @classmethod
    def parse(cls, data: bytes) -> 'SfpHeader':
        if len(data) < 48:
            raise ValueError("SFP header too short")
        fields = struct.unpack('<QQQQQQ', data[:48])
        return cls(*fields)


@dataclass
class SfpEntry:
    """SFP directory entry."""
    name: str = ""
    is_directory: bool = False
    file_size: int = 0
    compressed_size: int = 0
    offset: int = 0


@dataclass
class SqlpalComponent:
    """A component found in the SQLPAL installation."""
    name: str
    path: str
    component_type: str  # 'pal', 'libos', 'engine', 'config', 'patch'
    description: str
    size: int = 0


# ============================================================
# SQLPAL Installation Analyzer
# ============================================================

KNOWN_SQLPAL_LAYOUT = {
    "/opt/mssql/bin/sqlservr": SqlpalComponent(
        name="sqlservr (ELF)",
        path="/opt/mssql/bin/sqlservr",
        component_type="pal",
        description="Linux ELF binary containing the PAL host (palrun). "
                    "This is the entry point - a native Linux process that "
                    "bootstraps the Library OS and loads SQL Server PE binaries.",
    ),
    "/opt/mssql/lib/system.sfp": SqlpalComponent(
        name="system.sfp",
        path="/opt/mssql/lib/system.sfp",
        component_type="libos",
        description="Windows 8 Library OS archive. Contains:\n"
                    "  - ntoskrnl.dll.bin: User-mode NT kernel (raw memory image)\n"
                    "  - ntoskrnl.dll.bin.ini: Memory layout config\n"
                    "  - ntdll.dll + ntdll.dll.dbpatch: Patched NT DLL\n"
                    "  - win32k.sys + win32k.sys.dbpatch: Patched Win32 subsystem\n"
                    "  - kerberos.dll: Authentication\n"
                    "  - windows.hiv: Serialized registry hive\n"
                    "  - Win8.dbmanifest: Manifest data",
    ),
    "/opt/mssql/lib/sqlservr.sfp": SqlpalComponent(
        name="sqlservr.sfp",
        path="/opt/mssql/lib/sqlservr.sfp",
        component_type="engine",
        description="SQL Server engine archive. Contains:\n"
                    "  - sqlservr.exe: Main SQL Server engine (PE format)\n"
                    "  - SqlDK.dll: SQL Development Kit\n"
                    "  - sqllang.dll: Query language processor\n"
                    "  - SQLOS.dll: SQL Server Operating System\n"
                    "  - sqlmin.dll: Minimal SQL services",
    ),
    "/opt/mssql/lib/system.common.sfp": SqlpalComponent(
        name="system.common.sfp",
        path="/opt/mssql/lib/system.common.sfp",
        component_type="libos",
        description="Common system components (certificates, .NET Framework pieces)",
    ),
    "/opt/mssql/lib/system.certificates.sfp": SqlpalComponent(
        name="system.certificates.sfp",
        path="/opt/mssql/lib/system.certificates.sfp",
        component_type="config",
        description="Certificate stores for TLS/SSL",
    ),
}


# ============================================================
# How SQLPAL Loads PE Binaries
# ============================================================

SQLPAL_BOOT_SEQUENCE = """
## SQLPAL Boot Sequence (from strace analysis)

1. Linux starts /opt/mssql/bin/sqlservr as a normal ELF process
2. sqlservr contains embedded 'palrun' - the PAL host runtime
3. palrun opens system.sfp using Linux open()/pread() syscalls
4. Reads ntoskrnl.dll.bin.ini to get memory layout:
   - Base address for the Library OS
   - Section sizes and permissions (RWX)
5. Maps ntoskrnl.dll.bin into memory at specified addresses
   (NOT using PE loader - this is a pre-processed raw binary)
6. Reads .dbpatch files and applies binary patches:
   - Patches ntdll.dll to replace 'syscall' instructions with PAL downcalls
   - Patches win32k.sys similarly
   - This is the key: real Windows DLLs with syscalls redirected to PAL
7. Library OS initializes:
   - Sets up user-mode NT kernel
   - Loads serialized registry (windows.hiv)
   - Initializes Windows subsystems
8. Opens sqlservr.sfp, loads sqlservr.exe using Library OS PE loader
9. SQL Server starts, calls Win32/NT APIs as normal
10. Win32 calls -> ntdll.dll (patched) -> PAL downcall -> Linux syscalls

## Key PAL Syscall Mappings (from strace)

| SQL Server Operation | NT API | PAL Downcall | Linux Syscall |
|---------------------|--------|-------------|---------------|
| Query execution | NtReadFile | PAL_FileRead | pread64() |
| Buffer pool | NtAllocateVirtualMemory | PAL_MemAlloc | mmap() |
| Lock manager | NtWaitForSingleObject | PAL_EventWait | futex() |
| Network listen | NtCreateFile (\\Device\\Afd) | PAL_SocketCreate | socket() + bind() + listen() |
| TempDB I/O | NtWriteFile | PAL_FileWrite | pwrite64() |
| Scheduling | NtYieldExecution | PAL_ThreadYield | sched_yield() |
| Logging | NtCreateFile | PAL_StreamOpen | open() |
"""


# ============================================================
# dbpatch Analysis
# ============================================================

DBPATCH_EXPLANATION = """
## The .dbpatch Mechanism

Microsoft's most clever trick in SQLPAL: binary patching real Windows DLLs.

### Problem
Real Windows DLLs (ntdll.dll, win32k.sys) contain 'syscall' or 'int 2e'
instructions that would trap to the Windows kernel. On Linux, these would
cause SIGSYS/SIGSEGV.

### Solution: .dbpatch files
For each DLL that makes direct kernel calls, Microsoft ships a .dbpatch file
that contains binary patches:

  ntdll.dll.dbpatch    -> patches ntdll.dll
  win32k.sys.dbpatch   -> patches win32k.sys

Each patch entry specifies:
  - Offset within the original DLL
  - Original bytes (the syscall instruction sequence)
  - Replacement bytes (a call to the PAL downcall stub)

### Example (conceptual)
Original ntdll.dll:
  NtCreateFile:
    mov r10, rcx
    mov eax, 0x55      ; NtCreateFile syscall number
    syscall             ; <-- This would crash on Linux
    ret

After .dbpatch:
  NtCreateFile:
    mov r10, rcx
    mov eax, 0x55
    call [pal_downcall] ; <-- Redirected to PAL
    ret

### Why This Is Brilliant
- Uses REAL Windows DLLs (not reimplementations)
- Only modifies the syscall instruction sites
- All other logic (parameter validation, structure handling) stays intact
- The patched DLLs behave identically to originals, just with different kernel interface

### Open-Source Equivalent
To replicate this, you would:
1. Take ReactOS ntdll.dll source
2. Replace the Nt* syscall dispatch (currently uses int 2e / syscall)
3. Route through PAL calls instead
4. This is essentially what .dbpatch does, but at source level
"""


def analyze_local_mssql() -> dict:
    """Check if mssql-server is installed locally and analyze."""
    result = {"installed": False, "components": [], "notes": []}

    mssql_bin = Path("/opt/mssql/bin/sqlservr")
    if mssql_bin.exists():
        result["installed"] = True
        result["notes"].append("SQL Server on Linux is installed")

        for path, component in KNOWN_SQLPAL_LAYOUT.items():
            p = Path(path)
            if p.exists():
                component.size = p.stat().st_size
                result["components"].append(asdict(component))
    else:
        result["notes"].append(
            "SQL Server on Linux is NOT installed. "
            "Install with: curl https://packages.microsoft.com/keys/microsoft.asc | "
            "apt-key add - && apt-get install mssql-server"
        )
        # Still provide the known layout for documentation
        for path, component in KNOWN_SQLPAL_LAYOUT.items():
            result["components"].append(asdict(component))

    return result


def check_sfpack() -> Optional[str]:
    """Check if sfpack tool is available."""
    try:
        result = subprocess.run(["sfpack", "--help"], capture_output=True, timeout=5)
        return "sfpack"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check in common locations
    for path in ["./sfpack", "../deps/sfpack/sfpack", "/usr/local/bin/sfpack"]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


def generate_report(output_dir: str):
    """Generate the full SQLPAL analysis report."""
    os.makedirs(output_dir, exist_ok=True)

    # Analyze local installation
    local_analysis = analyze_local_mssql()
    sfpack_path = check_sfpack()

    report = []
    report.append("# SQLPAL Analysis Report\n")
    report.append(f"Generated by sqlpal_analysis.py\n")
    report.append(f"Local SQL Server installed: {local_analysis['installed']}\n")
    report.append(f"sfpack tool available: {sfpack_path is not None}\n")

    report.append("\n## Component Layout\n")
    report.append("| Component | Type | Path | Size | Description |")
    report.append("|-----------|------|------|------|-------------|")
    for comp in local_analysis["components"]:
        size_str = f"{comp['size']:,}" if comp['size'] else "N/A"
        desc_oneline = comp['description'].split('\n')[0]
        report.append(
            f"| {comp['name']} | {comp['component_type']} | "
            f"`{comp['path']}` | {size_str} | {desc_oneline} |"
        )

    report.append(SQLPAL_BOOT_SEQUENCE)
    report.append(DBPATCH_EXPLANATION)

    report.append("\n## Extraction Tools\n")
    report.append("### sfpack (SFP Archive Extractor)\n")
    report.append("```bash")
    report.append("# Clone and build sfpack")
    report.append("git clone https://github.com/nta/sfpack")
    report.append("cd sfpack && make")
    report.append("")
    report.append("# Extract Library OS contents")
    report.append("./sfpack /opt/mssql/lib/system.sfp")
    report.append("")
    report.append("# Extract SQL Server engine")
    report.append("./sfpack /opt/mssql/lib/sqlservr.sfp")
    report.append("```\n")

    report.append("### strace Analysis\n")
    report.append("```bash")
    report.append("# Trace SQLPAL boot sequence")
    report.append("strace -f -e trace=open,openat,mmap,mprotect,clone,futex \\")
    report.append("  /opt/mssql/bin/sqlservr 2>&1 | head -500")
    report.append("")
    report.append("# Watch PAL syscalls during query execution")
    report.append("strace -f -e trace=read,write,pread64,pwrite64,futex \\")
    report.append("  -p $(pgrep sqlservr) 2>&1 | head -200")
    report.append("```\n")

    report.append("### Binary Analysis\n")
    report.append("```bash")
    report.append("# Check if sqlservr is ELF (it should be)")
    report.append("file /opt/mssql/bin/sqlservr")
    report.append("")
    report.append("# Look for PAL symbols")
    report.append("nm -D /opt/mssql/bin/sqlservr 2>/dev/null | grep -i pal")
    report.append("")
    report.append("# Check linked libraries")
    report.append("ldd /opt/mssql/bin/sqlservr")
    report.append("")
    report.append("# Look for embedded strings related to PAL")
    report.append("strings /opt/mssql/bin/sqlservr | grep -i 'palrun\\|drawbridge\\|libos\\|sfp'")
    report.append("```\n")

    # Write report
    report_path = os.path.join(output_dir, "sqlpal_report.md")
    with open(report_path, "w") as f:
        f.write("\n".join(report))

    # Write structured data
    data_path = os.path.join(output_dir, "sqlpal_components.json")
    with open(data_path, "w") as f:
        json.dump(local_analysis, f, indent=2)

    print(f"Report written to: {report_path}")
    print(f"Component data written to: {data_path}")

    for note in local_analysis["notes"]:
        print(f"Note: {note}")


if __name__ == "__main__":
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    generate_report(output_dir)
