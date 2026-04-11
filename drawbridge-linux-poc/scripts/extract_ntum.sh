#!/bin/bash
#
# Extract the NT User-Mode Kernel (NTUM) from SQL Server on Linux
#
# This script:
#   1. Installs mssql-server package (download only, or uses existing)
#   2. Builds sfpack (SFP archive extractor)
#   3. Extracts system.sfp -> gets ntoskrnl.dll.bin, ntdll.dll, .dbpatch files
#   4. Extracts sqlservr.sfp -> gets sqlservr.exe and supporting DLLs
#   5. Catalogs all extracted components
#
# The NTUM is the core of Drawbridge's Library OS - a real Windows kernel
# running entirely in user mode. It's inside system.sfp.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$PROJECT_DIR/tools"
EXTRACTED_DIR="$PROJECT_DIR/extracted/ntum"

log() { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "[$(date +%H:%M:%S)] WARNING: $*"; }
err() { echo "[$(date +%H:%M:%S)] ERROR: $*" >&2; }

mkdir -p "$TOOLS_DIR" "$EXTRACTED_DIR"

# ============================================================
# Step 1: Build sfpack (SFP archive extractor)
# ============================================================
build_sfpack() {
    log "=== Building sfpack ==="

    if [ -x "$TOOLS_DIR/sfpack/sfpack" ]; then
        log "sfpack already built"
        return 0
    fi

    if ! command -v g++ &>/dev/null; then
        err "g++ not found. Install with: apt install g++"
        return 1
    fi

    cd "$TOOLS_DIR"
    if [ ! -d sfpack ]; then
        log "Cloning sfpack..."
        git clone https://github.com/nta/sfpack.git sfpack
    fi

    cd sfpack
    log "Building sfpack..."
    make clean 2>/dev/null || true
    make

    if [ -x "./sfpack" ]; then
        log "sfpack built successfully"
    else
        # Fallback: try manual compile
        log "Make failed, trying manual compilation..."
        g++ -std=c++17 -O2 -o sfpack sfpack.cpp 2>/dev/null || \
        g++ -std=c++14 -O2 -o sfpack sfpack.cpp 2>/dev/null || \
        g++ -O2 -o sfpack sfpack.cpp
    fi
}

# ============================================================
# Step 2: Locate or download mssql-server SFP files
# ============================================================
locate_sfp_files() {
    log "=== Locating SFP files ==="

    SFP_DIR=""

    # Check if mssql-server is installed
    if [ -d "/opt/mssql/lib" ]; then
        log "Found mssql-server installation at /opt/mssql"
        SFP_DIR="/opt/mssql/lib"
        return 0
    fi

    # Check if we already downloaded them
    if [ -f "$EXTRACTED_DIR/sfp-raw/system.sfp" ]; then
        log "Found previously downloaded SFP files"
        SFP_DIR="$EXTRACTED_DIR/sfp-raw"
        return 0
    fi

    # Try to download just the package
    log "mssql-server not installed. Attempting to download package..."
    mkdir -p "$EXTRACTED_DIR/sfp-raw"

    # Method 1: apt download (if Microsoft repo is configured)
    if apt-cache show mssql-server &>/dev/null 2>&1; then
        log "Downloading mssql-server .deb package..."
        cd "$EXTRACTED_DIR/sfp-raw"
        apt download mssql-server 2>/dev/null || true
        if ls mssql-server*.deb 1>/dev/null 2>&1; then
            log "Extracting SFP files from .deb..."
            dpkg-deb -x mssql-server*.deb ./deb-contents/
            if [ -d ./deb-contents/opt/mssql/lib ]; then
                cp ./deb-contents/opt/mssql/lib/*.sfp . 2>/dev/null || true
                SFP_DIR="$EXTRACTED_DIR/sfp-raw"
                return 0
            fi
        fi
    fi

    # Method 2: Direct download from Microsoft
    log "Trying direct download from Microsoft packages..."
    local MSSQL_URL="https://packages.microsoft.com/ubuntu/22.04/mssql-server-2022/pool/main/m/mssql-server/"

    # Try to find the latest package URL
    if command -v curl &>/dev/null; then
        local PKG_NAME
        PKG_NAME=$(curl -sL "$MSSQL_URL" 2>/dev/null | grep -oP 'mssql-server_[^"]+\.deb' | sort -V | tail -1) || true
        if [ -n "$PKG_NAME" ]; then
            log "Downloading $PKG_NAME..."
            cd "$EXTRACTED_DIR/sfp-raw"
            curl -LO "${MSSQL_URL}${PKG_NAME}" 2>/dev/null || true
            if [ -f "$PKG_NAME" ]; then
                dpkg-deb -x "$PKG_NAME" ./deb-contents/ 2>/dev/null
                if [ -d ./deb-contents/opt/mssql/lib ]; then
                    cp ./deb-contents/opt/mssql/lib/*.sfp . 2>/dev/null || true
                    SFP_DIR="$EXTRACTED_DIR/sfp-raw"
                    return 0
                fi
            fi
        fi
    fi

    warn "Could not locate or download SFP files."
    warn "Install mssql-server manually:"
    warn "  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/microsoft.gpg"
    warn "  echo 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/mssql-server-2022 jammy main' > /etc/apt/sources.list.d/mssql-server.list"
    warn "  apt update && apt download mssql-server"
    warn "Then re-run this script."
    return 1
}

# ============================================================
# Step 3: Extract SFP files
# ============================================================
extract_sfp_files() {
    log "=== Extracting SFP archives ==="

    local SFPACK="$TOOLS_DIR/sfpack/sfpack"
    if [ ! -x "$SFPACK" ]; then
        err "sfpack not found. Build it first."
        return 1
    fi

    mkdir -p "$EXTRACTED_DIR"/{system-libos,sqlserver-engine,all-dlls}

    # Extract system.sfp (Library OS - contains NTUM)
    if [ -f "$SFP_DIR/system.sfp" ]; then
        log "Extracting system.sfp (Library OS / NTUM)..."
        cd "$EXTRACTED_DIR/system-libos"
        "$SFPACK" "$SFP_DIR/system.sfp" 2>&1 || {
            warn "sfpack extraction failed, trying alternate approaches..."
            # sfpack might need different invocation
            "$SFPACK" -x "$SFP_DIR/system.sfp" 2>&1 || true
        }
        log "system.sfp contents:"
        find . -type f | head -50
    else
        warn "system.sfp not found in $SFP_DIR"
    fi

    # Extract sqlservr.sfp (SQL Server engine)
    if [ -f "$SFP_DIR/sqlservr.sfp" ]; then
        log "Extracting sqlservr.sfp (SQL Server engine)..."
        cd "$EXTRACTED_DIR/sqlserver-engine"
        "$SFPACK" "$SFP_DIR/sqlservr.sfp" 2>&1 || true
        log "sqlservr.sfp contents:"
        find . -type f | head -50
    else
        warn "sqlservr.sfp not found in $SFP_DIR"
    fi

    # Extract other SFP files
    for sfp in "$SFP_DIR"/*.sfp; do
        local basename
        basename=$(basename "$sfp" .sfp)
        if [ "$basename" != "system" ] && [ "$basename" != "sqlservr" ]; then
            log "Extracting $basename.sfp..."
            mkdir -p "$EXTRACTED_DIR/extra/$basename"
            cd "$EXTRACTED_DIR/extra/$basename"
            "$SFPACK" "$sfp" 2>&1 || true
        fi
    done
}

# ============================================================
# Step 4: Catalog extracted components
# ============================================================
catalog_components() {
    log "=== Cataloging extracted NTUM components ==="

    local CATALOG="$EXTRACTED_DIR/NTUM_CATALOG.md"

    cat > "$CATALOG" << 'CATEOF'
# Extracted NTUM Components

## From system.sfp (Library OS)

These are the real Windows components that make up the NT User-Mode Kernel:

### Core NTUM
| File | Description |
|------|-------------|
| `ntoskrnl.dll.bin` | User-mode NT kernel (raw memory image, NOT standard PE) |
| `ntoskrnl.dll.bin.ini` | Memory layout: base address, section sizes, permissions |
| `ntdll.dll` | NT native API DLL (real Windows binary) |
| `ntdll.dll.dbpatch` | Binary patches to redirect syscalls to PAL |
| `win32k.sys` | Win32 kernel subsystem (window manager, GDI) |
| `win32k.sys.dbpatch` | Binary patches for win32k |

### Supporting DLLs
| File | Description |
|------|-------------|
| `kerberos.dll` | Kerberos authentication |
| `msv1_0.dll` | NTLM authentication provider |
| `schannel.dll` | TLS/SSL provider |
| `crypt32.dll` | Cryptographic services |
| `bcrypt.dll` | BCrypt primitives |
| `ncrypt.dll` | CNG key storage |

### Configuration
| File | Description |
|------|-------------|
| `windows.hiv` | Serialized Windows registry hive |
| `Win8.dbmanifest` | Drawbridge manifest (component versions) |
| `.bin.ini` files | Memory layout configs for raw binary images |

## Key Files for Reverse Engineering

### ntoskrnl.dll.bin
This is NOT a standard PE file. It's a pre-processed raw binary image
that gets loaded directly into memory at addresses specified in the
.bin.ini file. To analyze:

```bash
# Check if it has PE headers anyway
file ntoskrnl.dll.bin
hexdump -C ntoskrnl.dll.bin | head -20

# Look for the .ini file that describes memory layout
cat ntoskrnl.dll.bin.ini
```

### .dbpatch files
These contain binary patches applied to Windows DLLs. Format:
- Offset within original DLL
- Original bytes (syscall instruction)
- Replacement bytes (PAL downcall)

To analyze:
```bash
# Dump patch entries
hexdump -C ntdll.dll.dbpatch | head -100

# Compare original vs patched
python3 ../reversing/dbpatch_analyzer.py ntdll.dll ntdll.dll.dbpatch
```

### PAL Downcall Interface
The .dbpatch replacements call into the PAL via a downcall mechanism.
To reverse-engineer the PAL interface:

```bash
# Disassemble patched ntdll and look for PAL calls
python3 ../reversing/pal_downcall_mapper.py ntdll.dll ntdll.dll.dbpatch
```
CATEOF

    # List all extracted files with sizes
    echo "" >> "$CATALOG"
    echo "## All Extracted Files" >> "$CATALOG"
    echo "" >> "$CATALOG"
    echo '```' >> "$CATALOG"
    if [ -d "$EXTRACTED_DIR/system-libos" ]; then
        find "$EXTRACTED_DIR/system-libos" -type f -exec ls -lh {} \; 2>/dev/null >> "$CATALOG" || true
    fi
    if [ -d "$EXTRACTED_DIR/sqlserver-engine" ]; then
        find "$EXTRACTED_DIR/sqlserver-engine" -type f -exec ls -lh {} \; 2>/dev/null >> "$CATALOG" || true
    fi
    echo '```' >> "$CATALOG"

    log "Catalog written to: $CATALOG"
}

# ============================================================
# Step 5: Analyze the ELF sqlservr binary for PAL symbols
# ============================================================
analyze_pal_binary() {
    log "=== Analyzing PAL binary ==="

    local SQLSERVR="/opt/mssql/bin/sqlservr"
    local ANALYSIS="$EXTRACTED_DIR/pal_binary_analysis.md"

    if [ ! -f "$SQLSERVR" ]; then
        warn "sqlservr binary not found, skipping PAL binary analysis"
        return 0
    fi

    cat > "$ANALYSIS" << EOF
# PAL Binary Analysis

## File Info
$(file "$SQLSERVR" 2>/dev/null || echo "N/A")

## Size
$(ls -lh "$SQLSERVR" 2>/dev/null | awk '{print $5}' || echo "N/A")

## Dynamic Libraries
$(ldd "$SQLSERVR" 2>/dev/null || echo "N/A - static or not accessible")

## PAL-Related Symbols
$(nm -D "$SQLSERVR" 2>/dev/null | grep -iE 'pal|drawbridge|libos|picoprocess|sfp' | head -100 || echo "No PAL symbols in dynamic symbol table")

## All Exported Symbols (first 200)
$(nm -D "$SQLSERVR" 2>/dev/null | head -200 || echo "N/A")

## PAL-Related Strings
$(strings "$SQLSERVR" 2>/dev/null | grep -iE 'pal|drawbridge|libos|picoprocess|sfp|ntoskrnl|ntdll|dbpatch' | sort -u | head -100 || echo "N/A")

## Memory Map Strings (related to .bin.ini loading)
$(strings "$SQLSERVR" 2>/dev/null | grep -iE '\.bin\.ini|\.sfp|\.dbpatch|\.hiv|manifest' | sort -u | head -50 || echo "N/A")
EOF

    log "PAL binary analysis written to: $ANALYSIS"
}

# ============================================================
# Main
# ============================================================

log "====================================="
log "NTUM Extraction from SQL Server Linux"
log "====================================="

build_sfpack || { warn "sfpack build failed, continuing with what we have..."; }
locate_sfp_files || { warn "SFP files not found, generating documentation only..."; }

if [ -n "${SFP_DIR:-}" ]; then
    extract_sfp_files
fi

catalog_components
analyze_pal_binary

log ""
log "=== Extraction complete ==="
log "Output: $EXTRACTED_DIR"
log ""
log "Next steps:"
log "  1. Review NTUM_CATALOG.md"
log "  2. Run reversing tools: python3 reversing/dbpatch_analyzer.py"
log "  3. Map PAL downcall interface: python3 reversing/pal_downcall_mapper.py"
