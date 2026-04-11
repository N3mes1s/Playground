#!/bin/bash
#
# Extract the real PE loader from Wine
#
# Wine's PE loader is the most battle-tested open-source PE/COFF loader.
# It handles: PE parsing, section mapping, import resolution, relocations,
# TLS, exception handling, and DLL loading.
#
# Key Wine source files for PE loading:
#   dlls/ntdll/loader.c       - Main PE loader (LdrLoadDll, map_image)
#   dlls/ntdll/virtual.c      - Virtual memory management
#   tools/winebuild/          - PE build tools
#   loader/                   - Wine process loader
#   include/winternl.h        - NT internal structures
#   include/winnt.h           - PE structures (IMAGE_DOS_HEADER, etc.)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WINE_DIR="$PROJECT_DIR/deps/wine"
OUTPUT_DIR="$PROJECT_DIR/extracted/wine-pe-loader"

if [ ! -d "$WINE_DIR" ]; then
    echo "ERROR: Wine source not found at $WINE_DIR"
    echo "Run setup_environment.sh first"
    exit 1
fi

echo "Extracting Wine PE loader to $OUTPUT_DIR..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"/{pe-structures,pe-loader,virtual-memory,process-loader,headers}

# ---- 1. PE Structure Definitions ----
echo "  [1/5] PE structure definitions (winnt.h, winternl.h)..."

# These contain the real IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, etc.
for header in winnt.h winternl.h winbase.h windef.h; do
    if [ -f "$WINE_DIR/include/$header" ]; then
        cp "$WINE_DIR/include/$header" "$OUTPUT_DIR/headers/"
    fi
done

# PE-specific headers
for header in pshpack1.h pshpack2.h pshpack4.h pshpack8.h poppack.h; do
    if [ -f "$WINE_DIR/include/$header" ]; then
        cp "$WINE_DIR/include/$header" "$OUTPUT_DIR/headers/"
    fi
done

# ---- 2. PE Loader Core (ntdll/loader.c) ----
echo "  [2/5] PE loader core (ntdll loader)..."

# The main PE loader - this is the real thing
if [ -d "$WINE_DIR/dlls/ntdll" ]; then
    for src in loader.c virtual.c process.c thread.c env.c; do
        if [ -f "$WINE_DIR/dlls/ntdll/$src" ]; then
            cp "$WINE_DIR/dlls/ntdll/$src" "$OUTPUT_DIR/pe-loader/"
        fi
    done

    # ntdll internal headers
    for hdr in ntdll_misc.h; do
        if [ -f "$WINE_DIR/dlls/ntdll/$hdr" ]; then
            cp "$WINE_DIR/dlls/ntdll/$hdr" "$OUTPUT_DIR/pe-loader/"
        fi
    done

    # Unix-side loader (this is where Linux integration happens)
    if [ -d "$WINE_DIR/dlls/ntdll/unix" ]; then
        mkdir -p "$OUTPUT_DIR/pe-loader/unix"
        for src in loader.c virtual.c process.c thread.c signal_x86_64.c; do
            if [ -f "$WINE_DIR/dlls/ntdll/unix/$src" ]; then
                cp "$WINE_DIR/dlls/ntdll/unix/$src" "$OUTPUT_DIR/pe-loader/unix/"
            fi
        done
        for hdr in unix_private.h; do
            if [ -f "$WINE_DIR/dlls/ntdll/unix/$hdr" ]; then
                cp "$WINE_DIR/dlls/ntdll/unix/$hdr" "$OUTPUT_DIR/pe-loader/unix/"
            fi
        done
    fi
fi

# ---- 3. Virtual Memory Layer ----
echo "  [3/5] Virtual memory management..."

if [ -d "$WINE_DIR/dlls/ntdll/unix" ]; then
    for src in virtual.c; do
        if [ -f "$WINE_DIR/dlls/ntdll/unix/$src" ]; then
            cp "$WINE_DIR/dlls/ntdll/unix/$src" "$OUTPUT_DIR/virtual-memory/" 2>/dev/null || true
        fi
    done
fi

# ---- 4. Wine Process Loader ----
echo "  [4/5] Wine process loader..."

if [ -d "$WINE_DIR/loader" ]; then
    for src in main.c preloader.c; do
        if [ -f "$WINE_DIR/loader/$src" ]; then
            cp "$WINE_DIR/loader/$src" "$OUTPUT_DIR/process-loader/"
        fi
    done
fi

# ---- 5. PE Structure Reference ----
echo "  [5/5] Generating PE structure reference..."

cat > "$OUTPUT_DIR/PE_LOADER_COMPONENTS.md" << 'PEEOF'
# Wine PE Loader - Extracted Components

## Key Files and Their Roles

### PE Structure Definitions (`headers/`)
- `winnt.h` - IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER,
  IMAGE_IMPORT_DESCRIPTOR, IMAGE_BASE_RELOCATION, etc.
- `winternl.h` - NT internal types (PEB, TEB, LDR_DATA_TABLE_ENTRY)

### PE Loader Core (`pe-loader/`)
- `loader.c` - **The main PE loader**. Key functions:
  - `LdrLoadDll()` - Top-level DLL load
  - `map_image()` - Map PE sections into memory
  - `fixup_imports()` - Resolve import address table (IAT)
  - `perform_relocations()` - Apply base relocations
  - `attach_dlls()` - Call DllMain for loaded DLLs
  - `process_attach()` - Process initialization

- `pe-loader/unix/loader.c` - **Linux-side PE loading**:
  - `load_pe_image()` - Load PE from file into memory
  - `map_pe_module()` - mmap PE sections with correct permissions
  - `virtual_map_image()` - Map PE image with relocations
  - This is where Wine bridges PE loading with Linux mmap/mprotect

### Virtual Memory (`virtual-memory/`)
- `virtual.c` - Memory management:
  - Maps PE sections to Linux mmap regions
  - Handles PAGE_EXECUTE_READ, PAGE_READWRITE, etc.
  - Manages memory regions for the PE image

### Process Loader (`process-loader/`)
- `preloader.c` - Reserves address space for PE images
- `main.c` - Wine's entry point, initializes the PE environment

## How Wine's PE Loader Works

1. **Parse PE headers**: Read DOS header -> PE signature -> COFF header -> Optional header
2. **Map sections**: For each section (.text, .data, .rdata, .bss):
   - Calculate virtual address and size
   - mmap with correct Linux permissions
   - Copy section data from file
3. **Process relocations**: If image loaded at non-preferred base:
   - Walk relocation table
   - Apply delta to each relocation entry
   - Support HIGHLOW (32-bit) and DIR64 (64-bit) relocations
4. **Resolve imports**: For each imported DLL:
   - Find the DLL (or our PAL-backed stub)
   - Walk the Import Lookup Table
   - Resolve each function by name or ordinal
   - Write resolved addresses to Import Address Table
5. **Initialize TLS**: Set up thread-local storage
6. **Call entry point**: Transfer control to PE's AddressOfEntryPoint

## Integration Points for Drawbridge PoC

To use Wine's PE loader with Gramine's PAL instead of Wine's own infrastructure:

1. Replace Wine's memory management (NtAllocateVirtualMemory) with
   Gramine's PalVirtualMemoryAlloc
2. Replace Wine's file I/O with Gramine's PalStreamOpen/Read/Write
3. Replace DLL resolution to load ReactOS DLLs instead of Wine's
4. The PE parsing and relocation logic stays unchanged
PEEOF

FILE_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l)
echo ""
echo "=== Extraction complete ==="
echo "  Output: $OUTPUT_DIR"
echo "  Files:  $FILE_COUNT"
echo "  Key file: $OUTPUT_DIR/PE_LOADER_COMPONENTS.md"
