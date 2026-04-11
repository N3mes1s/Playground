#!/bin/bash
#
# Drawbridge Linux PoC - Environment Setup
#
# Downloads and prepares real components from:
#   - Gramine (PAL implementation)
#   - Wine (PE loader)
#   - ReactOS (Windows DLL implementations)
#
# Usage: ./setup_environment.sh [--skip-gramine] [--skip-wine] [--skip-reactos]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPS_DIR="$PROJECT_DIR/deps"
EXTRACTED_DIR="$PROJECT_DIR/extracted"

# Component versions
GRAMINE_VERSION="v1.8"
WINE_VERSION="wine-9.0"
REACTOS_VERSION="0.4.15-dev"

SKIP_GRAMINE=false
SKIP_WINE=false
SKIP_REACTOS=false

for arg in "$@"; do
    case $arg in
        --skip-gramine) SKIP_GRAMINE=true ;;
        --skip-wine)    SKIP_WINE=true ;;
        --skip-reactos) SKIP_REACTOS=true ;;
        --help)
            echo "Usage: $0 [--skip-gramine] [--skip-wine] [--skip-reactos]"
            exit 0
            ;;
    esac
done

log() { echo "[$(date +%H:%M:%S)] $*"; }

mkdir -p "$DEPS_DIR" "$EXTRACTED_DIR"

# ============================================================
# 1. GRAMINE - Real PAL Implementation
# ============================================================
if [ "$SKIP_GRAMINE" = false ]; then
    log "=== Downloading Gramine (PAL source) ==="

    if [ ! -d "$DEPS_DIR/gramine" ]; then
        git clone --depth 1 --branch "$GRAMINE_VERSION" \
            https://github.com/gramineproject/gramine.git \
            "$DEPS_DIR/gramine" 2>/dev/null || \
        git clone --depth 1 \
            https://github.com/gramineproject/gramine.git \
            "$DEPS_DIR/gramine"
    else
        log "Gramine already downloaded, skipping"
    fi

    log "Extracting PAL components..."
    bash "$PROJECT_DIR/extraction/extract_gramine_pal.sh"
fi

# ============================================================
# 2. WINE - Real PE Loader
# ============================================================
if [ "$SKIP_WINE" = false ]; then
    log "=== Downloading Wine (PE loader source) ==="

    if [ ! -d "$DEPS_DIR/wine" ]; then
        # Wine is large - shallow clone just the loader-relevant parts
        git clone --depth 1 --branch "$WINE_VERSION" \
            https://gitlab.winehq.org/wine/wine.git \
            "$DEPS_DIR/wine" 2>/dev/null || \
        git clone --depth 1 \
            https://github.com/wine-mirror/wine.git \
            "$DEPS_DIR/wine"
    else
        log "Wine already downloaded, skipping"
    fi

    log "Extracting PE loader components..."
    bash "$PROJECT_DIR/extraction/extract_wine_loader.sh"
fi

# ============================================================
# 3. REACTOS - Real Windows DLL Implementations
# ============================================================
if [ "$SKIP_REACTOS" = false ]; then
    log "=== Downloading ReactOS (Windows DLL source) ==="

    if [ ! -d "$DEPS_DIR/reactos" ]; then
        # ReactOS is very large - we only need dll/ directory
        git clone --depth 1 --filter=blob:none --sparse \
            https://github.com/nicedreams/reactos.git \
            "$DEPS_DIR/reactos" 2>/dev/null && \
        (cd "$DEPS_DIR/reactos" && git sparse-checkout set dll/win32/kernel32 dll/ntdll dll/crt/msvcrt) || \
        log "WARNING: ReactOS sparse checkout failed, trying full clone..."
        git clone --depth 1 \
            https://github.com/nicedreams/reactos.git \
            "$DEPS_DIR/reactos" 2>/dev/null || true
    else
        log "ReactOS already downloaded, skipping"
    fi

    log "Extracting DLL components..."
    bash "$PROJECT_DIR/extraction/extract_reactos_dlls.sh"
fi

# ============================================================
# 4. Check for build dependencies
# ============================================================
log "=== Checking build dependencies ==="

check_cmd() {
    if command -v "$1" &>/dev/null; then
        log "  [OK] $1"
        return 0
    else
        log "  [MISSING] $1 - install with: $2"
        return 1
    fi
}

MISSING=0
check_cmd gcc "apt install build-essential" || MISSING=$((MISSING+1))
check_cmd x86_64-w64-mingw32-gcc "apt install gcc-mingw-w64-x86-64" || MISSING=$((MISSING+1))
check_cmd python3 "apt install python3" || MISSING=$((MISSING+1))
check_cmd meson "pip install meson" || MISSING=$((MISSING+1))
check_cmd ninja "apt install ninja-build" || MISSING=$((MISSING+1))

if [ $MISSING -gt 0 ]; then
    log ""
    log "WARNING: $MISSING dependencies missing. Install them before building."
fi

log ""
log "=== Setup complete ==="
log "Extracted components in: $EXTRACTED_DIR"
log ""
log "Next steps:"
log "  1. Review extracted components in $EXTRACTED_DIR/"
log "  2. Build the integration layer: make"
log "  3. Run test: ./drawbridge-run test/hello_win.exe"
