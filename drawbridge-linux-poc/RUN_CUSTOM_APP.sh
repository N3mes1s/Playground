#!/bin/bash
#
# Run a custom Windows EXE through the real SQLPAL NTUM on Linux
#
# Usage: ./RUN_CUSTOM_APP.sh <path-to-windows.exe>
#
# This uses Microsoft's real Drawbridge stack:
# - sqlpal.dll (2.7MB NTUM kernel, 1407 exports)
# - 62 real Windows DLLs from system.common.sfp
# - ntdll.dll, advapi32, crypt32, gdi32, combase, etc.
# - Full CLR (.NET) support
#

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path-to-windows-64bit.exe> [args...]"
    echo ""
    echo "Runs a Windows PE64 executable on Linux using the real"
    echo "Drawbridge/SQLPAL stack from SQL Server."
    echo ""
    echo "Requirements: mssql-server extracted at deps/mssql-extracted/"
    echo "The EXE must be x86-64 PE32+ (64-bit)."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MSSQL_DIR="$SCRIPT_DIR/deps/mssql-extracted"
SQLSERVR="$MSSQL_DIR/opt/mssql/bin/sqlservr"
PKG_DIR="$MSSQL_DIR/opt/mssql/lib/sqlservr"
TARGET_EXE="$(realpath "$1")"
shift

# Check prereqs
if [ ! -f "$SQLSERVR" ]; then
    echo "ERROR: mssql-server not extracted. Run:"
    echo "  mkdir -p deps/mssql-extracted && cd deps/mssql-extracted"
    echo "  dpkg-deb -x ../mssql-pkg/mssql-server_*.deb ."
    exit 1
fi

if [ ! -d "$PKG_DIR" ]; then
    echo "ERROR: sqlservr.sfp not extracted. Run:"
    echo "  cd deps/mssql-extracted && ../sfpack/sfpack opt/mssql/lib/sqlservr.sfp"
    exit 1
fi

# Replace sqlservr.exe with our target
cp "$TARGET_EXE" "$PKG_DIR/Content/binn/sqlservr.exe"
echo "[DRAWBRIDGE] Loaded: $TARGET_EXE"
echo "[DRAWBRIDGE] Booting NTUM..."

# Required system settings
ulimit -d unlimited 2>/dev/null

# Run through the real SQLPAL NTUM
export LD_LIBRARY_PATH="$MSSQL_DIR/opt/mssql/lib:$LD_LIBRARY_PATH"
export ACCEPT_EULA=Y
export PAL_OVERRIDE_PACKAGES="sqlservr=$PKG_DIR"

exec "$SQLSERVR" "$@"
