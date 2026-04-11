#!/bin/bash
#
# Build Shim DLLs for Drawbridge
#
# Creates minimal Win32 DLLs that export the functions malware needs.
# These are built from simplified ReactOS source code + our PAL stubs.
#
# Usage: ./build_shim_dlls.sh [32|64]
#
# Output: dlls/ directory with .dll files
#

set -e

ARCH="${1:-32}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REACTOS="$SCRIPT_DIR/../deps/reactos"
OUTPUT="$SCRIPT_DIR/dlls"
mkdir -p "$OUTPUT"

if [ "$ARCH" = "32" ]; then
    CC=i686-w64-mingw32-gcc
    CFLAGS="-shared -O2 -Wall -Wno-unused-parameter"
    echo "[BUILD] Building 32-bit shim DLLs..."
else
    CC=x86_64-w64-mingw32-gcc
    CFLAGS="-shared -O2 -Wall -Wno-unused-parameter"
    echo "[BUILD] Building 64-bit shim DLLs..."
fi

# Include paths from ReactOS
INCLUDES="-I$REACTOS/sdk/include/psdk \
          -I$REACTOS/sdk/include/ndk \
          -I$REACTOS/sdk/include/reactos \
          -I$REACTOS/sdk/include/crt \
          -I$REACTOS/sdk/include"

echo ""

#
# 1. Build msvcrt.dll shim (C runtime - needed by almost everything)
#
echo "[BUILD] msvcrt.dll shim..."
cat > /tmp/msvcrt_shim.c << 'CEOF'
#include <stddef.h>
#include <stdarg.h>

#define EXPORT __declspec(dllexport)

/* Minimal C runtime exports that malware needs */

/* Memory */
EXPORT void *malloc(size_t size);
EXPORT void *calloc(size_t n, size_t size);
EXPORT void *realloc(void *ptr, size_t size);
EXPORT void free(void *ptr);

/* String */
EXPORT size_t strlen(const char *s);
EXPORT char *strcpy(char *d, const char *s);
EXPORT char *strcat(char *d, const char *s);
EXPORT int strcmp(const char *a, const char *b);
EXPORT int strncmp(const char *a, const char *b, size_t n);
EXPORT void *memset(void *s, int c, size_t n);
EXPORT void *memcpy(void *d, const void *s, size_t n);
EXPORT void *memmove(void *d, const void *s, size_t n);

/* I/O */
EXPORT int puts(const char *s);
EXPORT int printf(const char *fmt, ...);
EXPORT int fprintf(void *stream, const char *fmt, ...);
EXPORT int sprintf(char *buf, const char *fmt, ...);

/* Process */
EXPORT void exit(int status);
EXPORT void _exit(int status);
EXPORT void abort(void);
EXPORT int atexit(void (*func)(void));

/* Random */
EXPORT int rand(void);
EXPORT void srand(unsigned int seed);

/* Time */
EXPORT long long time(long long *t);

/* CRT init */
EXPORT void _initterm(void **start, void **end);
EXPORT int _initterm_e(void **start, void **end);

/* CRT internals that malware references */
static int dummy_fmode = 0;
EXPORT int *__p__fmode(void) { return &dummy_fmode; }
EXPORT int *_errno(void) { static int e = 0; return &e; }

static int dummy_argc = 0;
static char *dummy_argv_data[] = {"program.exe", NULL};
static char **dummy_argv = dummy_argv_data;
static char *dummy_env[] = {NULL};

EXPORT int __getmainargs(int *argc, char ***argv, char ***env, int dowildcard, void *startinfo) {
    (void)dowildcard; (void)startinfo;
    *argc = 1;
    *argv = dummy_argv;
    *env = dummy_env;
    return 0;
}

EXPORT void __set_app_type(int type) { (void)type; }
EXPORT int *__p___argc(void) { return &dummy_argc; }
EXPORT char ***__p___argv(void) { return &dummy_argv; }
EXPORT char ***__p__environ(void) { return &dummy_env; }

/* File I/O stubs */
typedef void FILE;
static char iob_buf[3 * 64]; /* fake stdin/stdout/stderr */
EXPORT FILE *__iob_func(void) { return (FILE*)iob_buf; }
EXPORT void *_iob = iob_buf;
EXPORT int _fileno(FILE *f) { (void)f; return 1; }
EXPORT int _setmode(int fd, int mode) { (void)fd; (void)mode; return 0; }
EXPORT void _fpreset(void) {}
EXPORT int fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    (void)stream;
    /* Write to stdout by default */
    size_t total = size * nmemb;
    /* We can't call write() directly in a DLL without kernel32 */
    return (int)total;
}

/* Signal */
typedef void (*sighandler_t)(int);
EXPORT sighandler_t signal(int signum, sighandler_t handler) {
    (void)signum; (void)handler;
    return (sighandler_t)0; /* SIG_DFL */
}

/* _cexit */
EXPORT void _cexit(void) {}
EXPORT void _c_exit(void) {}

/* Assert */
EXPORT void _assert(const char *expr, const char *file, unsigned line) {
    (void)expr; (void)file; (void)line;
    abort();
}

/* DllMain */
int __stdcall DllMain(void *hinstDLL, unsigned long fdwReason, void *lpvReserved) {
    (void)hinstDLL; (void)fdwReason; (void)lpvReserved;
    return 1;
}
CEOF

cat > /tmp/msvcrt.def << 'DEFEOF'
LIBRARY msvcrt.dll
EXPORTS
    malloc
    calloc
    realloc
    free
    strlen
    strcpy
    strcat
    strcmp
    strncmp
    memset
    memcpy
    memmove
    puts
    printf
    fprintf
    sprintf
    exit
    _exit
    abort
    atexit
    rand
    srand
    time
    _initterm
    _initterm_e
    __p__fmode
    _errno
    __getmainargs
    __set_app_type
    __p___argc
    __p___argv
    __p__environ
    __iob_func
    _iob DATA
    _fileno
    _setmode
    _fpreset
    fwrite
    signal
    _cexit
    _c_exit
    _assert
DEFEOF

$CC $CFLAGS -o "$OUTPUT/msvcrt.dll" /tmp/msvcrt_shim.c /tmp/msvcrt.def \
    -Wl,--enable-stdcall-fixup -lmsvcrt 2>&1 || echo "  msvcrt.dll build failed (expected - circular dep)"

# Try simpler approach - just compile the shim standalone
$CC $CFLAGS -nostdlib -o "$OUTPUT/msvcrt.dll" /tmp/msvcrt_shim.c /tmp/msvcrt.def \
    -Wl,--enable-stdcall-fixup -lkernel32 -lntdll 2>&1 && echo "  -> msvcrt.dll OK" || echo "  -> msvcrt.dll FAILED"

ls -lh "$OUTPUT/msvcrt.dll" 2>/dev/null && file "$OUTPUT/msvcrt.dll" 2>/dev/null

echo ""
echo "[BUILD] Done. DLLs in $OUTPUT/"
ls -lh "$OUTPUT/"
