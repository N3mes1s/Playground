/*
 * Minimal MSVCRT shim DLL for Drawbridge
 *
 * Self-contained C runtime that implements the functions malware needs.
 * Does NOT link against the real msvcrt - implements everything from scratch
 * using kernel32.dll imports for I/O.
 *
 * Compile: i686-w64-mingw32-gcc -shared -o msvcrt.dll msvcrt_shim.c msvcrt.def
 *          -nostdlib -lkernel32 -Wl,-e,_DllMainCRTStartup@12
 */

/* stdarg.h is a compiler builtin, safe with -nostdlib */
#include <stdarg.h>

/* We can't include standard headers - define everything ourselves */
typedef unsigned int size_t;
typedef int ptrdiff_t;

#define NULL ((void*)0)
#define EXPORT __declspec(dllexport)
#define WINAPI __stdcall

/* kernel32 imports we use */
__declspec(dllimport) void * WINAPI GetProcessHeap(void);
__declspec(dllimport) void * WINAPI HeapAlloc(void *hHeap, unsigned long dwFlags, size_t dwBytes);
__declspec(dllimport) int    WINAPI HeapFree(void *hHeap, unsigned long dwFlags, void *lpMem);
__declspec(dllimport) void * WINAPI HeapReAlloc(void *hHeap, unsigned long dwFlags, void *lpMem, size_t dwBytes);
__declspec(dllimport) void * WINAPI GetStdHandle(unsigned long nStdHandle);
__declspec(dllimport) int    WINAPI WriteFile(void *hFile, const void *buf, unsigned long nBytes,
                                               unsigned long *written, void *overlapped);
__declspec(dllimport) void   WINAPI ExitProcess(unsigned int uExitCode);

#define HEAP_ZERO_MEMORY 0x08
#define STD_OUTPUT_HANDLE ((unsigned long)-11)
#define STD_ERROR_HANDLE  ((unsigned long)-12)

/* ---- Memory ---- */

EXPORT void *malloc(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

EXPORT void *calloc(size_t n, size_t size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * size);
}

EXPORT void *realloc(void *ptr, size_t size) {
    if (!ptr) return malloc(size);
    return HeapReAlloc(GetProcessHeap(), 0, ptr, size);
}

EXPORT void free(void *ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

/* ---- String ---- */

EXPORT size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

EXPORT char *strcpy(char *d, const char *s) {
    char *r = d;
    while ((*d++ = *s++));
    return r;
}

EXPORT char *strncpy(char *d, const char *s, size_t n) {
    char *r = d;
    while (n-- && (*d++ = *s++));
    while (n-- > 0) *d++ = 0;
    return r;
}

EXPORT char *strcat(char *d, const char *s) {
    char *r = d;
    while (*d) d++;
    while ((*d++ = *s++));
    return r;
}

EXPORT int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *(unsigned char*)a - *(unsigned char*)b;
}

EXPORT int strncmp(const char *a, const char *b, size_t n) {
    while (n-- && *a && *a == *b) { a++; b++; }
    return n == (size_t)-1 ? 0 : *(unsigned char*)a - *(unsigned char*)b;
}

EXPORT char *strchr(const char *s, int c) {
    while (*s) { if (*s == c) return (char*)s; s++; }
    return c == 0 ? (char*)s : NULL;
}

EXPORT char *strrchr(const char *s, int c) {
    const char *last = NULL;
    while (*s) { if (*s == c) last = s; s++; }
    return (char*)(c == 0 ? s : last);
}

EXPORT char *strstr(const char *haystack, const char *needle) {
    size_t nlen = strlen(needle);
    if (!nlen) return (char*)haystack;
    while (*haystack) {
        if (strncmp(haystack, needle, nlen) == 0) return (char*)haystack;
        haystack++;
    }
    return NULL;
}

/* ---- Memory ops ---- */

EXPORT void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

EXPORT void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dp = d;
    const unsigned char *sp = s;
    while (n--) *dp++ = *sp++;
    return d;
}

EXPORT void *memmove(void *d, const void *s, size_t n) {
    unsigned char *dp = d;
    const unsigned char *sp = s;
    if (dp < sp) {
        while (n--) *dp++ = *sp++;
    } else {
        dp += n; sp += n;
        while (n--) *--dp = *--sp;
    }
    return d;
}

EXPORT int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *pa = a, *pb = b;
    while (n--) {
        if (*pa != *pb) return *pa - *pb;
        pa++; pb++;
    }
    return 0;
}

/* ---- Simple I/O (via kernel32) ---- */

static void write_stdout(const char *s, size_t len) {
    unsigned long written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (unsigned long)len, &written, NULL);
}

EXPORT int puts(const char *s) {
    size_t len = strlen(s);
    write_stdout(s, len);
    write_stdout("\n", 1);
    return (int)len + 1;
}

/* Minimal integer-to-string */
static int itoa_simple(int val, char *buf, int base) {
    char tmp[32];
    int i = 0, neg = 0, j = 0;
    if (val < 0 && base == 10) { neg = 1; val = -val; }
    if (val == 0) tmp[i++] = '0';
    while (val > 0) { tmp[i++] = "0123456789abcdef"[val % base]; val /= base; }
    if (neg) buf[j++] = '-';
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = 0;
    return j;
}

/* Minimal printf - supports %s, %d, %x, %u, %c, %p, %% */
static int do_printf(char *out, size_t max, const char *fmt, va_list ap) {
    size_t pos = 0;
    while (*fmt && pos < max - 1) {
        if (*fmt != '%') { out[pos++] = *fmt++; continue; }
        fmt++;
        if (*fmt == '%') { out[pos++] = '%'; fmt++; continue; }

        /* Skip flags, width, precision */
        while (*fmt == '-' || *fmt == '+' || *fmt == ' ' || *fmt == '0' || *fmt == '#') fmt++;
        while (*fmt >= '0' && *fmt <= '9') fmt++;
        if (*fmt == '.') { fmt++; while (*fmt >= '0' && *fmt <= '9') fmt++; }
        if (*fmt == 'l') { fmt++; if (*fmt == 'l') fmt++; }
        if (*fmt == 'h') { fmt++; if (*fmt == 'h') fmt++; }

        char tmp[64];
        int len;
        switch (*fmt) {
            case 's': {
                const char *s = va_arg(ap, const char*);
                if (!s) s = "(null)";
                len = (int)strlen(s);
                for (int k = 0; k < len && pos < max - 1; k++) out[pos++] = s[k];
                break;
            }
            case 'd': case 'i':
                len = itoa_simple(va_arg(ap, int), tmp, 10);
                for (int k = 0; k < len && pos < max - 1; k++) out[pos++] = tmp[k];
                break;
            case 'u': {
                unsigned u = va_arg(ap, unsigned);
                len = itoa_simple((int)u, tmp, 10);
                for (int k = 0; k < len && pos < max - 1; k++) out[pos++] = tmp[k];
                break;
            }
            case 'x': case 'X':
                len = itoa_simple(va_arg(ap, unsigned), tmp, 16);
                for (int k = 0; k < len && pos < max - 1; k++) out[pos++] = tmp[k];
                break;
            case 'p':
                out[pos++] = '0'; if (pos < max - 1) out[pos++] = 'x';
                len = itoa_simple((unsigned)(size_t)va_arg(ap, void*), tmp, 16);
                for (int k = 0; k < len && pos < max - 1; k++) out[pos++] = tmp[k];
                break;
            case 'c':
                out[pos++] = (char)va_arg(ap, int);
                break;
            default:
                out[pos++] = '%';
                if (pos < max - 1) out[pos++] = *fmt;
                break;
        }
        fmt++;
    }
    out[pos] = 0;
    return (int)pos;
}

EXPORT int printf(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    __builtin_va_start(ap, fmt);
    int n = do_printf(buf, sizeof(buf), fmt, ap);
    __builtin_va_end(ap);
    write_stdout(buf, n);
    return n;
}

EXPORT int fprintf(void *stream, const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    __builtin_va_start(ap, fmt);
    int n = do_printf(buf, sizeof(buf), fmt, ap);
    __builtin_va_end(ap);
    unsigned long written;
    /* Treat any stream as stderr */
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, n, &written, NULL);
    return n;
}

EXPORT int sprintf(char *buf, const char *fmt, ...) {
    va_list ap;
    __builtin_va_start(ap, fmt);
    int n = do_printf(buf, 4096, fmt, ap);
    __builtin_va_end(ap);
    return n;
}

EXPORT int fwrite(const void *ptr, size_t size, size_t nmemb, void *stream) {
    (void)stream;
    size_t total = size * nmemb;
    write_stdout((const char*)ptr, total);
    return (int)nmemb;
}

/* ---- Process ---- */

EXPORT void exit(int status) { ExitProcess(status); for(;;); }
EXPORT void _exit(int status) { ExitProcess(status); for(;;); }
EXPORT void _cexit(void) {}
EXPORT void _c_exit(void) {}

EXPORT void abort(void) { ExitProcess(3); for(;;); }

static void (*atexit_funcs[32])(void);
static int atexit_count = 0;

EXPORT int atexit(void (*func)(void)) {
    if (atexit_count >= 32) return -1;
    atexit_funcs[atexit_count++] = func;
    return 0;
}

/* ---- Random ---- */

static unsigned long rand_seed = 1;

EXPORT int rand(void) {
    rand_seed = rand_seed * 1103515245 + 12345;
    return (int)((rand_seed >> 16) & 0x7FFF);
}

EXPORT void srand(unsigned int seed) { rand_seed = seed; }

/* ---- Time ---- */

/* Stub - returns 0. Real implementation needs NtQuerySystemTime */
EXPORT long long time(long long *t) {
    long long now = 0; /* TODO: real time */
    if (t) *t = now;
    return now;
}

/* ---- CRT Init ---- */

EXPORT void _initterm(void (**start)(void), void (**end)(void)) {
    while (start < end) {
        if (*start) (*start)();
        start++;
    }
}

EXPORT int _initterm_e(int (**start)(void), int (**end)(void)) {
    while (start < end) {
        if (*start) {
            int ret = (*start)();
            if (ret) return ret;
        }
        start++;
    }
    return 0;
}

/* ---- CRT internals ---- */

static int dummy_fmode = 0;
EXPORT int *__p__fmode(void) { return &dummy_fmode; }
EXPORT int *_errno(void) { static int e = 0; return &e; }

static int dummy_argc = 1;
static char *dummy_argv_data[] = {"program.exe", NULL};
static char **dummy_argv = dummy_argv_data;
static char **dummy_env = NULL;

EXPORT int __getmainargs(int *argc, char ***argv, char ***env, int dowildcard, void *startinfo) {
    (void)dowildcard; (void)startinfo;
    *argc = 1;
    *argv = dummy_argv;
    if (env) *env = (char***)&dummy_env;
    return 0;
}

EXPORT void __set_app_type(int type) { (void)type; }
EXPORT int *__p___argc(void) { return &dummy_argc; }
EXPORT char ***__p___argv(void) { return &dummy_argv; }
EXPORT char ***__p__environ(void) { return &dummy_env; }

static char iob_buf[3 * 64];
EXPORT void *__iob_func(void) { return iob_buf; }
void *_iob = iob_buf;
EXPORT int _fileno(void *f) { (void)f; return 1; }
EXPORT int _setmode(int fd, int mode) { (void)fd; (void)mode; return 0; }
EXPORT void _fpreset(void) {}

typedef void (*sighandler_t)(int);
EXPORT sighandler_t signal(int signum, sighandler_t handler) {
    (void)signum; (void)handler; return (sighandler_t)0;
}

EXPORT void _assert(const char *expr, const char *file, unsigned line) {
    (void)expr; (void)file; (void)line; abort();
}

/* ---- Stack probing (needed by GCC for large stack frames) ---- */
void __chkstk_ms(void) { /* no-op on Linux PAL host */ }

/* ---- DllMain ---- */

int WINAPI DllMain(void *hinstDLL, unsigned long fdwReason, void *lpvReserved) {
    (void)hinstDLL; (void)fdwReason; (void)lpvReserved;
    return 1;
}

/* Entry point for the DLL */
int WINAPI _DllMainCRTStartup(void *hinstDLL, unsigned long fdwReason, void *lpvReserved) {
    return DllMain(hinstDLL, fdwReason, lpvReserved);
}
