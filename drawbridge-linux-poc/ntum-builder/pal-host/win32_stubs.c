/*
 * Win32 API Stubs
 *
 * Implements the most common Win32 functions that malware/apps call.
 * These translate Win32 calls to PAL operations.
 *
 * In the real SQLPAL, these are inside sqlpal.dll (the NTUM kernel).
 * Here we provide them as a stub library for the PAL host.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/random.h>
#include <pthread.h>

/* Windows types */
typedef int BOOL;
typedef uint32_t DWORD;
typedef void *HANDLE;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef uint64_t SIZE_T;
typedef DWORD *LPDWORD;
typedef int64_t LARGE_INTEGER;

#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define STD_INPUT_HANDLE  ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE  ((DWORD)-12)

/*
 * ABI TRANSLATION
 *
 * Windows x64 ABI:    rcx, rdx, r8, r9, stack (callee saves rbx,rsi,rdi,rbp,r12-r15)
 * System V AMD64 ABI: rdi, rsi, rdx, rcx, r8, r9, stack (callee saves rbx,rbp,r12-r15)
 *
 * We generate thunks that shuffle registers from Windows to SysV convention.
 * Each thunk is a small piece of x86-64 machine code.
 */

#include <sys/mman.h>

/* Thunk code templates for ABI translation (Windows x64 -> SysV AMD64) */

/* 1-arg thunk: mov rdi,rcx; jmp target */
static const uint8_t thunk_1arg[] = {
    0x48, 0x89, 0xcf,              /* mov rdi, rcx */
    0x48, 0xb8, 0,0,0,0,0,0,0,0,  /* mov rax, <target> */
    0xff, 0xe0                     /* jmp rax */
};

/* 2-arg thunk: mov rdi,rcx; mov rsi,rdx; jmp target */
static const uint8_t thunk_2arg[] = {
    0x48, 0x89, 0xcf,              /* mov rdi, rcx */
    0x48, 0x89, 0xd6,              /* mov rsi, rdx */
    0x48, 0xb8, 0,0,0,0,0,0,0,0,  /* mov rax, <target> */
    0xff, 0xe0                     /* jmp rax */
};

/* 3-arg thunk: mov rdi,rcx; mov rsi,rdx; mov rdx,r8; jmp target */
static const uint8_t thunk_3arg[] = {
    0x48, 0x89, 0xcf,              /* mov rdi, rcx */
    0x48, 0x89, 0xd6,              /* mov rsi, rdx */
    0x4c, 0x89, 0xc2,              /* mov rdx, r8 */
    0x48, 0xb8, 0,0,0,0,0,0,0,0,  /* mov rax, <target> */
    0xff, 0xe0                     /* jmp rax */
};

/* 4-arg thunk: mov rdi,rcx; mov rsi,rdx; mov rdx,r8; mov rcx,r9; jmp target */
static const uint8_t thunk_4arg[] = {
    0x48, 0x89, 0xcf,              /* mov rdi, rcx */
    0x48, 0x89, 0xd6,              /* mov rsi, rdx */
    0x4c, 0x89, 0xc2,              /* mov rdx, r8 */
    0x4c, 0x89, 0xc9,              /* mov rcx, r9 */
    0x48, 0xb8, 0,0,0,0,0,0,0,0,  /* mov rax, <target> */
    0xff, 0xe0                     /* jmp rax */
};

/* 5-arg thunk: mov rdi,rcx; mov rsi,rdx; mov rdx,r8; mov rcx,r9; mov r8,[rsp+0x28]; jmp */
static const uint8_t thunk_5arg[] = {
    0x48, 0x89, 0xcf,              /* mov rdi, rcx */
    0x48, 0x89, 0xd6,              /* mov rsi, rdx */
    0x4c, 0x89, 0xc2,              /* mov rdx, r8 */
    0x4c, 0x89, 0xc9,              /* mov rcx, r9 */
    0x4c, 0x8b, 0x44, 0x24, 0x28, /* mov r8, [rsp+0x28] */
    0x48, 0xb8, 0,0,0,0,0,0,0,0,  /* mov rax, <target> */
    0xff, 0xe0                     /* jmp rax */
};

/* 0-arg thunk: just jmp target (no translation needed) */
static const uint8_t thunk_0arg[] = {
    0x48, 0xb8, 0,0,0,0,0,0,0,0,  /* mov rax, <target> */
    0xff, 0xe0                     /* jmp rax */
};

static uint8_t *thunk_page = NULL;
static size_t thunk_offset = 0;
#define THUNK_PAGE_SIZE 65536

static void *make_thunk(const uint8_t *template, size_t tpl_size,
                        size_t addr_offset, void *target) {
    if (!thunk_page) {
        thunk_page = mmap(NULL, THUNK_PAGE_SIZE,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (thunk_page == MAP_FAILED) return NULL;
    }

    if (thunk_offset + tpl_size > THUNK_PAGE_SIZE) return NULL;

    uint8_t *thunk = thunk_page + thunk_offset;
    memcpy(thunk, template, tpl_size);
    /* Patch the target address into the thunk */
    *(uint64_t*)(thunk + addr_offset) = (uint64_t)target;
    thunk_offset += (tpl_size + 15) & ~15;  /* Align to 16 bytes */
    return thunk;
}

#define THUNK0(fn) make_thunk(thunk_0arg, sizeof(thunk_0arg), 2, (fn))
#define THUNK1(fn) make_thunk(thunk_1arg, sizeof(thunk_1arg), 5, (fn))
#define THUNK2(fn) make_thunk(thunk_2arg, sizeof(thunk_2arg), 8, (fn))
#define THUNK3(fn) make_thunk(thunk_3arg, sizeof(thunk_3arg), 11, (fn))
#define THUNK4(fn) make_thunk(thunk_4arg, sizeof(thunk_4arg), 14, (fn))
#define THUNK5(fn) make_thunk(thunk_5arg, sizeof(thunk_5arg), 19, (fn))

/* Memory flags */
#define MEM_COMMIT  0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40

/* Thread-local last error */
static __thread DWORD tls_last_error = 0;

/* ---- kernel32.dll stubs ---- */

HANDLE stub_GetStdHandle(DWORD nStdHandle) {
    switch (nStdHandle) {
        case STD_INPUT_HANDLE:  return (HANDLE)(intptr_t)0;
        case STD_OUTPUT_HANDLE: return (HANDLE)(intptr_t)1;
        case STD_ERROR_HANDLE:  return (HANDLE)(intptr_t)2;
        default: return INVALID_HANDLE_VALUE;
    }
}

BOOL stub_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nBytes,
                    LPDWORD lpWritten, LPVOID lpOverlapped) {
    (void)lpOverlapped;
    ssize_t n = write((int)(intptr_t)hFile, lpBuffer, nBytes);
    if (n < 0) { if (lpWritten) *lpWritten = 0; return FALSE; }
    if (lpWritten) *lpWritten = (DWORD)n;
    return TRUE;
}

BOOL stub_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nBytes,
                   LPDWORD lpRead, LPVOID lpOverlapped) {
    (void)lpOverlapped;
    ssize_t n = read((int)(intptr_t)hFile, lpBuffer, nBytes);
    if (n < 0) { if (lpRead) *lpRead = 0; return FALSE; }
    if (lpRead) *lpRead = (DWORD)n;
    return TRUE;
}

BOOL stub_WriteConsoleA(HANDLE hConsole, LPCVOID lpBuffer, DWORD nChars,
                        LPDWORD lpWritten, LPVOID lpReserved) {
    return stub_WriteFile(hConsole, lpBuffer, nChars, lpWritten, NULL);
}

void stub_ExitProcess(DWORD uExitCode) {
    printf("[DRAWBRIDGE] Process exiting with code %u\n", uExitCode);
    _exit(uExitCode);
}

LPVOID stub_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
                         DWORD flAllocationType, DWORD flProtect) {
    int prot = PROT_READ | PROT_WRITE;
    if (flProtect & PAGE_EXECUTE_READWRITE) prot |= PROT_EXEC;
    if (flProtect & PAGE_EXECUTE_READ) prot = PROT_READ | PROT_EXEC;

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (lpAddress) flags |= MAP_FIXED_NOREPLACE;

    void *result = mmap(lpAddress, dwSize, prot, flags, -1, 0);
    return (result == MAP_FAILED) ? NULL : result;
}

BOOL stub_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (dwFreeType & MEM_RELEASE) {
        /* For MEM_RELEASE, dwSize must be 0 and we need to know the original size */
        /* Hack: use a page size default */
        munmap(lpAddress, dwSize ? dwSize : 4096);
    }
    return TRUE;
}

HANDLE stub_GetProcessHeap(void) {
    return (HANDLE)(intptr_t)0xDEAD;
}

LPVOID stub_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    (void)hHeap;
    void *p = malloc(dwBytes);
    if (p && (dwFlags & 0x08)) memset(p, 0, dwBytes);  /* HEAP_ZERO_MEMORY */
    return p;
}

BOOL stub_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    (void)hHeap; (void)dwFlags;
    free(lpMem);
    return TRUE;
}

DWORD stub_GetLastError(void) { return tls_last_error; }
void  stub_SetLastError(DWORD err) { tls_last_error = err; }

DWORD stub_GetCurrentProcessId(void) { return (DWORD)getpid(); }
DWORD stub_GetCurrentThreadId(void)  { return (DWORD)pthread_self(); }
HANDLE stub_GetCurrentProcess(void)  { return (HANDLE)(intptr_t)-1; }

BOOL stub_CloseHandle(HANDLE hObject) {
    /* For fd-based handles */
    int fd = (int)(intptr_t)hObject;
    if (fd > 2) close(fd);
    return TRUE;
}

void stub_GetSystemTimeAsFileTime(void *lpSystemTimeAsFileTime) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* Convert to Windows FILETIME (100ns intervals since 1601) */
    uint64_t ft = ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL
                  + ts.tv_nsec / 100;
    *(uint64_t*)lpSystemTimeAsFileTime = ft;
}

BOOL stub_QueryPerformanceCounter(LARGE_INTEGER *lpCounter) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    *lpCounter = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    return TRUE;
}

BOOL stub_QueryPerformanceFrequency(LARGE_INTEGER *lpFreq) {
    *lpFreq = 1000000000LL;  /* nanosecond resolution */
    return TRUE;
}

DWORD stub_GetTickCount(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (DWORD)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

BOOL stub_IsDebuggerPresent(void) { return FALSE; }
BOOL stub_IsProcessorFeaturePresent(DWORD feature) { return FALSE; }

void stub_InitializeSListHead(void *ListHead) { *(void**)ListHead = NULL; }

DWORD stub_GetModuleFileNameA(HANDLE hModule, LPSTR lpFilename, DWORD nSize) {
    const char *name = "drawbridge.exe";
    size_t len = strlen(name);
    if (len >= nSize) len = nSize - 1;
    memcpy(lpFilename, name, len);
    lpFilename[len] = '\0';
    return (DWORD)len;
}

HANDLE stub_GetModuleHandleA(LPCSTR lpModuleName) {
    return (HANDLE)(intptr_t)0x400000;  /* Fake base address */
}

LPSTR stub_GetCommandLineA(void) {
    return "drawbridge.exe";
}

DWORD stub_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    const char *val = getenv(lpName);
    if (!val) return 0;
    size_t len = strlen(val);
    if (len >= nSize) return (DWORD)(len + 1);
    memcpy(lpBuffer, val, len + 1);
    return (DWORD)len;
}

void stub_Sleep(DWORD dwMilliseconds) {
    usleep(dwMilliseconds * 1000);
}

HANDLE stub_CreateThread(void *lpAttributes, SIZE_T dwStackSize,
                         void *lpStartAddress, LPVOID lpParameter,
                         DWORD dwCreationFlags, LPDWORD lpThreadId) {
    pthread_t *t = malloc(sizeof(pthread_t));
    if (!t) return NULL;
    if (pthread_create(t, NULL, lpStartAddress, lpParameter) != 0) {
        free(t);
        return NULL;
    }
    if (lpThreadId) *lpThreadId = (DWORD)(uintptr_t)*t;
    return (HANDLE)t;
}

/* MSVCRT stubs */
int stub_puts(const char *str) {
    int n = printf("%s\n", str);
    return n;
}

int stub_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

void *stub_malloc(size_t size) { return malloc(size); }
void  stub_free(void *ptr) { free(ptr); }
void *stub_memset(void *s, int c, size_t n) { return memset(s, c, n); }
void *stub_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
size_t stub_strlen(const char *s) { return strlen(s); }
int stub_strcmp(const char *a, const char *b) { return strcmp(a, b); }
void stub_exit(int status) { _exit(status); }

void *stub_calloc(size_t nmemb, size_t size) { return calloc(nmemb, size); }
void *stub_realloc(void *ptr, size_t size) { return realloc(ptr, size); }

/* CRT init stubs */
void stub_initterm(void **start, void **end) {
    while (start < end) {
        if (*start) ((void(*)(void))(*start))();
        start++;
    }
}

int stub_initterm_e(void **start, void **end) {
    while (start < end) {
        if (*start) {
            int ret = ((int(*)(void))(*start))();
            if (ret) return ret;
        }
        start++;
    }
    return 0;
}

/* ---- Import resolution table ---- */

typedef struct {
    const char *dll_name;
    const char *func_name;
    void *addr;
} stub_entry_t;

static const stub_entry_t g_stubs[] = {
    /* kernel32.dll */
    {"KERNEL32.dll", "GetStdHandle", stub_GetStdHandle},
    {"KERNEL32.dll", "WriteFile", stub_WriteFile},
    {"KERNEL32.dll", "ReadFile", stub_ReadFile},
    {"KERNEL32.dll", "WriteConsoleA", stub_WriteConsoleA},
    {"KERNEL32.dll", "ExitProcess", stub_ExitProcess},
    {"KERNEL32.dll", "VirtualAlloc", stub_VirtualAlloc},
    {"KERNEL32.dll", "VirtualFree", stub_VirtualFree},
    {"KERNEL32.dll", "GetProcessHeap", stub_GetProcessHeap},
    {"KERNEL32.dll", "HeapAlloc", stub_HeapAlloc},
    {"KERNEL32.dll", "HeapFree", stub_HeapFree},
    {"KERNEL32.dll", "GetLastError", stub_GetLastError},
    {"KERNEL32.dll", "SetLastError", stub_SetLastError},
    {"KERNEL32.dll", "GetCurrentProcessId", stub_GetCurrentProcessId},
    {"KERNEL32.dll", "GetCurrentThreadId", stub_GetCurrentThreadId},
    {"KERNEL32.dll", "GetCurrentProcess", stub_GetCurrentProcess},
    {"KERNEL32.dll", "CloseHandle", stub_CloseHandle},
    {"KERNEL32.dll", "GetSystemTimeAsFileTime", stub_GetSystemTimeAsFileTime},
    {"KERNEL32.dll", "QueryPerformanceCounter", stub_QueryPerformanceCounter},
    {"KERNEL32.dll", "QueryPerformanceFrequency", stub_QueryPerformanceFrequency},
    {"KERNEL32.dll", "GetTickCount", stub_GetTickCount},
    {"KERNEL32.dll", "IsDebuggerPresent", stub_IsDebuggerPresent},
    {"KERNEL32.dll", "IsProcessorFeaturePresent", stub_IsProcessorFeaturePresent},
    {"KERNEL32.dll", "InitializeSListHead", stub_InitializeSListHead},
    {"KERNEL32.dll", "GetModuleFileNameA", stub_GetModuleFileNameA},
    {"KERNEL32.dll", "GetModuleHandleA", stub_GetModuleHandleA},
    {"KERNEL32.dll", "GetCommandLineA", stub_GetCommandLineA},
    {"KERNEL32.dll", "GetEnvironmentVariableA", stub_GetEnvironmentVariableA},
    {"KERNEL32.dll", "Sleep", stub_Sleep},
    {"KERNEL32.dll", "CreateThread", stub_CreateThread},
    {"KERNEL32.dll", "SetUnhandledExceptionFilter", stub_GetCurrentProcess}, /* nop */
    {"KERNEL32.dll", "UnhandledExceptionFilter", stub_IsDebuggerPresent},    /* nop */

    /* msvcrt.dll / api-ms-win-crt-* */
    {"msvcrt.dll", "puts", stub_puts},
    {"msvcrt.dll", "printf", stub_printf},
    {"msvcrt.dll", "malloc", stub_malloc},
    {"msvcrt.dll", "free", stub_free},
    {"msvcrt.dll", "calloc", stub_calloc},
    {"msvcrt.dll", "realloc", stub_realloc},
    {"msvcrt.dll", "memset", stub_memset},
    {"msvcrt.dll", "memcpy", stub_memcpy},
    {"msvcrt.dll", "strlen", stub_strlen},
    {"msvcrt.dll", "strcmp", stub_strcmp},
    {"msvcrt.dll", "exit", stub_exit},
    {"msvcrt.dll", "_initterm", stub_initterm},
    {"msvcrt.dll", "_initterm_e", stub_initterm_e},

    /* VCRUNTIME140.dll */
    {"VCRUNTIME140.dll", "memcpy", stub_memcpy},
    {"VCRUNTIME140.dll", "memset", stub_memset},
    {"VCRUNTIME140.dll", "memmove", stub_memcpy}, /* simplified */
    {"VCRUNTIME140.dll", "__C_specific_handler", stub_IsDebuggerPresent}, /* stub */

    /* api-ms-win-crt stubs */
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm", stub_initterm},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm_e", stub_initterm_e},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "exit", stub_exit},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_exit", stub_exit},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_cexit", stub_exit},
    {"api-ms-win-crt-heap-l1-1-0.dll", "malloc", stub_malloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "free", stub_free},
    {"api-ms-win-crt-heap-l1-1-0.dll", "calloc", stub_calloc},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__acrt_iob_func", stub_GetCurrentProcess}, /* stub */

    {NULL, NULL, NULL}
};

/* Case-insensitive string compare */
static int stricmp(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
        char cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return *a - *b;
}

void *win32_resolve_import(const char *dll_name, const char *func_name,
                           uint16_t ordinal, void *ctx) {
    (void)ctx;
    if (!func_name) return NULL;  /* No ordinal support yet */

    for (const stub_entry_t *e = g_stubs; e->dll_name; e++) {
        if (stricmp(dll_name, e->dll_name) == 0 &&
            strcmp(func_name, e->func_name) == 0) {
            /* Create an ABI translation thunk.
             * Windows x64 passes args in rcx,rdx,r8,r9
             * Linux SysV passes args in rdi,rsi,rdx,rcx,r8,r9
             * The thunk shuffles registers before calling our stub. */
            void *thunk = make_thunk(thunk_5arg, sizeof(thunk_5arg),
                                     19, e->addr);
            return thunk ? thunk : e->addr;
        }
    }
    return NULL;
}
