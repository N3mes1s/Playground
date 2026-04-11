/*
 * Win32 API Stubs
 *
 * Implements the most common Win32 functions that malware/apps call.
 * These translate Win32 calls to PAL operations.
 *
 * In the real SQLPAL, these are inside sqlpal.dll (the NTUM kernel).
 * Here we provide them as a stub library for the PAL host.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/random.h>
#include <pthread.h>

typedef int32_t LONG;

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

/* In 32-bit mode, Windows uses stdcall (callee cleans stack).
 * We declare stubs as stdcall so they're ABI-compatible. */
#ifdef HOST_32BIT
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI /* nothing - thunks handle ABI translation */
#endif

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

HANDLE WINAPI stub_GetStdHandle(DWORD nStdHandle) {
    switch (nStdHandle) {
        case STD_INPUT_HANDLE:  return (HANDLE)(intptr_t)0;
        case STD_OUTPUT_HANDLE: return (HANDLE)(intptr_t)1;
        case STD_ERROR_HANDLE:  return (HANDLE)(intptr_t)2;
        default: return INVALID_HANDLE_VALUE;
    }
}

BOOL WINAPI stub_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nBytes,
                    LPDWORD lpWritten, LPVOID lpOverlapped) {
    (void)lpOverlapped;
    ssize_t n = write((int)(intptr_t)hFile, lpBuffer, nBytes);
    if (n < 0) { if (lpWritten) *lpWritten = 0; return FALSE; }
    if (lpWritten) *lpWritten = (DWORD)n;
    return TRUE;
}

BOOL WINAPI stub_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nBytes,
                   LPDWORD lpRead, LPVOID lpOverlapped) {
    (void)lpOverlapped;
    ssize_t n = read((int)(intptr_t)hFile, lpBuffer, nBytes);
    if (n < 0) { if (lpRead) *lpRead = 0; return FALSE; }
    if (lpRead) *lpRead = (DWORD)n;
    return TRUE;
}

BOOL WINAPI stub_WriteConsoleA(HANDLE hConsole, LPCVOID lpBuffer, DWORD nChars,
                        LPDWORD lpWritten, LPVOID lpReserved) {
    return stub_WriteFile(hConsole, lpBuffer, nChars, lpWritten, NULL);
}

void WINAPI stub_ExitProcess(DWORD uExitCode) {
    printf("[DRAWBRIDGE] Process exiting with code %u\n", uExitCode);
    _exit(uExitCode);
}

LPVOID WINAPI stub_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
                         DWORD flAllocationType, DWORD flProtect) {
    int prot = PROT_READ | PROT_WRITE;
    if (flProtect & PAGE_EXECUTE_READWRITE) prot |= PROT_EXEC;
    if (flProtect & PAGE_EXECUTE_READ) prot = PROT_READ | PROT_EXEC;

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (lpAddress) flags |= MAP_FIXED_NOREPLACE;

    void *result = mmap(lpAddress, dwSize, prot, flags, -1, 0);
    return (result == MAP_FAILED) ? NULL : result;
}

BOOL WINAPI stub_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (dwFreeType & MEM_RELEASE) {
        /* For MEM_RELEASE, dwSize must be 0 and we need to know the original size */
        /* Hack: use a page size default */
        munmap(lpAddress, dwSize ? dwSize : 4096);
    }
    return TRUE;
}

HANDLE WINAPI stub_GetProcessHeap(void) {
    return (HANDLE)(intptr_t)0xDEAD;
}

LPVOID WINAPI stub_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    (void)hHeap;
    void *p = malloc(dwBytes);
    if (p && (dwFlags & 0x08)) memset(p, 0, dwBytes);  /* HEAP_ZERO_MEMORY */
    return p;
}

BOOL WINAPI stub_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    (void)hHeap; (void)dwFlags;
    free(lpMem);
    return TRUE;
}

DWORD WINAPI stub_GetLastError(void) { return tls_last_error; }
void WINAPI stub_SetLastError(DWORD err) { tls_last_error = err; }

DWORD WINAPI stub_GetCurrentProcessId(void) { return (DWORD)getpid(); }
DWORD WINAPI stub_GetCurrentThreadId(void)  { return (DWORD)pthread_self(); }
HANDLE WINAPI stub_GetCurrentProcess(void)  { return (HANDLE)(intptr_t)-1; }

BOOL WINAPI stub_CloseHandle(HANDLE hObject) {
    /* For fd-based handles */
    int fd = (int)(intptr_t)hObject;
    if (fd > 2) close(fd);
    return TRUE;
}

void WINAPI stub_GetSystemTimeAsFileTime(void *lpSystemTimeAsFileTime) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* Convert to Windows FILETIME (100ns intervals since 1601) */
    uint64_t ft = ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL
                  + ts.tv_nsec / 100;
    *(uint64_t*)lpSystemTimeAsFileTime = ft;
}

BOOL WINAPI stub_QueryPerformanceCounter(LARGE_INTEGER *lpCounter) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    *lpCounter = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    return TRUE;
}

BOOL WINAPI stub_QueryPerformanceFrequency(LARGE_INTEGER *lpFreq) {
    *lpFreq = 1000000000LL;  /* nanosecond resolution */
    return TRUE;
}

DWORD WINAPI stub_GetTickCount(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (DWORD)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

BOOL WINAPI stub_IsDebuggerPresent(void) { return FALSE; }
BOOL WINAPI stub_IsProcessorFeaturePresent(DWORD feature) { return FALSE; }

void WINAPI stub_InitializeSListHead(void *ListHead) { *(void**)ListHead = NULL; }

DWORD WINAPI stub_GetModuleFileNameA(HANDLE hModule, LPSTR lpFilename, DWORD nSize) {
    const char *name = "drawbridge.exe";
    size_t len = strlen(name);
    if (len >= nSize) len = nSize - 1;
    memcpy(lpFilename, name, len);
    lpFilename[len] = '\0';
    return (DWORD)len;
}

HANDLE WINAPI stub_GetModuleHandleA(LPCSTR lpModuleName) {
    return (HANDLE)(intptr_t)0x400000;  /* Fake base address */
}

LPSTR WINAPI stub_GetCommandLineA(void) {
    return "drawbridge.exe";
}

DWORD WINAPI stub_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    const char *val = getenv(lpName);
    if (!val) return 0;
    size_t len = strlen(val);
    if (len >= nSize) return (DWORD)(len + 1);
    memcpy(lpBuffer, val, len + 1);
    return (DWORD)len;
}

void WINAPI stub_Sleep(DWORD dwMilliseconds) {
    usleep(dwMilliseconds * 1000);
}

HANDLE WINAPI stub_CreateThread(void *lpAttributes, SIZE_T dwStackSize,
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

/* ---- Additional kernel32 stubs for malware compatibility ---- */

HANDLE WINAPI stub_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
                               DWORD dwShareMode, LPVOID lpSecurityAttributes,
                               DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                               HANDLE hTemplateFile) {
    (void)dwShareMode; (void)lpSecurityAttributes;
    (void)dwFlagsAndAttributes; (void)hTemplateFile;
    int flags = 0;
    if ((dwDesiredAccess & 0x80000000) && (dwDesiredAccess & 0x40000000))
        flags = O_RDWR;
    else if (dwDesiredAccess & 0x40000000)
        flags = O_WRONLY;
    else
        flags = O_RDONLY;
    switch (dwCreationDisposition) {
        case 1: flags |= O_CREAT | O_EXCL; break;     /* CREATE_NEW */
        case 2: flags |= O_CREAT | O_TRUNC; break;    /* CREATE_ALWAYS */
        case 3: break;                                  /* OPEN_EXISTING */
        case 4: flags |= O_CREAT; break;               /* OPEN_ALWAYS */
        case 5: flags |= O_TRUNC; break;               /* TRUNCATE_EXISTING */
    }
    int fd = open(lpFileName, flags, 0644);
    if (fd < 0) return INVALID_HANDLE_VALUE;
    return (HANDLE)(intptr_t)fd;
}

DWORD WINAPI stub_GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
    struct stat st;
    if (fstat((int)(intptr_t)hFile, &st) < 0) return 0xFFFFFFFF;
    if (lpFileSizeHigh) *lpFileSizeHigh = (DWORD)(st.st_size >> 32);
    return (DWORD)(st.st_size & 0xFFFFFFFF);
}

DWORD WINAPI stub_SetFilePointer(HANDLE hFile, int32_t lDistanceToMove,
                                  int32_t *lpDistanceToMoveHigh, DWORD dwMoveMethod) {
    int whence = SEEK_SET;
    if (dwMoveMethod == 1) whence = SEEK_CUR;
    if (dwMoveMethod == 2) whence = SEEK_END;
    off_t result = lseek((int)(intptr_t)hFile, lDistanceToMove, whence);
    if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = 0;
    return (DWORD)result;
}

BOOL WINAPI stub_SetEndOfFile(HANDLE hFile) {
    off_t pos = lseek((int)(intptr_t)hFile, 0, SEEK_CUR);
    return ftruncate((int)(intptr_t)hFile, pos) == 0;
}

BOOL WINAPI stub_FlushFileBuffers(HANDLE hFile) {
    return fsync((int)(intptr_t)hFile) == 0;
}

BOOL WINAPI stub_CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists) {
    if (bFailIfExists && access(lpNewFileName, F_OK) == 0) return FALSE;
    int src = open(lpExistingFileName, O_RDONLY);
    if (src < 0) return FALSE;
    int dst = open(lpNewFileName, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst < 0) { close(src); return FALSE; }
    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) write(dst, buf, n);
    close(src); close(dst);
    return TRUE;
}

BOOL WINAPI stub_DeleteFileA(LPCSTR lpFileName) {
    return unlink(lpFileName) == 0;
}

DWORD WINAPI stub_GetFileAttributesA(LPCSTR lpFileName) {
    struct stat st;
    if (stat(lpFileName, &st) < 0) return 0xFFFFFFFF;
    DWORD attrs = 0x80; /* FILE_ATTRIBUTE_NORMAL */
    if (S_ISDIR(st.st_mode)) attrs = 0x10; /* FILE_ATTRIBUTE_DIRECTORY */
    return attrs;
}

BOOL WINAPI stub_SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes) {
    (void)lpFileName; (void)dwFileAttributes;
    return TRUE; /* Stub - ignore attributes */
}

DWORD WINAPI stub_GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer) {
    const char *tmp = "/tmp/";
    size_t len = strlen(tmp);
    if (len >= nBufferLength) return (DWORD)(len + 1);
    memcpy(lpBuffer, tmp, len + 1);
    return (DWORD)len;
}

DWORD WINAPI stub_GetWindowsDirectoryA(LPSTR lpBuffer, DWORD uSize) {
    const char *dir = "C:\\Windows";
    size_t len = strlen(dir);
    if (len >= uSize) return (DWORD)(len + 1);
    memcpy(lpBuffer, dir, len + 1);
    return (DWORD)len;
}

DWORD WINAPI stub_GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer) {
    if (!getcwd(lpBuffer, nBufferLength)) return 0;
    return (DWORD)strlen(lpBuffer);
}

DWORD WINAPI stub_GetDriveTypeA(LPCSTR lpRootPathName) {
    (void)lpRootPathName;
    return 3; /* DRIVE_FIXED */
}

HANDLE WINAPI stub_CreateMutexA(LPVOID lpAttributes, BOOL bInitialOwner, LPCSTR lpName) {
    (void)lpAttributes; (void)lpName;
    pthread_mutex_t *m = malloc(sizeof(pthread_mutex_t));
    if (!m) return NULL;
    pthread_mutex_init(m, NULL);
    if (bInitialOwner) pthread_mutex_lock(m);
    return (HANDLE)m;
}

BOOL WINAPI stub_ReleaseMutex(HANDLE hMutex) {
    return pthread_mutex_unlock((pthread_mutex_t*)hMutex) == 0;
}

DWORD WINAPI stub_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    (void)dwMilliseconds; /* TODO: timeout */
    pthread_mutex_t *m = (pthread_mutex_t*)hHandle;
    pthread_mutex_lock(m);
    return 0; /* WAIT_OBJECT_0 */
}

DWORD WINAPI stub_TlsAlloc(void) {
    pthread_key_t key;
    if (pthread_key_create(&key, NULL) != 0) return 0xFFFFFFFF;
    return (DWORD)key;
}

LPVOID WINAPI stub_TlsGetValue(DWORD dwTlsIndex) {
    return pthread_getspecific((pthread_key_t)dwTlsIndex);
}

BOOL WINAPI stub_TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue) {
    return pthread_setspecific((pthread_key_t)dwTlsIndex, lpTlsValue) == 0;
}

HANDLE WINAPI stub_FindFirstFileA(LPCSTR lpFileName, LPVOID lpFindFileData) {
    (void)lpFileName; (void)lpFindFileData;
    return INVALID_HANDLE_VALUE; /* Stub: no files found */
}

BOOL WINAPI stub_FindNextFileA(HANDLE hFindFile, LPVOID lpFindFileData) {
    (void)hFindFile; (void)lpFindFileData;
    return FALSE;
}

BOOL WINAPI stub_FindClose(HANDLE hFindFile) {
    (void)hFindFile;
    return TRUE;
}

HANDLE WINAPI stub_LoadLibraryA(LPCSTR lpLibFileName) {
    printf("[DRAWBRIDGE] LoadLibraryA(\"%s\") - stub\n", lpLibFileName);
    return (HANDLE)(intptr_t)0x10000000; /* Fake handle */
}

void* WINAPI stub_GetProcAddress(HANDLE hModule, LPCSTR lpProcName) {
    printf("[DRAWBRIDGE] GetProcAddress(%p, \"%s\") - stub\n", hModule, lpProcName);
    return NULL;
}

BOOL WINAPI stub_GetVersionExA(LPVOID lpVersionInformation) {
    /* Return Windows 10 version info */
    uint32_t *p = (uint32_t*)lpVersionInformation;
    /* dwOSVersionInfoSize already set by caller */
    p[1] = 10; /* dwMajorVersion */
    p[2] = 0;  /* dwMinorVersion */
    p[3] = 19041; /* dwBuildNumber */
    p[4] = 2;  /* dwPlatformId = VER_PLATFORM_WIN32_NT */
    return TRUE;
}

void WINAPI stub_GetStartupInfoA(LPVOID lpStartupInfo) {
    memset(lpStartupInfo, 0, 68); /* sizeof(STARTUPINFOA) on 32-bit */
    *(uint32_t*)lpStartupInfo = 68; /* cb */
}

BOOL WINAPI stub_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPVOID a, LPVOID b, BOOL c, DWORD d, LPVOID e, LPCSTR f,
    LPVOID g, LPVOID h) {
    printf("[DRAWBRIDGE] CreateProcessA(\"%s\", \"%s\") - blocked\n",
           lpApplicationName ? lpApplicationName : "(null)",
           lpCommandLine ? lpCommandLine : "(null)");
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;
    return FALSE; /* Block process creation */
}

LONG WINAPI stub_InterlockedIncrement(volatile LONG *Addend) {
    return __sync_add_and_fetch(Addend, 1);
}

LONG WINAPI stub_InterlockedDecrement(volatile LONG *Addend) {
    return __sync_sub_and_fetch(Addend, 1);
}

/* ---- advapi32.dll stubs ---- */

typedef void* HKEY;
#define ERROR_SUCCESS 0

LONG WINAPI stub_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
                                DWORD samDesired, HKEY *phkResult) {
    (void)hKey; (void)lpSubKey; (void)ulOptions; (void)samDesired;
    printf("[DRAWBRIDGE] RegOpenKeyExA(\"%s\") - stub\n", lpSubKey ? lpSubKey : "(null)");
    if (phkResult) *phkResult = 0xBAAD;
    return ERROR_SUCCESS;
}

LONG WINAPI stub_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
    LPSTR lpClass, DWORD dwOptions, DWORD samDesired, LPVOID lpSecurityAttributes,
    HKEY *phkResult, LPDWORD lpdwDisposition) {
    (void)hKey;(void)Reserved;(void)lpClass;(void)dwOptions;
    (void)samDesired;(void)lpSecurityAttributes;
    printf("[DRAWBRIDGE] RegCreateKeyExA(\"%s\") - stub\n", lpSubKey ? lpSubKey : "(null)");
    if (phkResult) *phkResult = 0xBAAD;
    if (lpdwDisposition) *lpdwDisposition = 1; /* REG_CREATED_NEW_KEY */
    return ERROR_SUCCESS;
}

LONG WINAPI stub_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved,
    DWORD dwType, const void *lpData, DWORD cbData) {
    (void)hKey;(void)Reserved;(void)dwType;(void)lpData;(void)cbData;
    printf("[DRAWBRIDGE] RegSetValueExA(\"%s\") - stub\n", lpValueName ? lpValueName : "(null)");
    return ERROR_SUCCESS;
}

LONG WINAPI stub_RegCloseKey(HKEY hKey) {
    (void)hKey;
    return ERROR_SUCCESS;
}

/* Service Control Manager stubs */
HANDLE WINAPI stub_OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess) {
    (void)lpMachineName;(void)lpDatabaseName;(void)dwDesiredAccess;
    printf("[DRAWBRIDGE] OpenSCManagerA() - stub\n");
    return (HANDLE)(intptr_t)0x5C00;
}

HANDLE WINAPI stub_OpenServiceA(HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess) {
    (void)hSCManager;(void)dwDesiredAccess;
    printf("[DRAWBRIDGE] OpenServiceA(\"%s\") - stub\n", lpServiceName ? lpServiceName : "(null)");
    return NULL; /* Service not found */
}

HANDLE WINAPI stub_CreateServiceA(HANDLE hSCManager, LPCSTR lpServiceName,
    LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType,
    DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName,
    LPCSTR a, LPDWORD b, LPCSTR c, LPCSTR d, LPCSTR e) {
    (void)hSCManager;(void)lpDisplayName;(void)dwDesiredAccess;
    (void)dwServiceType;(void)dwStartType;(void)dwErrorControl;
    (void)a;(void)b;(void)c;(void)d;(void)e;
    printf("[DRAWBRIDGE] CreateServiceA(\"%s\", bin=\"%s\") - blocked\n",
           lpServiceName ? lpServiceName : "(null)",
           lpBinaryPathName ? lpBinaryPathName : "(null)");
    return NULL;
}

BOOL WINAPI stub_StartServiceA(HANDLE hService, DWORD dwNumServiceArgs, LPCSTR *lpServiceArgVectors) {
    (void)hService;(void)dwNumServiceArgs;(void)lpServiceArgVectors;
    printf("[DRAWBRIDGE] StartServiceA() - blocked\n");
    return FALSE;
}

BOOL WINAPI stub_DeleteService(HANDLE hService) {
    (void)hService;
    return TRUE;
}

BOOL WINAPI stub_CloseServiceHandle(HANDLE hSCObject) {
    (void)hSCObject;
    return TRUE;
}

HANDLE WINAPI stub_RegisterServiceCtrlHandlerA(LPCSTR lpServiceName, LPVOID lpHandlerProc) {
    (void)lpServiceName;(void)lpHandlerProc;
    return (HANDLE)(intptr_t)1;
}

BOOL WINAPI stub_SetServiceStatus(HANDLE hServiceStatus, LPVOID lpServiceStatus) {
    (void)hServiceStatus;(void)lpServiceStatus;
    return TRUE;
}

BOOL WINAPI stub_StartServiceCtrlDispatcherA(LPVOID lpServiceStartTable) {
    (void)lpServiceStartTable;
    printf("[DRAWBRIDGE] StartServiceCtrlDispatcherA() - stub\n");
    return TRUE;
}

/* ---- msvcrt additional stubs ---- */
int stub_fprintf(void *stream, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vfprintf(stream ? stream : stderr, fmt, ap);
    va_end(ap); return n;
}

int stub_rand(void) { return rand(); }
void stub_srand(unsigned int seed) { srand(seed); }
int64_t stub_time(int64_t *t) {
    int64_t now = (int64_t)time(NULL);
    if (t) *t = now;
    return now;
}
char *stub_strcat(char *d, const char *s) { return strcat(d, s); }
char *stub_strcpy(char *d, const char *s) { return strcpy(d, s); }
void stub_abort(void) { abort(); }
int stub_atexit(void (*func)(void)) { return atexit(func); }

typedef void (*signal_handler_t)(int);
signal_handler_t stub_signal(int signum, signal_handler_t handler) {
    (void)signum; (void)handler;
    return NULL; /* SIG_DFL */
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
    /* New stubs for malware compatibility */
    {"KERNEL32.dll", "CreateFileA", stub_CreateFileA},
    {"KERNEL32.dll", "GetFileSize", stub_GetFileSize},
    {"KERNEL32.dll", "SetFilePointer", stub_SetFilePointer},
    {"KERNEL32.dll", "SetEndOfFile", stub_SetEndOfFile},
    {"KERNEL32.dll", "FlushFileBuffers", stub_FlushFileBuffers},
    {"KERNEL32.dll", "CopyFileA", stub_CopyFileA},
    {"KERNEL32.dll", "DeleteFileA", stub_DeleteFileA},
    {"KERNEL32.dll", "GetFileAttributesA", stub_GetFileAttributesA},
    {"KERNEL32.dll", "SetFileAttributesA", stub_SetFileAttributesA},
    {"KERNEL32.dll", "GetTempPathA", stub_GetTempPathA},
    {"KERNEL32.dll", "GetWindowsDirectoryA", stub_GetWindowsDirectoryA},
    {"KERNEL32.dll", "GetCurrentDirectoryA", stub_GetCurrentDirectoryA},
    {"KERNEL32.dll", "GetDriveTypeA", stub_GetDriveTypeA},
    {"KERNEL32.dll", "CreateMutexA", stub_CreateMutexA},
    {"KERNEL32.dll", "ReleaseMutex", stub_ReleaseMutex},
    {"KERNEL32.dll", "WaitForSingleObject", stub_WaitForSingleObject},
    {"KERNEL32.dll", "TlsAlloc", stub_TlsAlloc},
    {"KERNEL32.dll", "TlsGetValue", stub_TlsGetValue},
    {"KERNEL32.dll", "TlsSetValue", stub_TlsSetValue},
    {"KERNEL32.dll", "FindFirstFileA", stub_FindFirstFileA},
    {"KERNEL32.dll", "FindNextFileA", stub_FindNextFileA},
    {"KERNEL32.dll", "FindClose", stub_FindClose},
    {"KERNEL32.dll", "LoadLibraryA", stub_LoadLibraryA},
    {"KERNEL32.dll", "GetProcAddress", stub_GetProcAddress},
    {"KERNEL32.dll", "GetVersionExA", stub_GetVersionExA},
    {"KERNEL32.dll", "GetStartupInfoA", stub_GetStartupInfoA},
    {"KERNEL32.dll", "CreateProcessA", stub_CreateProcessA},
    {"KERNEL32.dll", "InterlockedIncrement", stub_InterlockedIncrement},
    {"KERNEL32.dll", "InterlockedDecrement", stub_InterlockedDecrement},
    {"KERNEL32.dll", "GetFileTime", stub_IsDebuggerPresent},  /* stub returns FALSE/0 */
    {"KERNEL32.dll", "SetFileTime", stub_IsDebuggerPresent},  /* stub */

    /* advapi32.dll */
    {"ADVAPI32.DLL", "RegOpenKeyExA", stub_RegOpenKeyExA},
    {"ADVAPI32.DLL", "RegCreateKeyExA", stub_RegCreateKeyExA},
    {"ADVAPI32.DLL", "RegSetValueExA", stub_RegSetValueExA},
    {"ADVAPI32.DLL", "RegCloseKey", stub_RegCloseKey},
    {"ADVAPI32.DLL", "OpenSCManagerA", stub_OpenSCManagerA},
    {"ADVAPI32.DLL", "OpenServiceA", stub_OpenServiceA},
    {"ADVAPI32.DLL", "CreateServiceA", stub_CreateServiceA},
    {"ADVAPI32.DLL", "StartServiceA", stub_StartServiceA},
    {"ADVAPI32.DLL", "DeleteService", stub_DeleteService},
    {"ADVAPI32.DLL", "CloseServiceHandle", stub_CloseServiceHandle},
    {"ADVAPI32.DLL", "RegisterServiceCtrlHandlerA", stub_RegisterServiceCtrlHandlerA},
    {"ADVAPI32.DLL", "SetServiceStatus", stub_SetServiceStatus},
    {"ADVAPI32.DLL", "StartServiceCtrlDispatcherA", stub_StartServiceCtrlDispatcherA},

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
    {"msvcrt.dll", "fprintf", stub_fprintf},
    {"msvcrt.dll", "rand", stub_rand},
    {"msvcrt.dll", "srand", stub_srand},
    {"msvcrt.dll", "time", stub_time},
    {"msvcrt.dll", "strcat", stub_strcat},
    {"msvcrt.dll", "strcpy", stub_strcpy},
    {"msvcrt.dll", "abort", stub_abort},
    {"msvcrt.dll", "atexit", stub_atexit},
    {"msvcrt.dll", "signal", stub_signal},
    {"msvcrt.dll", "_cexit", stub_exit},
    {"msvcrt.dll", "_fpreset", stub_IsDebuggerPresent},  /* nop */
    {"msvcrt.dll", "__set_app_type", stub_IsDebuggerPresent},  /* nop */
    {"msvcrt.dll", "__getmainargs", stub_IsDebuggerPresent},   /* nop */
    {"msvcrt.dll", "__p__environ", stub_GetCurrentProcess},    /* nop */
    {"msvcrt.dll", "_iob", stub_GetCurrentProcess},            /* nop */
    {"msvcrt.dll", "_fmode", stub_GetCurrentProcess},          /* nop */
    {"msvcrt.dll", "_fileno", stub_GetCurrentProcess},         /* nop */
    {"msvcrt.dll", "_setmode", stub_IsDebuggerPresent},        /* nop */
    {"msvcrt.dll", "_assert", stub_abort},

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
#ifdef HOST_32BIT
            /* 32-bit mode: stdcall uses stack args, same as cdecl on Linux.
             * No ABI translation needed - return stub directly. */
            return e->addr;
#else
            /* 64-bit mode: Windows x64 passes args in rcx,rdx,r8,r9
             * Linux SysV passes args in rdi,rsi,rdx,rcx,r8,r9
             * The thunk shuffles registers before calling our stub. */
            void *thunk = make_thunk(thunk_5arg, sizeof(thunk_5arg),
                                     19, e->addr);
            return thunk ? thunk : e->addr;
#endif
        }
    }
    return NULL;
}
