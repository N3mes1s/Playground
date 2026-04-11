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
#include <sys/sysinfo.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
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

/* ABI Convention:
 * In 64-bit mode: use ms_abi so the compiler translates Windows x64
 * calling convention (rcx, rdx, r8, r9) to SysV automatically.
 * This eliminates the need for hand-written thunks.
 * In 32-bit mode: stdcall (callee cleans stack). */
#ifdef HOST_32BIT
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI __attribute__((ms_abi))
#endif

/*
 * ABI Note: With ms_abi on all WINAPI stubs, the compiler handles
 * register translation automatically. No thunks needed.
 */

/* Memory flags */
#define MEM_COMMIT  0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40

/* Thread-local last error */
typedef void *HKEY;
static __thread DWORD tls_last_error = 0;

/* DATA exports for msvcrt - these must be actual data, not function pointers.
 * When malware imports _fmode or _iob as DATA, the IAT entry must point
 * to the variable, not to a function. */
static int msvcrt_fmode_data = 0;          /* _fmode: text/binary mode flag */

/* _iob: Array of 3 Windows FILE structures (each 64 bytes).
 * The mingw CRT accesses _iob[0] for stdin, _iob[1] for stdout, _iob[2] for stderr.
 * We store a magic value at offset 0 of each entry so our stubs can identify
 * which real FILE* to use. */
#define IOB_MAGIC_STDIN  0xDB10
#define IOB_MAGIC_STDOUT 0xDB11
#define IOB_MAGIC_STDERR 0xDB12
static uint8_t msvcrt_iob_data[3 * 64];
static int msvcrt_iob_initialized = 0;

static void init_iob(void) {
    if (msvcrt_iob_initialized) return;
    memset(msvcrt_iob_data, 0, sizeof(msvcrt_iob_data));
    /* Store magic values so stubs can map back to real FILE* */
    *(uint32_t*)(msvcrt_iob_data + 0 * 64) = IOB_MAGIC_STDIN;
    *(uint32_t*)(msvcrt_iob_data + 1 * 64) = IOB_MAGIC_STDOUT;
    *(uint32_t*)(msvcrt_iob_data + 2 * 64) = IOB_MAGIC_STDERR;
    msvcrt_iob_initialized = 1;
}

/* Map a Windows FILE* (pointing into our iob array) to a real Linux FILE* */
static FILE *map_win_file(void *stream) {
    if (!stream) return stdout;
    uintptr_t s = (uintptr_t)stream;
    uintptr_t base = (uintptr_t)msvcrt_iob_data;
    if (s >= base && s < base + sizeof(msvcrt_iob_data)) {
        int idx = (int)((s - base) / 64);
        switch (idx) {
            case 0: return stdin;
            case 1: return stdout;
            case 2: return stderr;
        }
    }
    /* Check magic values */
    uint32_t magic = *(uint32_t*)stream;
    if (magic == IOB_MAGIC_STDIN) return stdin;
    if (magic == IOB_MAGIC_STDOUT) return stdout;
    if (magic == IOB_MAGIC_STDERR) return stderr;
    /* Unknown - assume stdout */
    return stdout;
}

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

LPVOID WINAPI stub_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
    (void)hHeap; (void)dwFlags;
    return realloc(lpMem, dwBytes);
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

/* MSVCRT stubs - all use WINAPI (ms_abi) for correct ABI */
WINAPI int stub_puts(const char *str) {
    int n = printf("%s\n", str);
    return n;
}

WINAPI int stub_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

WINAPI int stub_sprintf(char *buf, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsprintf(buf, fmt, ap);
    va_end(ap);
    return n;
}

WINAPI void *stub_malloc(size_t size) { return malloc(size); }
WINAPI void  stub_free(void *ptr) { free(ptr); }
WINAPI void *stub_memset(void *s, int c, size_t n) { return memset(s, c, n); }
WINAPI void *stub_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
WINAPI size_t stub_strlen(const char *s) { return strlen(s); }
WINAPI int stub_strcmp(const char *a, const char *b) { return strcmp(a, b); }
WINAPI void stub_exit(int status) { _exit(status); }

WINAPI void *stub_calloc(size_t nmemb, size_t size) { return calloc(nmemb, size); }
WINAPI void *stub_realloc(void *ptr, size_t size) { return realloc(ptr, size); }

/* CRT init stubs */
WINAPI void stub_initterm(void **start, void **end) {
    while (start < end) {
        if (*start) ((void(WINAPI *)(void))(*start))();
        start++;
    }
}

WINAPI int stub_initterm_e(void **start, void **end) {
    while (start < end) {
        if (*start) {
            int ret = ((int(WINAPI *)(void))(*start))();
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
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        ssize_t w = write(dst, buf, n);
        (void)w;
    }
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

/* ---- Critical Sections (needed by WannaCry, updater_trojan) ---- */

typedef struct { pthread_mutex_t m; int init; } CRITICAL_SECTION_IMPL;

void WINAPI stub_InitializeCriticalSection(LPVOID lpCriticalSection) {
    CRITICAL_SECTION_IMPL *cs = (CRITICAL_SECTION_IMPL*)lpCriticalSection;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&cs->m, &attr);
    pthread_mutexattr_destroy(&attr);
    cs->init = 1;
}

void WINAPI stub_EnterCriticalSection(LPVOID lpCriticalSection) {
    CRITICAL_SECTION_IMPL *cs = (CRITICAL_SECTION_IMPL*)lpCriticalSection;
    if (!cs->init) stub_InitializeCriticalSection(lpCriticalSection);
    pthread_mutex_lock(&cs->m);
}

void WINAPI stub_LeaveCriticalSection(LPVOID lpCriticalSection) {
    CRITICAL_SECTION_IMPL *cs = (CRITICAL_SECTION_IMPL*)lpCriticalSection;
    pthread_mutex_unlock(&cs->m);
}

void WINAPI stub_DeleteCriticalSection(LPVOID lpCriticalSection) {
    CRITICAL_SECTION_IMPL *cs = (CRITICAL_SECTION_IMPL*)lpCriticalSection;
    if (cs->init) pthread_mutex_destroy(&cs->m);
    cs->init = 0;
}

BOOL WINAPI stub_InitializeCriticalSectionAndSpinCount(LPVOID lpCS, DWORD dwSpinCount) {
    (void)dwSpinCount;
    stub_InitializeCriticalSection(lpCS);
    return TRUE;
}

/* ---- VirtualProtect / VirtualQuery ---- */

BOOL WINAPI stub_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
                                 DWORD flNewProtect, DWORD *lpflOldProtect) {
    if (lpflOldProtect) *lpflOldProtect = 0x04; /* PAGE_READWRITE */
    int prot = PROT_READ | PROT_WRITE;
    if (flNewProtect & 0x40) prot |= PROT_EXEC; /* PAGE_EXECUTE_READWRITE */
    if (flNewProtect & 0x20) prot = PROT_READ | PROT_EXEC;
    mprotect(lpAddress, dwSize, prot);
    return TRUE;
}

SIZE_T WINAPI stub_VirtualQuery(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T dwLength) {
    (void)lpAddress;
    if (lpBuffer && dwLength >= 28) memset(lpBuffer, 0, dwLength);
    return dwLength;
}

/* ---- Unicode (W) variants ---- */

HANDLE WINAPI stub_CreateFileW(const void *lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPVOID lpSecAttr, DWORD dwCreation, DWORD dwFlags, HANDLE hTpl) {
    /* Convert wchar to char (ASCII only for PoC) */
    const uint16_t *w = (const uint16_t*)lpFileName;
    char buf[512]; int i;
    for (i = 0; w[i] && i < 511; i++) buf[i] = (char)(w[i] & 0xFF);
    buf[i] = 0;
    return stub_CreateFileA(buf, dwDesiredAccess, dwShareMode, lpSecAttr, dwCreation, dwFlags, hTpl);
}

DWORD WINAPI stub_GetFileAttributesW(const void *lpFileName) {
    const uint16_t *w = (const uint16_t*)lpFileName;
    char buf[512]; int i;
    for (i = 0; w[i] && i < 511; i++) buf[i] = (char)(w[i] & 0xFF);
    buf[i] = 0;
    return stub_GetFileAttributesA(buf);
}

BOOL WINAPI stub_SetFileAttributesW(const void *lpFileName, DWORD dwFileAttributes) {
    (void)lpFileName; (void)dwFileAttributes;
    return TRUE;
}

BOOL WINAPI stub_CreateDirectoryA(LPCSTR lpPathName, LPVOID lpSecurityAttributes) {
    (void)lpSecurityAttributes;
    mkdir(lpPathName, 0755);
    return TRUE;
}

BOOL WINAPI stub_CreateDirectoryW(const void *lpPathName, LPVOID lpSecurityAttributes) {
    const uint16_t *w = (const uint16_t*)lpPathName;
    char buf[512]; int i;
    for (i = 0; w[i] && i < 511; i++) buf[i] = (char)(w[i] & 0xFF);
    buf[i] = 0;
    return stub_CreateDirectoryA(buf, lpSecurityAttributes);
}

BOOL WINAPI stub_SetCurrentDirectoryA(LPCSTR lpPathName) {
    return chdir(lpPathName) == 0;
}

BOOL WINAPI stub_SetCurrentDirectoryW(const void *lpPathName) {
    const uint16_t *w = (const uint16_t*)lpPathName;
    char buf[512]; int i;
    for (i = 0; w[i] && i < 511; i++) buf[i] = (char)(w[i] & 0xFF);
    buf[i] = 0;
    return stub_SetCurrentDirectoryA(buf);
}

DWORD WINAPI stub_GetTempPathW(DWORD nBufLen, void *lpBuffer) {
    uint16_t *w = (uint16_t*)lpBuffer;
    const char *tmp = "/tmp/";
    int i;
    for (i = 0; tmp[i] && (DWORD)i < nBufLen - 1; i++) w[i] = tmp[i];
    w[i] = 0;
    return (DWORD)i;
}

DWORD WINAPI stub_GetWindowsDirectoryW(void *lpBuffer, DWORD uSize) {
    uint16_t *w = (uint16_t*)lpBuffer;
    const char *dir = "C:\\Windows";
    int i;
    for (i = 0; dir[i] && (DWORD)i < uSize - 1; i++) w[i] = dir[i];
    w[i] = 0;
    return (DWORD)i;
}

DWORD WINAPI stub_GetComputerNameW(void *lpBuffer, DWORD *nSize) {
    uint16_t *w = (uint16_t*)lpBuffer;
    const char *name = "DRAWBRIDGE";
    DWORD i;
    for (i = 0; name[i] && i < *nSize - 1; i++) w[i] = name[i];
    w[i] = 0;
    *nSize = i;
    return TRUE;
}

int WINAPI stub_MultiByteToWideChar(DWORD CodePage, DWORD dwFlags,
    LPCSTR lpMBStr, int cbMB, void *lpWCStr, int cchWC) {
    (void)CodePage; (void)dwFlags;
    if (cbMB == -1) cbMB = (int)strlen(lpMBStr) + 1;
    if (!lpWCStr || cchWC == 0) return cbMB;
    uint16_t *w = (uint16_t*)lpWCStr;
    int i;
    for (i = 0; i < cbMB && i < cchWC; i++) w[i] = (uint8_t)lpMBStr[i];
    return i;
}

int WINAPI stub_WideCharToMultiByte(DWORD CodePage, DWORD dwFlags,
    const void *lpWCStr, int cchWC, LPSTR lpMBStr, int cbMB,
    LPCSTR lpDefault, BOOL *lpUsed) {
    (void)CodePage; (void)dwFlags; (void)lpDefault; (void)lpUsed;
    const uint16_t *w = (const uint16_t*)lpWCStr;
    if (cchWC == -1) { int n = 0; while (w[n]) n++; cchWC = n + 1; }
    if (!lpMBStr || cbMB == 0) return cchWC;
    int i;
    for (i = 0; i < cchWC && i < cbMB; i++) lpMBStr[i] = (char)(w[i] & 0xFF);
    return i;
}

DWORD WINAPI stub_GetFullPathNameA(LPCSTR lpFileName, DWORD nBufLen,
                                     LPSTR lpBuffer, LPSTR *lpFilePart) {
    if (!lpFileName) return 0;
    size_t len = strlen(lpFileName);
    if (len >= nBufLen) return (DWORD)(len + 1);
    memcpy(lpBuffer, lpFileName, len + 1);
    if (lpFilePart) {
        char *p = lpBuffer + len;
        while (p > lpBuffer && *(p-1) != '\\' && *(p-1) != '/') p--;
        *lpFilePart = p;
    }
    return (DWORD)len;
}

HANDLE WINAPI stub_OpenMutexA(DWORD dwDesiredAccess, BOOL bInherit, LPCSTR lpName) {
    (void)dwDesiredAccess; (void)bInherit; (void)lpName;
    return NULL; /* Mutex doesn't exist */
}

void WINAPI stub_FreeLibrary(HANDLE hLibModule) { (void)hLibModule; }

BOOL WINAPI stub_IsBadReadPtr(LPCVOID lp, SIZE_T ucb) { (void)lp; (void)ucb; return FALSE; }

DWORD WINAPI stub_GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode) {
    (void)hProcess;
    if (lpExitCode) *lpExitCode = 0;
    return TRUE;
}

void WINAPI stub_TerminateProcess(HANDLE hProcess, DWORD uExitCode) {
    (void)hProcess;
    printf("[DRAWBRIDGE] TerminateProcess(%u) - blocked\n", uExitCode);
}

DWORD WINAPI stub_GetFileSizeEx(HANDLE hFile, void *lpFileSize) {
    struct stat st;
    if (fstat((int)(intptr_t)hFile, &st) < 0) return FALSE;
    if (lpFileSize) *(int64_t*)lpFileSize = st.st_size;
    return TRUE;
}

void WINAPI stub_SystemTimeToFileTime(LPVOID lpSysTime, LPVOID lpFileTime) {
    *(uint64_t*)lpFileTime = 0;
}

void WINAPI stub_LocalFileTimeToFileTime(LPVOID lpLocal, LPVOID lpFileTime) {
    if (lpLocal && lpFileTime) *(uint64_t*)lpFileTime = *(uint64_t*)lpLocal;
}

/* Resource stubs */
HANDLE WINAPI stub_FindResourceA(HANDLE hModule, LPCSTR lpName, LPCSTR lpType) {
    (void)hModule; (void)lpName; (void)lpType;
    return NULL;
}

HANDLE WINAPI stub_LoadResource(HANDLE hModule, HANDLE hResInfo) {
    (void)hModule; (void)hResInfo;
    return NULL;
}

LPVOID WINAPI stub_LockResource(HANDLE hResData) { (void)hResData; return NULL; }
DWORD  WINAPI stub_SizeofResource(HANDLE hModule, HANDLE hResInfo) {
    (void)hModule; (void)hResInfo; return 0;
}

LPVOID WINAPI stub_GlobalAlloc(DWORD uFlags, SIZE_T dwBytes) {
    (void)uFlags;
    return malloc(dwBytes);
}

HANDLE WINAPI stub_GlobalFree(LPVOID hMem) { free(hMem); return NULL; }

/* ---- Crypto stubs (advapi32) ---- */
/* HKEY typedef needed here if not already defined */
BOOL WINAPI stub_CryptAcquireContextA(LPVOID phProv, LPCSTR a, LPCSTR b, DWORD c, DWORD d) {
    (void)a;(void)b;(void)c;(void)d;
    if (phProv) *(void**)phProv = (void*)(intptr_t)0xC9D0;
    return TRUE;
}
BOOL WINAPI stub_CryptAcquireContextW(LPVOID phProv, const void *a, const void *b, DWORD c, DWORD d) {
    (void)a;(void)b;(void)c;(void)d;
    if (phProv) *(void**)phProv = (void*)(intptr_t)0xC9D0;
    return TRUE;
}
BOOL WINAPI stub_CryptReleaseContext(HANDLE hProv, DWORD dwFlags) { (void)hProv;(void)dwFlags; return TRUE; }
BOOL WINAPI stub_CryptGenRandom(HANDLE hProv, DWORD dwLen, void *pbBuffer) {
    (void)hProv;
    /* Use real randomness from Linux */
    ssize_t ret = getrandom(pbBuffer, dwLen, 0);
    (void)ret;
    return TRUE;
}
BOOL WINAPI stub_CryptCreateHash(HANDLE hProv, DWORD algId, HANDLE hKey, DWORD dwFlags, LPVOID phHash) {
    (void)hProv;(void)algId;(void)hKey;(void)dwFlags;
    if (phHash) *(void**)phHash = (void*)(intptr_t)0xA5A5;
    return TRUE;
}
BOOL WINAPI stub_CryptHashData(HANDLE hHash, const void *pbData, DWORD dwDataLen, DWORD dwFlags) {
    (void)hHash;(void)pbData;(void)dwDataLen;(void)dwFlags; return TRUE;
}
BOOL WINAPI stub_CryptGetHashParam(HANDLE hHash, DWORD dwParam, void *pbData, DWORD *pdwDataLen, DWORD dwFlags) {
    (void)hHash;(void)dwParam;(void)dwFlags;
    if (pbData && pdwDataLen) memset(pbData, 0, *pdwDataLen);
    return TRUE;
}
BOOL WINAPI stub_CryptDestroyHash(HANDLE hHash) { (void)hHash; return TRUE; }
BOOL WINAPI stub_CryptGenKey(HANDLE hProv, DWORD algId, DWORD dwFlags, LPVOID phKey) {
    (void)hProv;(void)algId;(void)dwFlags;
    if (phKey) *(void**)phKey = (void*)(intptr_t)0x0AE5;
    return TRUE;
}
BOOL WINAPI stub_CryptDestroyKey(HANDLE hKey) { (void)hKey; return TRUE; }
BOOL WINAPI stub_CryptEncrypt(HANDLE hKey, HANDLE hHash, BOOL Final, DWORD dwFlags,
    void *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {
    (void)hKey;(void)hHash;(void)Final;(void)dwFlags;(void)pbData;(void)pdwDataLen;(void)dwBufLen;
    return TRUE;
}
BOOL WINAPI stub_CryptImportKey(HANDLE hProv, const void *pbData, DWORD dwDataLen,
    HANDLE hPubKey, DWORD dwFlags, LPVOID phKey) {
    (void)hProv;(void)pbData;(void)dwDataLen;(void)hPubKey;(void)dwFlags;
    if (phKey) *(void**)phKey = (void*)(intptr_t)0x0AE5;
    return TRUE;
}
BOOL WINAPI stub_CryptExportKey(HANDLE hKey, HANDLE hExpKey, DWORD dwBlobType,
    DWORD dwFlags, void *pbData, DWORD *pdwDataLen) {
    (void)hKey;(void)hExpKey;(void)dwBlobType;(void)dwFlags;(void)pbData;(void)pdwDataLen;
    return FALSE; /* Not supported */
}
BOOL WINAPI stub_CryptSetKeyParam(HANDLE hKey, DWORD dwParam, const void *pbData, DWORD dwFlags) {
    (void)hKey;(void)dwParam;(void)pbData;(void)dwFlags; return TRUE;
}

/* Registry extras */
LONG WINAPI stub_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, void *lpData, LPDWORD lpcbData) {
    (void)hKey;(void)lpValueName;(void)lpReserved;(void)lpType;(void)lpData;(void)lpcbData;
    return 2; /* ERROR_FILE_NOT_FOUND */
}
LONG WINAPI stub_RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) { (void)hKey;(void)lpSubKey; return 0; }
LONG WINAPI stub_RegDeleteValueA(HKEY hKey, LPCSTR lpValueName) { (void)hKey;(void)lpValueName; return 0; }
LONG WINAPI stub_RegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName) {
    (void)hKey;(void)dwIndex;(void)lpName;(void)cchName; return 259; /* ERROR_NO_MORE_ITEMS */
}
LONG WINAPI stub_RegCreateKeyW(HKEY hKey, const void *lpSubKey, HKEY *phkResult) {
    (void)hKey;(void)lpSubKey;
    if (phkResult) *phkResult = (HKEY)(intptr_t)0xBAAD;
    return 0;
}

/* Security stubs */
BOOL WINAPI stub_InitializeSecurityDescriptor(LPVOID pSD, DWORD dwRevision) {
    (void)dwRevision; if (pSD) memset(pSD, 0, 20); return TRUE;
}
BOOL WINAPI stub_SetSecurityDescriptorDacl(LPVOID pSD, BOOL bDaclPresent, LPVOID pDacl, BOOL bDefault) {
    (void)pSD;(void)bDaclPresent;(void)pDacl;(void)bDefault; return TRUE;
}

/* ---- advapi32.dll stubs ---- */

#define ERROR_SUCCESS 0

LONG WINAPI stub_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
                                DWORD samDesired, HKEY *phkResult) {
    (void)hKey; (void)lpSubKey; (void)ulOptions; (void)samDesired;
    printf("[DRAWBRIDGE] RegOpenKeyExA(\"%s\") - stub\n", lpSubKey ? lpSubKey : "(null)");
    if (phkResult) *phkResult = (HKEY)(intptr_t)0xBAAD;
    return ERROR_SUCCESS;
}

LONG WINAPI stub_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
    LPSTR lpClass, DWORD dwOptions, DWORD samDesired, LPVOID lpSecurityAttributes,
    HKEY *phkResult, LPDWORD lpdwDisposition) {
    (void)hKey;(void)Reserved;(void)lpClass;(void)dwOptions;
    (void)samDesired;(void)lpSecurityAttributes;
    printf("[DRAWBRIDGE] RegCreateKeyExA(\"%s\") - stub\n", lpSubKey ? lpSubKey : "(null)");
    if (phkResult) *phkResult = (HKEY)(intptr_t)0xBAAD;
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
WINAPI int stub_fprintf(void *stream, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vfprintf(stream ? (FILE*)stream : stderr, fmt, ap);
    va_end(ap); return n;
}

WINAPI int stub_rand(void) { return rand(); }
WINAPI void stub_srand(unsigned int seed) { srand(seed); }
WINAPI int64_t stub_time(int64_t *t) {
    int64_t now = (int64_t)time(NULL);
    if (t) *t = now;
    return now;
}
WINAPI char *stub_strcat(char *d, const char *s) { return strcat(d, s); }
WINAPI char *stub_strcpy(char *d, const char *s) { return strcpy(d, s); }
WINAPI void stub_abort(void) { abort(); }
WINAPI int stub_atexit(void (*func)(void)) { (void)func; return 0; }

typedef void (*signal_handler_t)(int);
WINAPI signal_handler_t stub_signal(int signum, signal_handler_t handler) {
    (void)signum; (void)handler;
    return NULL; /* SIG_DFL */
}

/* ---- kernel32 additional stubs for full_test/hello_drawbridge ---- */

BOOL WINAPI stub_GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize) {
    const char *name = "DRAWBRIDGE";
    DWORD len = (DWORD)strlen(name);
    if (len >= *nSize) { *nSize = len + 1; return FALSE; }
    memcpy(lpBuffer, name, len + 1);
    *nSize = len;
    return TRUE;
}

void WINAPI stub_GetSystemInfo(void *lpSystemInfo) {
    /* Minimal SYSTEM_INFO: page size and processor count */
    memset(lpSystemInfo, 0, 48);
    uint32_t *si = (uint32_t*)lpSystemInfo;
    si[0] = 9;   /* wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 */
    si[1] = 4096; /* dwPageSize */
    /* dwNumberOfProcessors at offset 20 (32-bit) or similar */
    si[5] = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
    si[8] = 6;   /* dwProcessorType */
    si[9] = 4096; /* dwAllocationGranularity */
}

void WINAPI stub_GlobalMemoryStatus(void *lpBuffer) {
    /* MEMORYSTATUS structure */
    uint32_t *ms = (uint32_t*)lpBuffer;
    struct sysinfo si;
    sysinfo(&si);
    ms[0] = 32;  /* dwLength */
    ms[1] = 50;  /* dwMemoryLoad */
    /* Store as 32-bit values (MEMORYSTATUS uses DWORD) */
    ms[2] = (uint32_t)(si.totalram * si.mem_unit);  /* dwTotalPhys */
    ms[3] = (uint32_t)(si.freeram * si.mem_unit);    /* dwAvailPhys */
    ms[4] = (uint32_t)(si.totalswap * si.mem_unit);  /* dwTotalPageFile */
    ms[5] = (uint32_t)(si.freeswap * si.mem_unit);   /* dwAvailPageFile */
    ms[6] = 0x7FFE0000;  /* dwTotalVirtual */
    ms[7] = 0x7FFD0000;  /* dwAvailVirtual */
}

BOOL WINAPI stub_IsDBCSLeadByteEx(DWORD CodePage, DWORD TestChar) {
    (void)CodePage; (void)TestChar;
    return FALSE;
}

HANDLE WINAPI stub_CreateEventA(LPVOID lpAttributes, BOOL bManualReset,
                                 BOOL bInitialState, LPCSTR lpName) {
    (void)lpAttributes; (void)lpName; (void)bManualReset;
    int efd = eventfd(bInitialState ? 1 : 0, EFD_NONBLOCK);
    if (efd < 0) return NULL;
    return (HANDLE)(intptr_t)efd;
}

BOOL WINAPI stub_SetEvent(HANDLE hEvent) {
    uint64_t val = 1;
    ssize_t r = write((int)(intptr_t)hEvent, &val, sizeof(val));
    (void)r;
    return TRUE;
}

BOOL WINAPI stub_ResetEvent(HANDLE hEvent) {
    uint64_t val;
    ssize_t r = read((int)(intptr_t)hEvent, &val, sizeof(val));
    (void)r;
    return TRUE;
}

DWORD WINAPI stub_GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode) {
    (void)hThread;
    if (lpExitCode) *lpExitCode = 0;
    return TRUE;
}

void WINAPI stub_GetStartupInfoW(void *lpStartupInfo) {
    memset(lpStartupInfo, 0, 104); /* sizeof(STARTUPINFOW) on x64 */
    *(uint32_t*)lpStartupInfo = 104; /* cb */
}

/* ---- msvcrt additional stubs for CRT init ---- */

static int msvcrt_errno_val = 0;
static int msvcrt_commode_val = 0;
static char **msvcrt_initenv_ptr = NULL;  /* __initenv: pointer to char** */

WINAPI int *stub_errno(void) { return &msvcrt_errno_val; }
WINAPI int *stub_commode(void) { return &msvcrt_commode_val; }
WINAPI void *stub___iob_func(void) {
    /* Return pointer to an array of 3 FILE* (stdin, stdout, stderr).
     * The mingw CRT indexes this: __iob_func()[0]=stdin, [1]=stdout, [2]=stderr.
     * We store the actual Linux FILE pointers. */
    static FILE *iob[3];
    static int init = 0;
    if (!init) { iob[0] = stdin; iob[1] = stdout; iob[2] = stderr; init = 1; }
    return iob;
}
WINAPI void *stub___initenv(void) { return &msvcrt_initenv_ptr; }
WINAPI int stub___lc_codepage_func(void) { return 0; }
WINAPI int stub___mb_cur_max_func(void) { return 1; }
WINAPI void stub___setusermatherr(void *handler) { (void)handler; }
WINAPI void stub__amsg_exit(int rterrnum) { (void)rterrnum; _exit(255); }

WINAPI void *stub__onexit(void *func) { (void)func; return func; }

WINAPI int stub_fputc(int c, void *stream) {
    return fputc(c, stream ? (FILE*)stream : stdout);
}

WINAPI size_t stub_fwrite(const void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, stream ? (FILE*)stream : stdout);
}

WINAPI int stub_vfprintf_impl(void *stream, const char *fmt, va_list ap) {
    return vfprintf(stream ? (FILE*)stream : stderr, fmt, ap);
}

WINAPI void *stub_localeconv(void) {
    static struct { char *decimal_point; char *thousands_sep; } lc = { ".", "" };
    return &lc;
}

WINAPI char *stub_strerror(int errnum) {
    return strerror(errnum);
}

WINAPI int stub_strncmp(const char *a, const char *b, size_t n) {
    return strncmp(a, b, n);
}

WINAPI size_t stub_wcslen(const void *s) {
    const uint16_t *w = (const uint16_t*)s;
    size_t len = 0;
    while (w[len]) len++;
    return len;
}

WINAPI void *stub___C_specific_handler(void) { return NULL; }

/* __getmainargs populates argc, argv, envp for the CRT startup.
 * Windows signature: int __getmainargs(int *argc, char ***argv,
 *                                       char ***envp, int doWildcard,
 *                                       void *startInfo) */
static char *dummy_argv[] = { "drawbridge.exe", NULL };
static char *dummy_envp[] = { NULL };

WINAPI int stub___getmainargs(int *_argc, char ***_argv,
                              char ***_envp, int doWild, void *startInfo) {
    (void)doWild; (void)startInfo;
    if (_argc) *_argc = 1;
    if (_argv) *_argv = dummy_argv;
    if (_envp) *_envp = dummy_envp;
    return 0;
}

/* __p__environ returns a pointer to the _environ variable */
WINAPI char ***stub___p__environ(void) {
    static char **env_ptr = NULL;
    if (!env_ptr) env_ptr = dummy_envp;
    return &env_ptr;
}

/* __p__fmode returns pointer to _fmode */
WINAPI int *stub___p__fmode(void) {
    return &msvcrt_fmode_data;
}

/* ---- WS2_32 (Winsock) stubs ---- */

/* WSADATA structure (at least 400 bytes on Windows) */
typedef struct {
    uint16_t wVersion;
    uint16_t wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    uint16_t iMaxSockets;
    uint16_t iMaxUdpDg;
    char *lpVendorInfo;
} WSADATA_STUB;

WINAPI int stub_WSAStartup(uint16_t wVersionRequested, WSADATA_STUB *lpWSAData) {
    if (lpWSAData) {
        memset(lpWSAData, 0, sizeof(*lpWSAData));
        lpWSAData->wVersion = wVersionRequested;
        lpWSAData->wHighVersion = 0x0202;  /* 2.2 */
        strcpy(lpWSAData->szDescription, "Drawbridge Winsock");
    }
    return 0;  /* Success */
}

WINAPI int stub_WSACleanup(void) { return 0; }

WINAPI uint64_t stub_socket(int af, int type, int protocol) {
    int fd = socket(af, type, protocol);
    if (fd < 0) return (uint64_t)-1;  /* INVALID_SOCKET */
    return (uint64_t)fd;
}

WINAPI int stub_connect(uint64_t s, const struct sockaddr *name, int namelen) {
    int ret = connect((int)s, name, (socklen_t)namelen);
    return ret;  /* 0 = success, -1 = error */
}

WINAPI int stub_closesocket(uint64_t s) {
    return close((int)s);
}

WINAPI uint16_t stub_htons(uint16_t hostshort) {
    return htons(hostshort);
}

WINAPI uint32_t stub_inet_addr(const char *cp) {
    return inet_addr(cp);
}

WINAPI int stub_getaddrinfo(const char *node, const char *service,
                            const struct addrinfo *hints,
                            struct addrinfo **res) {
    return getaddrinfo(node, service, hints, res);
}

WINAPI void stub_freeaddrinfo(struct addrinfo *res) {
    freeaddrinfo(res);
}

/* ---- msvcrt lock stubs ---- */
static pthread_mutex_t msvcrt_locks[64] = { [0 ... 63] = PTHREAD_MUTEX_INITIALIZER };

WINAPI void stub__lock(int locknum) {
    if (locknum >= 0 && locknum < 64)
        pthread_mutex_lock(&msvcrt_locks[locknum]);
}

WINAPI void stub__unlock(int locknum) {
    if (locknum >= 0 && locknum < 64)
        pthread_mutex_unlock(&msvcrt_locks[locknum]);
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
    {"KERNEL32.dll", "HeapReAlloc", stub_HeapReAlloc},
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
    {"KERNEL32.dll", "GetFileTime", stub_IsDebuggerPresent},
    {"KERNEL32.dll", "SetFileTime", stub_IsDebuggerPresent},
    /* Critical sections */
    {"KERNEL32.dll", "InitializeCriticalSection", stub_InitializeCriticalSection},
    {"KERNEL32.dll", "InitializeCriticalSectionAndSpinCount", stub_InitializeCriticalSectionAndSpinCount},
    {"KERNEL32.dll", "EnterCriticalSection", stub_EnterCriticalSection},
    {"KERNEL32.dll", "LeaveCriticalSection", stub_LeaveCriticalSection},
    {"KERNEL32.dll", "DeleteCriticalSection", stub_DeleteCriticalSection},
    /* Memory */
    {"KERNEL32.dll", "VirtualProtect", stub_VirtualProtect},
    {"KERNEL32.dll", "VirtualQuery", stub_VirtualQuery},
    /* Unicode W variants */
    {"KERNEL32.dll", "CreateFileW", stub_CreateFileW},
    {"KERNEL32.dll", "GetFileAttributesW", stub_GetFileAttributesW},
    {"KERNEL32.dll", "SetFileAttributesW", stub_SetFileAttributesW},
    {"KERNEL32.dll", "CreateDirectoryA", stub_CreateDirectoryA},
    {"KERNEL32.dll", "CreateDirectoryW", stub_CreateDirectoryW},
    {"KERNEL32.dll", "SetCurrentDirectoryA", stub_SetCurrentDirectoryA},
    {"KERNEL32.dll", "SetCurrentDirectoryW", stub_SetCurrentDirectoryW},
    {"KERNEL32.dll", "GetTempPathW", stub_GetTempPathW},
    {"KERNEL32.dll", "GetWindowsDirectoryW", stub_GetWindowsDirectoryW},
    {"KERNEL32.dll", "GetComputerNameW", stub_GetComputerNameW},
    {"KERNEL32.dll", "MultiByteToWideChar", stub_MultiByteToWideChar},
    {"KERNEL32.dll", "WideCharToMultiByte", stub_WideCharToMultiByte},
    {"KERNEL32.dll", "GetFullPathNameA", stub_GetFullPathNameA},
    {"KERNEL32.dll", "OpenMutexA", stub_OpenMutexA},
    {"KERNEL32.dll", "FreeLibrary", stub_FreeLibrary},
    {"KERNEL32.dll", "IsBadReadPtr", stub_IsBadReadPtr},
    {"KERNEL32.dll", "GetExitCodeProcess", stub_GetExitCodeProcess},
    {"KERNEL32.dll", "TerminateProcess", stub_TerminateProcess},
    {"KERNEL32.dll", "GetFileSizeEx", stub_GetFileSizeEx},
    {"KERNEL32.dll", "SystemTimeToFileTime", stub_SystemTimeToFileTime},
    {"KERNEL32.dll", "LocalFileTimeToFileTime", stub_LocalFileTimeToFileTime},
    {"KERNEL32.dll", "FindResourceA", stub_FindResourceA},
    {"KERNEL32.dll", "LoadResource", stub_LoadResource},
    {"KERNEL32.dll", "LockResource", stub_LockResource},
    {"KERNEL32.dll", "SizeofResource", stub_SizeofResource},
    {"KERNEL32.dll", "GlobalAlloc", stub_GlobalAlloc},
    {"KERNEL32.dll", "GlobalFree", stub_GlobalFree},
    {"KERNEL32.dll", "GetComputerNameA", stub_GetComputerNameA},
    {"KERNEL32.dll", "GetSystemInfo", stub_GetSystemInfo},
    {"KERNEL32.dll", "GlobalMemoryStatus", stub_GlobalMemoryStatus},
    {"KERNEL32.dll", "IsDBCSLeadByteEx", stub_IsDBCSLeadByteEx},
    {"KERNEL32.dll", "CreateEventA", stub_CreateEventA},
    {"KERNEL32.dll", "SetEvent", stub_SetEvent},
    {"KERNEL32.dll", "ResetEvent", stub_ResetEvent},
    {"KERNEL32.dll", "GetExitCodeThread", stub_GetExitCodeThread},
    {"KERNEL32.dll", "GetStartupInfoW", stub_GetStartupInfoW},

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
    /* Crypto */
    {"ADVAPI32.DLL", "CryptAcquireContextA", stub_CryptAcquireContextA},
    {"ADVAPI32.DLL", "CryptAcquireContextW", stub_CryptAcquireContextW},
    {"ADVAPI32.DLL", "CryptReleaseContext", stub_CryptReleaseContext},
    {"ADVAPI32.DLL", "CryptGenRandom", stub_CryptGenRandom},
    {"ADVAPI32.DLL", "CryptCreateHash", stub_CryptCreateHash},
    {"ADVAPI32.DLL", "CryptHashData", stub_CryptHashData},
    {"ADVAPI32.DLL", "CryptGetHashParam", stub_CryptGetHashParam},
    {"ADVAPI32.DLL", "CryptDestroyHash", stub_CryptDestroyHash},
    {"ADVAPI32.DLL", "CryptGenKey", stub_CryptGenKey},
    {"ADVAPI32.DLL", "CryptDestroyKey", stub_CryptDestroyKey},
    {"ADVAPI32.DLL", "CryptEncrypt", stub_CryptEncrypt},
    {"ADVAPI32.DLL", "CryptImportKey", stub_CryptImportKey},
    {"ADVAPI32.DLL", "CryptExportKey", stub_CryptExportKey},
    {"ADVAPI32.DLL", "CryptSetKeyParam", stub_CryptSetKeyParam},
    /* Registry extras */
    {"ADVAPI32.DLL", "RegQueryValueExA", stub_RegQueryValueExA},
    {"ADVAPI32.DLL", "RegDeleteKeyA", stub_RegDeleteKeyA},
    {"ADVAPI32.DLL", "RegDeleteValueA", stub_RegDeleteValueA},
    {"ADVAPI32.DLL", "RegEnumKeyA", stub_RegEnumKeyA},
    {"ADVAPI32.DLL", "RegCreateKeyW", stub_RegCreateKeyW},
    /* Security */
    {"ADVAPI32.DLL", "InitializeSecurityDescriptor", stub_InitializeSecurityDescriptor},
    {"ADVAPI32.DLL", "SetSecurityDescriptorDacl", stub_SetSecurityDescriptorDacl},

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
    {"msvcrt.dll", "__set_app_type", stub___setusermatherr},    /* nop - takes 1 arg */
    {"msvcrt.dll", "__getmainargs", stub___getmainargs},
    {"msvcrt.dll", "__p__environ", stub___p__environ},
    {"msvcrt.dll", "__p__fmode", stub___p__fmode},

    /* DATA imports: _iob and _fmode must point to actual data, not functions.
     * The IAT entry gets set to the ADDRESS of the data. */
    {"msvcrt.dll", "_iob", (void*)&msvcrt_iob_data},
    {"msvcrt.dll", "_fmode", (void*)&msvcrt_fmode_data},
    {"msvcrt.dll", "_fileno", stub_GetCurrentProcess},         /* nop */
    {"msvcrt.dll", "_setmode", stub_IsDebuggerPresent},        /* nop */
    {"msvcrt.dll", "_assert", stub_abort},
    {"msvcrt.dll", "__C_specific_handler", stub___C_specific_handler},
    {"msvcrt.dll", "___lc_codepage_func", stub___lc_codepage_func},
    {"msvcrt.dll", "___mb_cur_max_func", stub___mb_cur_max_func},
    {"msvcrt.dll", "__initenv", (void*)&msvcrt_initenv_ptr},
    {"msvcrt.dll", "__iob_func", stub___iob_func},
    {"msvcrt.dll", "__setusermatherr", stub___setusermatherr},
    {"msvcrt.dll", "_amsg_exit", stub__amsg_exit},
    {"msvcrt.dll", "_commode", (void*)&msvcrt_commode_val},
    {"msvcrt.dll", "_errno", stub_errno},
    {"msvcrt.dll", "_onexit", stub__onexit},
    {"msvcrt.dll", "fputc", stub_fputc},
    {"msvcrt.dll", "fwrite", stub_fwrite},
    {"msvcrt.dll", "localeconv", stub_localeconv},
    {"msvcrt.dll", "strerror", stub_strerror},
    {"msvcrt.dll", "strncmp", stub_strncmp},
    {"msvcrt.dll", "vfprintf", stub_vfprintf_impl},
    {"msvcrt.dll", "wcslen", stub_wcslen},
    {"msvcrt.dll", "sprintf", stub_sprintf},

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

    /* WS2_32.dll (Winsock) */
    {"WS2_32.dll", "WSAStartup", stub_WSAStartup},
    {"WS2_32.dll", "WSACleanup", stub_WSACleanup},
    {"WS2_32.dll", "socket", stub_socket},
    {"WS2_32.dll", "connect", stub_connect},
    {"WS2_32.dll", "closesocket", stub_closesocket},
    {"WS2_32.dll", "htons", stub_htons},
    {"WS2_32.dll", "inet_addr", stub_inet_addr},
    {"WS2_32.dll", "getaddrinfo", stub_getaddrinfo},
    {"WS2_32.dll", "freeaddrinfo", stub_freeaddrinfo},

    /* msvcrt locks */
    {"msvcrt.dll", "_lock", stub__lock},
    {"msvcrt.dll", "_unlock", stub__unlock},

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
            /* With ms_abi on all stubs, the compiler handles ABI
             * translation automatically. Return function pointer directly. */
            return e->addr;
        }
    }
    return NULL;
}
