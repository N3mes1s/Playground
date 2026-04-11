#ifndef WIN32_STUBS_H
#define WIN32_STUBS_H

#include <stdint.h>
#include <stddef.h>

/*
 * Minimal Win32 API stubs (Library OS layer)
 *
 * These implement the Windows API functions that our test programs
 * call, translating them to PAL operations. This is the essence
 * of the Drawbridge library OS concept.
 *
 * In a full implementation, these would be complete reimplementations
 * of kernel32.dll, ntdll.dll, etc. For our PoC, we implement just
 * enough to run simple console programs.
 */

/* ---- Windows type definitions ---- */

typedef int            BOOL;
typedef uint32_t       DWORD;
typedef int32_t        LONG;
typedef uint16_t       WORD;
typedef unsigned char  BYTE;
typedef void          *HANDLE;
typedef void          *LPVOID;
typedef const void    *LPCVOID;
typedef char          *LPSTR;
typedef const char    *LPCSTR;
typedef wchar_t       *LPWSTR;
typedef const wchar_t *LPCWSTR;
typedef uint64_t       SIZE_T;
typedef void          *HMODULE;
typedef int          (*FARPRC)(void);   /* Generic function pointer */
typedef DWORD        *LPDWORD;
typedef uint64_t      ULONG_PTR;

#define TRUE   1
#define FALSE  0
#define NULL_HANDLE ((HANDLE)(intptr_t)-1)
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)

/* Standard handles */
#define STD_INPUT_HANDLE  ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE  ((DWORD)-12)

/* VirtualAlloc flags */
#define MEM_COMMIT      0x00001000
#define MEM_RESERVE     0x00002000
#define MEM_RELEASE     0x00008000

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40

/* File access flags */
#define GENERIC_READ    0x80000000
#define GENERIC_WRITE   0x40000000

/* CreateFile disposition */
#define CREATE_NEW        1
#define CREATE_ALWAYS     2
#define OPEN_EXISTING     3
#define OPEN_ALWAYS       4
#define TRUNCATE_EXISTING 5

/* File attributes */
#define FILE_ATTRIBUTE_NORMAL 0x80

/* FormatMessage flags */
#define FORMAT_MESSAGE_FROM_SYSTEM 0x00001000

/* Heap flags */
#define HEAP_ZERO_MEMORY 0x00000008

/* ---- kernel32.dll stubs ---- */

/* Console I/O */
HANDLE  stub_GetStdHandle(DWORD nStdHandle);
BOOL    stub_WriteConsoleA(HANDLE hConsole, LPCVOID lpBuffer,
                           DWORD nNumberOfCharsToWrite,
                           LPDWORD lpNumberOfCharsWritten,
                           LPVOID lpReserved);
BOOL    stub_WriteFile(HANDLE hFile, LPCVOID lpBuffer,
                       DWORD nNumberOfBytesToWrite,
                       LPDWORD lpNumberOfBytesWritten,
                       LPVOID lpOverlapped);
BOOL    stub_ReadFile(HANDLE hFile, LPVOID lpBuffer,
                      DWORD nNumberOfBytesToRead,
                      LPDWORD lpNumberOfBytesRead,
                      LPVOID lpOverlapped);

/* Process control */
void    stub_ExitProcess(DWORD uExitCode) __attribute__((noreturn));
HANDLE  stub_GetCurrentProcess(void);
DWORD   stub_GetCurrentProcessId(void);
DWORD   stub_GetCurrentThreadId(void);

/* Memory management */
LPVOID  stub_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
                          DWORD flAllocationType, DWORD flProtect);
BOOL    stub_VirtualFree(LPVOID lpAddress, SIZE_T dwSize,
                         DWORD dwFreeType);
HANDLE  stub_GetProcessHeap(void);
LPVOID  stub_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL    stub_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

/* String / formatting */
int     stub_MultiByteToWideChar(DWORD CodePage, DWORD dwFlags,
                                 LPCSTR lpMultiByteStr, int cbMultiByte,
                                 LPWSTR lpWideCharStr, int cchWideChar);
int     stub_WideCharToMultiByte(DWORD CodePage, DWORD dwFlags,
                                 LPCWSTR lpWideCharStr, int cchWideChar,
                                 LPSTR lpMultiByteStr, int cbMultiByte,
                                 LPCSTR lpDefaultChar, BOOL *lpUsedDefaultChar);
DWORD   stub_FormatMessageA(DWORD dwFlags, LPCVOID lpSource,
                            DWORD dwMessageId, DWORD dwLanguageId,
                            LPSTR lpBuffer, DWORD nSize, void *Arguments);

/* Module / library */
HMODULE stub_GetModuleHandleA(LPCSTR lpModuleName);
FARPRC  stub_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

/* System info */
void    stub_GetSystemInfo(void *lpSystemInfo);
DWORD   stub_GetLastError(void);
void    stub_SetLastError(DWORD dwErrCode);
BOOL    stub_QueryPerformanceCounter(int64_t *lpPerformanceCount);
BOOL    stub_QueryPerformanceFrequency(int64_t *lpFrequency);
DWORD   stub_GetTickCount(void);

/* File I/O */
HANDLE  stub_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
                         DWORD dwShareMode, LPVOID lpSecurityAttributes,
                         DWORD dwCreationDisposition,
                         DWORD dwFlagsAndAttributes,
                         HANDLE hTemplateFile);
BOOL    stub_CloseHandle(HANDLE hObject);

/* Environment */
DWORD   stub_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer,
                                     DWORD nSize);
LPSTR   stub_GetCommandLineA(void);

/* ---- ntdll.dll stubs ---- */

/* These are lower-level NT API functions */
LONG    stub_NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                     LPVOID *BaseAddress,
                                     ULONG_PTR ZeroBits,
                                     SIZE_T *RegionSize,
                                     DWORD AllocationType,
                                     DWORD Protect);

/* ---- msvcrt.dll stubs ---- */

/* C runtime functions commonly imported by simple programs */
int     stub_puts(const char *str);
int     stub_printf(const char *format, ...);
void   *stub_malloc(size_t size);
void    stub_free(void *ptr);
void   *stub_memset(void *s, int c, size_t n);
void   *stub_memcpy(void *dest, const void *src, size_t n);
size_t  stub_strlen(const char *s);
int     stub_strcmp(const char *s1, const char *s2);
void    stub_exit(int status) __attribute__((noreturn));

/* ---- Import resolution ---- */

/*
 * Resolve a Win32 API import.
 * Given a DLL name and function name (or ordinal), returns a pointer
 * to our stub implementation.
 */
void *win32_resolve_import(const char *dll_name, const char *func_name,
                           uint16_t ordinal);

/*
 * Initialize the Win32 stub layer.
 * Must be called after pal_init().
 */
int win32_stubs_init(void);

/*
 * Set the command line string (for GetCommandLineA).
 */
void win32_set_command_line(const char *cmdline);

#endif /* WIN32_STUBS_H */
