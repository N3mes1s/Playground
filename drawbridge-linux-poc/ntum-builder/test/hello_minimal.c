/*
 * Minimal Windows PE test program
 *
 * Uses only the Win32 APIs that our PAL stubs implement:
 * - GetStdHandle
 * - WriteFile (via WriteConsoleA)
 * - ExitProcess
 *
 * Cross-compile: x86_64-w64-mingw32-gcc -o hello.exe hello.c -nostdlib -e _start
 */

/* Minimal Windows type definitions (no windows.h dependency) */
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef unsigned long *LPDWORD;

#define STD_OUTPUT_HANDLE ((DWORD)-11)

/* These are resolved by the PAL host's import resolver */
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE hFile, const void *lpBuffer,
    DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, void *lpOverlapped);
__declspec(dllimport) void __stdcall ExitProcess(DWORD uExitCode);

void _start(void) {
    HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);

    const char msg1[] = "Hello from Windows PE running on Linux!\n";
    const char msg2[] = "This is Drawbridge in action.\n";
    const char msg3[] = "PAL translating Win32 -> Linux syscalls.\n";

    DWORD written;
    WriteFile(stdout_handle, msg1, sizeof(msg1) - 1, &written, 0);
    WriteFile(stdout_handle, msg2, sizeof(msg2) - 1, &written, 0);
    WriteFile(stdout_handle, msg3, sizeof(msg3) - 1, &written, 0);

    ExitProcess(0);
}
