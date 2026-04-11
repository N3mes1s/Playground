/*
 * 32-bit Windows PE test program for Drawbridge
 *
 * Cross-compile: i686-w64-mingw32-gcc -o hello32.exe hello32.c -nostdlib -lkernel32 -e _start
 */

typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef unsigned long *LPDWORD;

#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE hFile, const void *lpBuffer,
    DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, void *lpOverlapped);
__declspec(dllimport) void __stdcall ExitProcess(DWORD uExitCode);
__declspec(dllimport) void __stdcall Sleep(DWORD dwMilliseconds);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);

void _start(void) {
    HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;

    const char msg1[] = "[32-bit PE] Hello from Windows on Linux!\n";
    const char msg2[] = "[32-bit PE] Drawbridge PAL active.\n";
    const char msg3[] = "[32-bit PE] PID: ";

    WriteFile(stdout_handle, msg1, sizeof(msg1) - 1, &written, 0);
    WriteFile(stdout_handle, msg2, sizeof(msg2) - 1, &written, 0);
    WriteFile(stdout_handle, msg3, sizeof(msg3) - 1, &written, 0);

    /* Print PID */
    DWORD pid = GetCurrentProcessId();
    char buf[16];
    int i = 0;
    if (pid == 0) { buf[i++] = '0'; }
    else {
        char tmp[16]; int j = 0;
        while (pid > 0) { tmp[j++] = '0' + (pid % 10); pid /= 10; }
        while (j > 0) buf[i++] = tmp[--j];
    }
    buf[i++] = '\n';
    WriteFile(stdout_handle, buf, i, &written, 0);

    ExitProcess(0);
}
