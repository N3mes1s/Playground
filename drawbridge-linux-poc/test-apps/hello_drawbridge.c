/*
 * Test application for Drawbridge / SQLPAL execution
 *
 * This is a full Windows console application that exercises various
 * Win32 APIs. When run through the SQLPAL NTUM, all these calls
 * go through the real Windows kernel running in user mode on Linux.
 *
 * Compile: x86_64-w64-mingw32-gcc -o app.exe hello_drawbridge.c -mconsole
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    char buf[512];

    /* Banner */
    const char banner[] =
        "============================================\r\n"
        "  Drawbridge Test App - Running on Linux!   \r\n"
        "  Real NTUM (sqlpal.dll) providing Win32    \r\n"
        "============================================\r\n\r\n";
    WriteFile(hStdout, banner, sizeof(banner) - 1, &written, NULL);

    /* Process info */
    int len = sprintf(buf, "PID: %lu\r\nThread ID: %lu\r\n",
                      GetCurrentProcessId(), GetCurrentThreadId());
    WriteFile(hStdout, buf, len, &written, NULL);

    /* System info */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    len = sprintf(buf, "Processors: %lu\r\nPage size: %lu\r\n",
                  si.dwNumberOfProcessors, si.dwPageSize);
    WriteFile(hStdout, buf, len, &written, NULL);

    /* Memory info */
    MEMORYSTATUS ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatus(&ms);
    len = sprintf(buf, "Total physical memory: %lu MB\r\nAvailable: %lu MB\r\n",
                  (unsigned long)(ms.dwTotalPhys / (1024 * 1024)),
                  (unsigned long)(ms.dwAvailPhys / (1024 * 1024)));
    WriteFile(hStdout, buf, len, &written, NULL);

    /* OS version */
    OSVERSIONINFOA osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExA(&osvi);
    len = sprintf(buf, "OS Version: %lu.%lu (Build %lu)\r\n",
                  osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    WriteFile(hStdout, buf, len, &written, NULL);

    /* Computer name */
    char compname[256];
    DWORD compsize = sizeof(compname);
    GetComputerNameA(compname, &compsize);
    len = sprintf(buf, "Computer: %s\r\n", compname);
    WriteFile(hStdout, buf, len, &written, NULL);

    /* Current directory */
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    len = sprintf(buf, "Current directory: %s\r\n", cwd);
    WriteFile(hStdout, buf, len, &written, NULL);

    /* Memory allocation test */
    void *mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        len = sprintf(buf, "VirtualAlloc: OK at %p\r\n", mem);
        WriteFile(hStdout, buf, len, &written, NULL);
        memset(mem, 0x41, 4096);  /* Fill with 'A' */
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    /* File I/O test */
    HANDLE hFile = CreateFileA("C:\\drawbridge_test.txt",
                                GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char testdata[] = "Written from Drawbridge on Linux!\r\n";
        WriteFile(hFile, testdata, sizeof(testdata) - 1, &written, NULL);
        CloseHandle(hFile);
        len = sprintf(buf, "File write: OK (wrote %lu bytes)\r\n", written);
    } else {
        len = sprintf(buf, "File write: failed (err=%lu)\r\n", GetLastError());
    }
    WriteFile(hStdout, buf, len, &written, NULL);

    /* Crypto test */
    HCRYPTPROV hProv;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE randomBytes[16];
        CryptGenRandom(hProv, sizeof(randomBytes), randomBytes);
        len = sprintf(buf, "CryptGenRandom: ");
        for (int i = 0; i < 16; i++) len += sprintf(buf + len, "%02x", randomBytes[i]);
        len += sprintf(buf + len, "\r\n");
        WriteFile(hStdout, buf, len, &written, NULL);
        CryptReleaseContext(hProv, 0);
    }

    /* Arguments */
    len = sprintf(buf, "\r\nArguments (%d):\r\n", argc);
    WriteFile(hStdout, buf, len, &written, NULL);
    for (int i = 0; i < argc; i++) {
        len = sprintf(buf, "  argv[%d] = \"%s\"\r\n", i, argv[i]);
        WriteFile(hStdout, buf, len, &written, NULL);
    }

    const char done[] = "\r\n=== Drawbridge test complete! ===\r\n";
    WriteFile(hStdout, done, sizeof(done) - 1, &written, NULL);

    return 0;
}
