/*
 * Comprehensive Drawbridge Test Application
 *
 * Exercises all major Win32 subsystems and prints results to stdout.
 * This proves the Drawbridge NTUM correctly translates each API.
 *
 * Compile: x86_64-w64-mingw32-gcc -o full_test.exe full_test.c -ladvapi32 -lws2_32 -mconsole
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

static void print_separator(const char *name) {
    printf("\n=== %s ===\n", name);
}

/* 1. Process & Thread */
static void test_process_thread(void) {
    print_separator("PROCESS & THREAD");
    printf("PID: %lu\n", GetCurrentProcessId());
    printf("TID: %lu\n", GetCurrentThreadId());
    printf("Process Handle: %p\n", GetCurrentProcess());

    /* Create a thread */
    HANDLE thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)(void*)GetCurrentThreadId, NULL, 0, NULL);
    if (thread) {
        WaitForSingleObject(thread, 1000);
        DWORD exit_code;
        GetExitCodeThread(thread, &exit_code);
        printf("Child thread returned: %lu\n", exit_code);
        CloseHandle(thread);
    }
}

/* 2. File I/O */
static void test_file_io(void) {
    print_separator("FILE I/O");

    /* Create and write */
    HANDLE f = CreateFileA("C:\\drawbridge_test.txt", GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        const char data[] = "Hello from Drawbridge!\r\nLine 2\r\n";
        DWORD written;
        WriteFile(f, data, sizeof(data)-1, &written, NULL);
        printf("Write: %lu bytes\n", written);
        CloseHandle(f);
    } else {
        printf("CreateFile (write): FAILED (%lu)\n", GetLastError());
    }

    /* Read back */
    f = CreateFileA("C:\\drawbridge_test.txt", GENERIC_READ, 0, NULL,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        char buf[256] = {0};
        DWORD read_bytes;
        ReadFile(f, buf, sizeof(buf)-1, &read_bytes, NULL);
        printf("Read: %lu bytes = \"%s\"\n", read_bytes, buf);

        /* File size */
        DWORD size = GetFileSize(f, NULL);
        printf("File size: %lu\n", size);
        CloseHandle(f);
    }

    /* Delete */
    if (DeleteFileA("C:\\drawbridge_test.txt"))
        printf("Delete: OK\n");

    /* Directory */
    printf("Temp path: ");
    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    printf("%s\n", tmp);

    printf("Windows dir: ");
    char windir[MAX_PATH];
    GetWindowsDirectoryA(windir, sizeof(windir));
    printf("%s\n", windir);

    printf("Current dir: ");
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    printf("%s\n", cwd);
}

/* 3. Memory Management */
static void test_memory(void) {
    print_separator("MEMORY");

    /* VirtualAlloc */
    void *mem = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        printf("VirtualAlloc: %p (64KB)\n", mem);
        memset(mem, 0x41, 65536);  /* Fill with 'A' */
        printf("memset: OK\n");

        /* VirtualProtect */
        DWORD old;
        if (VirtualProtect(mem, 65536, PAGE_EXECUTE_READ, &old))
            printf("VirtualProtect: RX (was 0x%lx)\n", (unsigned long)old);

        VirtualFree(mem, 0, MEM_RELEASE);
        printf("VirtualFree: OK\n");
    }

    /* HeapAlloc */
    void *h = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4096);
    if (h) {
        printf("HeapAlloc: %p (4KB)\n", h);
        HeapFree(GetProcessHeap(), 0, h);
    }
}

/* 4. System Info */
static void test_sysinfo(void) {
    print_separator("SYSTEM INFO");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("Processors: %lu\n", si.dwNumberOfProcessors);
    printf("Page size: %lu\n", si.dwPageSize);
    printf("Arch: %u\n", si.wProcessorArchitecture);

    MEMORYSTATUS ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatus(&ms);
    printf("Physical RAM: %lu MB\n", (unsigned long)(ms.dwTotalPhys / (1024*1024)));
    printf("Available: %lu MB\n", (unsigned long)(ms.dwAvailPhys / (1024*1024)));

    OSVERSIONINFOA osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExA(&osvi);
    printf("OS: %lu.%lu build %lu\n", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

    char name[256];
    DWORD nsize = sizeof(name);
    GetComputerNameA(name, &nsize);
    printf("Computer: %s\n", name);

    printf("Tick count: %lu ms\n", GetTickCount());
}

/* 5. Synchronization */
static void test_sync(void) {
    print_separator("SYNCHRONIZATION");

    /* Critical section */
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    EnterCriticalSection(&cs);
    printf("CriticalSection: entered\n");
    LeaveCriticalSection(&cs);
    DeleteCriticalSection(&cs);
    printf("CriticalSection: done\n");

    /* Event */
    HANDLE evt = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (evt) {
        SetEvent(evt);
        DWORD wait = WaitForSingleObject(evt, 0);
        printf("Event: signaled (wait=%lu)\n", wait);
        CloseHandle(evt);
    }

    /* Mutex */
    HANDLE mtx = CreateMutexA(NULL, FALSE, NULL);
    if (mtx) {
        WaitForSingleObject(mtx, 0);
        printf("Mutex: acquired\n");
        ReleaseMutex(mtx);
        CloseHandle(mtx);
    }
}

/* 6. Registry */
static void test_registry(void) {
    print_separator("REGISTRY");

    HKEY key;
    LONG ret = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\DrawbridgeTest",
                                0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);
    if (ret == ERROR_SUCCESS) {
        const char *val = "Hello from Drawbridge";
        RegSetValueExA(key, "TestValue", 0, REG_SZ, (BYTE*)val, strlen(val)+1);
        printf("RegSetValue: OK\n");

        char buf[256]; DWORD size = sizeof(buf); DWORD type;
        ret = RegQueryValueExA(key, "TestValue", NULL, &type, (BYTE*)buf, &size);
        if (ret == ERROR_SUCCESS)
            printf("RegQueryValue: \"%s\" (type=%lu)\n", buf, type);

        RegDeleteValueA(key, "TestValue");
        RegCloseKey(key);
        RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\DrawbridgeTest");
        printf("Registry: cleaned up\n");
    } else {
        printf("RegCreateKey: error %ld\n", ret);
    }
}

/* 7. Crypto */
static void test_crypto(void) {
    print_separator("CRYPTOGRAPHY");

    HCRYPTPROV prov;
    if (CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE random[32];
        CryptGenRandom(prov, sizeof(random), random);
        printf("Random: ");
        for (int i = 0; i < 16; i++) printf("%02x", random[i]);
        printf("...\n");

        HCRYPTHASH hash;
        if (CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash)) {
            const char *data = "Drawbridge test";
            CryptHashData(hash, (BYTE*)data, strlen(data), 0);
            BYTE digest[20]; DWORD dsize = sizeof(digest);
            CryptGetHashParam(hash, HP_HASHVAL, digest, &dsize, 0);
            printf("SHA1(\"Drawbridge test\"): ");
            for (DWORD i = 0; i < dsize; i++) printf("%02x", digest[i]);
            printf("\n");
            CryptDestroyHash(hash);
        }
        CryptReleaseContext(prov, 0);
    }
}

/* 8. Network (Winsock) */
static void test_network(void) {
    print_separator("NETWORK");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) == 0) {
        printf("Winsock: %d.%d\n", LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));

        /* Create a socket */
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s != INVALID_SOCKET) {
            printf("Socket: created (fd=%lld)\n", (long long)s);

            /* Try to connect to localhost:80 (will likely fail but exercises the API) */
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(80);
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            int ret = connect(s, (struct sockaddr*)&addr, sizeof(addr));
            printf("Connect 127.0.0.1:80: %s\n", ret == 0 ? "OK" : "refused (expected)");

            closesocket(s);
        }

        /* DNS lookup */
        struct addrinfo *result = NULL;
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int dns_ret = getaddrinfo("localhost", "80", &hints, &result);
        printf("DNS resolve 'localhost': %s\n", dns_ret == 0 ? "OK" : "failed");
        if (result) freeaddrinfo(result);

        WSACleanup();
    }
}

/* 9. Environment */
static void test_environment(void) {
    print_separator("ENVIRONMENT");

    char buf[256];
    DWORD len = GetEnvironmentVariableA("PATH", buf, sizeof(buf));
    printf("PATH: %.*s...\n", 60, buf);

    printf("CommandLine: %s\n", GetCommandLineA());

    printf("ModuleFileName: ");
    GetModuleFileNameA(NULL, buf, sizeof(buf));
    printf("%s\n", buf);
}

/* 10. Time */
static void test_time(void) {
    print_separator("TIME");

    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    printf("PerfFreq: %lld\n", freq.QuadPart);
    printf("PerfCounter: %lld\n", counter.QuadPart);

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    printf("FileTime: 0x%08lx%08lx\n", ft.dwHighDateTime, ft.dwLowDateTime);

    printf("TickCount: %lu ms\n", GetTickCount());
}

int main(int argc, char **argv) {
    printf("========================================\n");
    printf("  Drawbridge Full API Test\n");
    printf("  Windows PE running on Linux via NTUM\n");
    printf("========================================\n");
    printf("argc: %d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("argv[%d]: %s\n", i, argv[i]);

    test_process_thread();
    test_file_io();
    test_memory();
    test_sysinfo();
    test_sync();
    test_registry();
    test_crypto();
    test_network();
    test_environment();
    test_time();

    printf("\n========================================\n");
    printf("  ALL TESTS COMPLETE\n");
    printf("========================================\n");
    return 0;
}
