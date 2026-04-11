/*
 * Drawbridge PAL Host
 *
 * Linux ELF executable that loads and runs Windows PE binaries
 * using the Drawbridge library OS architecture.
 *
 * This is our reimplementation of what sqlservr (the ELF PAL host) does:
 * 1. Initialize the PAL (Linux syscall implementations)
 * 2. Load the target PE binary into memory
 * 3. Resolve Win32 API imports against our stubs
 * 4. Transfer control to the PE entry point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "pe_loader.h"

/* From pal_linux.c */
extern void *pal_linux_create(void);

/* From win32_stubs.c */
extern void *win32_resolve_import(const char *dll_name, const char *func_name,
                                   uint16_t ordinal, void *ctx);

static void print_banner(void) {
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  Drawbridge PAL Host v0.1                       ║\n");
    printf("║  Running Windows PE on Linux via Library OS      ║\n");
    printf("║  Based on SQLPAL architecture from SQL Server    ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
}

static void sighandler(int sig) {
    const char *name = "UNKNOWN";
    switch(sig) {
        case SIGSEGV: name = "SIGSEGV"; break;
        case SIGBUS:  name = "SIGBUS"; break;
        case SIGFPE:  name = "SIGFPE"; break;
        case SIGILL:  name = "SIGILL"; break;
    }
    fprintf(stderr, "\n[PAL] Signal %s (%d) caught in PE code\n", name, sig);
    fprintf(stderr, "[PAL] The Windows binary crashed or hit an unimplemented API\n");
    _exit(128 + sig);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    print_banner();

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <windows.exe> [args...]\n", argv[0]);
        fprintf(stderr, "\nRuns a Windows PE executable on Linux using Drawbridge architecture.\n");
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  %s hello.exe\n", argv[0]);
        fprintf(stderr, "  %s malware.exe --analyze\n", argv[0]);
        return 1;
    }

    const char *pe_path = argv[1];

    /* Install signal handlers for PE crashes */
    signal(SIGSEGV, sighandler);
    signal(SIGBUS, sighandler);
    signal(SIGFPE, sighandler);
    signal(SIGILL, sighandler);

    /* Step 1: Initialize PAL */
    printf("[HOST] Initializing PAL (Linux implementation)...\n");
    void *pal = pal_linux_create();
    if (!pal) {
        fprintf(stderr, "[HOST] Failed to initialize PAL\n");
        return 1;
    }
    printf("[HOST] PAL initialized (30 operations mapped to Linux syscalls)\n\n");

    /* Step 2: Load the PE binary */
    printf("[HOST] Loading PE binary: %s\n", pe_path);
    pe_loaded_image_t image = {0};
    if (pe_load_image(pe_path, &image) != 0) {
        fprintf(stderr, "[HOST] Failed to load PE binary\n");
        return 1;
    }

    printf("[HOST] PE loaded at %p (%s, %s)\n",
           image.base,
           image.is_64bit ? "64-bit" : "32-bit",
           image.is_dll ? "DLL" : "EXE");
    printf("[HOST] Entry point: %p\n", (void*)image.entry_point);
    if (image.relocated)
        printf("[HOST] Image relocated from 0x%lx to %p\n",
               (unsigned long)image.preferred_base, image.base);
    printf("\n");

    /* Step 3: Resolve imports */
    printf("[HOST] Resolving Win32 API imports...\n");
    int import_result = pe_resolve_imports(&image, win32_resolve_import, NULL);

    if (import_result != 0) {
        printf("\n[HOST] WARNING: Some imports could not be resolved.\n");
        printf("[HOST] The binary may crash when calling unimplemented APIs.\n");
        printf("[HOST] Continuing anyway (Drawbridge-style fault handling)...\n\n");
    } else {
        printf("[HOST] All imports resolved successfully!\n\n");
    }

    /* Step 4: Transfer control to PE entry point */
    printf("[HOST] ═══════════════════════════════════════════\n");
    printf("[HOST] Transferring control to PE entry point...\n");
    printf("[HOST] ═══════════════════════════════════════════\n\n");

    if (image.is_dll) {
        /* For DLLs, call DllMain(hInstance, DLL_PROCESS_ATTACH, NULL) */
        typedef int (*dll_main_fn)(void *hInstance, uint32_t fdwReason, void *lpvReserved);
        dll_main_fn entry = (dll_main_fn)image.entry_point;

        printf("[HOST] Calling DllMain(%p, DLL_PROCESS_ATTACH, NULL)\n\n", image.base);
        int result = entry(image.base, 1 /* DLL_PROCESS_ATTACH */, NULL);
        printf("\n[HOST] DllMain returned: %d\n", result);
    } else {
        /* For EXEs, there are two calling conventions:
         * - Console apps: mainCRTStartup(void) -> main(argc, argv)
         * - The CRT startup calls the actual main()
         * We just jump to the entry point and let it run */
        typedef int (*exe_entry_fn)(void);
        exe_entry_fn entry = (exe_entry_fn)image.entry_point;

        int result = entry();
        printf("\n[HOST] PE entry point returned: %d\n", result);
    }

    /* Cleanup */
    pe_unload_image(&image);
    free(pal);

    printf("[HOST] Drawbridge session ended.\n");
    return 0;
}
