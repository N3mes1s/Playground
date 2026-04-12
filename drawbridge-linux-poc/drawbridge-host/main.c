/*
 * main.c — Drawbridge Host entry-point shell.
 *
 * Heavy lifting is now split across component owners per
 * /root/.claude/plans/hashed-sparking-lake.md:
 *   pe_loader.c  (C1)  — SFP parser, PE header parsing, LibOS memory.
 *   pal_boot.c   (C2)  — 22-step PAL boot sequence.
 *   pal_sys.c    (C10) — time / random / sysinfo / getpid translations.
 *   ntum_bootstrap.c   — NTUM trampoline into sqlpal.dll.
 *
 * This file is the ~50-line shell that wires those pieces together.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "drawbridge_types.h"
#include "pe_loader.h"
#include "ntum_bootstrap.h"
#include "dk_pal.h"
#include "ntum_signals.h"

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("Drawbridge Host v2.0 - Generic NTUM Runtime\n"
           "Reimplemented from SQLPAL reverse engineering\n\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <windows.exe> [--sfp-dir <path>]\n", argv[0]);
        return 1;
    }

    const char *target_exe = argv[1];
    const char *sfp_dir    = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sfp-dir") == 0 && i + 1 < argc)
            sfp_dir = argv[++i];
    }
    if (!sfp_dir) {
        sfp_dir = "deps/mssql-extracted/opt/mssql/lib";
        printf("[HOST] Using default SFP dir: %s\n", sfp_dir);
    }

    pe_loader_init();
    pe_loader_setup_libos_memory();

    printf("[HOST] Loading SFP archives from %s\n", sfp_dir);
    char path[512];
    sfp_archive_t system_sfp = {0};
    sfp_archive_t common_sfp = {0};

    snprintf(path, sizeof(path), "%s/system.sfp", sfp_dir);
    if (pe_loader_load_sfp(path, &system_sfp) != 0) {
        fprintf(stderr, "[HOST] Cannot load system.sfp\n");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/system.common.sfp", sfp_dir);
    if (pe_loader_load_sfp(path, &common_sfp) != 0) {
        printf("[HOST] system.common.sfp not found (optional)\n");
    }

    printf("\n[HOST] Loading NTUM kernel (sqlpal.dll)...\n");
    void *ntum_raw = pe_loader_map_pe_from_sfp(&system_sfp, "sqlpal.dll", NULL);
    if (!ntum_raw) {
        fprintf(stderr, "[HOST] Cannot load sqlpal.dll\n");
        return 1;
    }

    printf("[HOST] Loading support DLLs...\n");
    pe_loader_map_pe_from_sfp(&system_sfp, "DkDll.dll",        NULL);
    pe_loader_map_pe_from_sfp(&system_sfp, "AppLoader.exe",    NULL);
    pe_loader_map_pe_from_sfp(&system_sfp, "vcruntime140.dll", NULL);

    printf("\n[HOST] Parsing NTUM PE...\n");
    void   *pe_image_base = NULL;
    uint32_t pe_size_of_image = 0;
    uint32_t pe_entry_rva = 0;
    size_t   pe_raw_size = 0;
    void *ntum = pe_loader_parse_and_map(ntum_raw,
                                         &pe_image_base,
                                         &pe_size_of_image,
                                         &pe_entry_rva,
                                         &pe_raw_size);
    if (!ntum) return 1;
    ntum_signal_set_pe_data(ntum_raw, pe_raw_size, (uint64_t)pe_image_base);

    printf("\n[HOST] Target: %s\n", target_exe);
    struct stat st;
    if (stat(target_exe, &st) != 0) {
        fprintf(stderr, "[HOST] Cannot find: %s\n", target_exe);
        return 1;
    }
    printf("[HOST] Size: %lu bytes\n", (unsigned long)st.st_size);

    printf("\n[HOST] Bootstrapping NTUM kernel...\n");
    ntum_signal_init();
    dk_pal_init();

    WINDOWS_LIBOS_PARAMETERS *libos_params = (WINDOWS_LIBOS_PARAMETERS *)
        mmap((void *)0x100010000ULL, sizeof(WINDOWS_LIBOS_PARAMETERS),
             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
             -1, 0);
    if (libos_params == MAP_FAILED) {
        libos_params = (WINDOWS_LIBOS_PARAMETERS *)
            mmap(NULL, sizeof(WINDOWS_LIBOS_PARAMETERS),
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    printf("[HOST] LIBOS_PARAMS at %p\n", (void *)libos_params);

    ntum_bootstrap_init(libos_params, ntum,
                        pe_size_of_image ? pe_size_of_image : 16 * 1024 * 1024,
                        pe_entry_rva ? pe_entry_rva : 0x3A04D0,
                        dk_pal_get_table());

    printf("\n[HOST] Launching NTUM boot thread...\n");
    int boot_result = ntum_bootstrap_launch(libos_params);
    if (boot_result != 0)
        fprintf(stderr, "[HOST] NTUM boot failed\n");

    if (system_sfp.fd > 0) close(system_sfp.fd);
    if (common_sfp.fd > 0) close(common_sfp.fd);
    free(system_sfp.name_table);
    free(common_sfp.name_table);
    return 0;
}
