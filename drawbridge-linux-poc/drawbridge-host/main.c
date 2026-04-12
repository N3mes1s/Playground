/*
 * Drawbridge Host - Generic NTUM Runtime
 *
 * Reimplementation of the SQLPAL ELF host (sqlservr) that can run
 * arbitrary Windows PE executables through the real NTUM (sqlpal.dll).
 *
 * Based on reverse engineering of:
 * - sqlservr ELF binary (strings, strace, radare2)
 * - NTUM memory map (from boot strace analysis)
 * - SFP archive format
 * - package.manifest format
 *
 * Architecture:
 *   drawbridge-host (this) → sqlpal.dll (NTUM) → ntdll.dll → app.exe
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dlfcn.h>

#include "drawbridge_types.h"
#include "ntum_bootstrap.h"
#include "dk_pal.h"
#include "ntum_signals.h"

/* Memory layout constants now defined in drawbridge_types.h */

/* SFP types are now defined in drawbridge_types.h (included via ntum_bootstrap.h) */

/* Forward declarations */
static int setup_libos_memory(void);
static int load_sfp(const char *path, sfp_archive_t *archive);
static const char *sfp_get_name(sfp_archive_t *archive, uint64_t offset);
static int sfp_find_file(sfp_archive_t *archive, const char *name,
                          uint64_t *data_offset, uint64_t *data_size);
static void *map_pe_from_sfp(sfp_archive_t *archive, const char *name,
                              void *base_addr);

/* ================================================================
 * SFP Archive Loader
 * ================================================================ */

static int load_sfp(const char *path, sfp_archive_t *archive) {
    archive->fd = open(path, O_RDONLY);
    if (archive->fd < 0) return -1;

    /* Read header */
    if (read(archive->fd, &archive->header, sizeof(sfp_header_t)) != sizeof(sfp_header_t)) {
        close(archive->fd);
        return -1;
    }

    if (archive->header.magic != 0x00504653) {  /* "SFP\0" */
        fprintf(stderr, "[SFP] Bad magic in %s: 0x%08x\n", path, archive->header.magic);
        close(archive->fd);
        return -1;
    }

    /* Load name table */
    archive->name_table_size = archive->header.data_offset - archive->header.name_table_offset;
    archive->name_table = malloc(archive->name_table_size);
    if (!archive->name_table) { close(archive->fd); return -1; }

    lseek(archive->fd, archive->header.name_table_offset, SEEK_SET);
    ssize_t nr = read(archive->fd, archive->name_table, archive->name_table_size);
    (void)nr;

    /* Get package label (pkgLabel is absolute offset, convert to relative) */
    uint64_t label_rel = archive->header.package_label_offset - archive->header.name_table_offset;
    const char *label = sfp_get_name(archive, label_rel);
    if (label) {
        strncpy(archive->label, label, sizeof(archive->label) - 1);
    }

    /* Calculate entry count from directory size */
    uint64_t dir_size = archive->header.name_table_offset - archive->header.first_dir_offset;
    unsigned long num_entries = dir_size / 80;  /* sizeof(sfp_dir_entry) = 80 */

    printf("[SFP] Loaded: %s (label=%s, %lu entries)\n",
           path, archive->label, num_entries);
    return 0;
}

/* Get a name from the name table (plain ASCII, null-terminated) */
static const char *sfp_get_name(sfp_archive_t *archive, uint64_t offset) {
    if (offset >= archive->name_table_size) return "?";
    return (const char*)(archive->name_table + offset);
}

/* Find a file in the SFP by name (recursive search) */
static int sfp_find_file_r(sfp_archive_t *archive, uint64_t dir_offset,
                            const char *target, uint64_t *data_offset,
                            uint64_t *data_size) {
    sfp_dir_entry_t entry;
    lseek(archive->fd, dir_offset, SEEK_SET);
    if (read(archive->fd, &entry, sizeof(entry)) != sizeof(entry)) return -1;

    /* nameOffset is absolute file offset - convert to name table index */
    uint64_t name_idx = entry.name_offset >= archive->header.name_table_offset ?
        entry.name_offset - archive->header.name_table_offset : entry.name_offset;
    const char *name = sfp_get_name(archive, name_idx);

    if (!entry.is_dir) {
        if (strcasecmp(name, target) == 0) {
            *data_offset = entry.start_offset;
            *data_size = entry.file_length;
            return 0;
        }
        return -1;
    }

    /* Search children */
    for (uint64_t off = entry.start_offset;
         off < entry.start_offset + entry.data_length;
         off += sizeof(sfp_dir_entry_t)) {
        if (sfp_find_file_r(archive, off, target, data_offset, data_size) == 0)
            return 0;
    }
    return -1;
}

static int sfp_find_file(sfp_archive_t *archive, const char *name,
                          uint64_t *data_offset, uint64_t *data_size) {
    return sfp_find_file_r(archive, archive->header.first_dir_offset,
                           name, data_offset, data_size);
}

/* Map a PE file from inside an SFP archive directly into memory */
static void *map_pe_from_sfp(sfp_archive_t *archive, const char *name,
                              void *base_hint) {
    uint64_t data_offset, data_size;
    if (sfp_find_file(archive, name, &data_offset, &data_size) != 0) {
        fprintf(stderr, "[SFP] File not found: %s\n", name);
        return NULL;
    }

    /* Map the file data from the SFP fd */
    /* Align offset to page boundary */
    uint64_t page_offset = data_offset & ~0xFFFULL;
    uint64_t offset_adj = data_offset - page_offset;
    size_t map_size = (data_size + offset_adj + 4095) & ~4095ULL;

    /* All SFP mappings must be in LibOS address range.
     * The NTUM uses these addresses in thread context frames
     * and expects them to be within the valid LibOS range. */
    static uint64_t sfp_map_next = 0x3FFF80000000ULL; /* High kernel control area */
    int flags = MAP_PRIVATE;
    if (base_hint) {
        flags |= MAP_FIXED_NOREPLACE;
    } else {
        /* Assign a LibOS-range address */
        base_hint = (void*)__atomic_fetch_add(&sfp_map_next, map_size + 0x1000,
                                               __ATOMIC_SEQ_CST);
    }

    void *mapped = mmap(base_hint, map_size, PROT_READ | PROT_WRITE,
                        flags, archive->fd, page_offset);
    if (mapped == MAP_FAILED && base_hint) {
        /* Try MAP_FIXED (overwrite) */
        mapped = mmap(base_hint, map_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_FIXED, archive->fd, page_offset);
    }
    if (mapped == MAP_FAILED) return NULL;

    printf("[HOST] Mapped %s from SFP at %p (%lu KB)\n",
           name, mapped, (unsigned long)(data_size / 1024));
    return (uint8_t*)mapped + offset_adj;
}

/* ================================================================
 * LibOS Memory Setup
 * ================================================================ */

static int setup_libos_memory(void) {
    printf("[HOST] Setting up LibOS memory regions...\n");

    /* Control pages */
    void *p;

    p = mmap((void*)LIBOS_CONTROL_PAGE, 4096, PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] 0x100000000 failed\n"); }
    else printf("  0x100000000: control page OK\n");

    p = mmap((void*)LIBOS_IMAGE_BASE, 4096, PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] 0x200000000 failed\n"); }
    else printf("  0x200000000: image base OK\n");

    /* Kernel heap (1GB, NORESERVE) */
    p = mmap((void*)LIBOS_KERNEL_HEAP, LIBOS_KERNEL_HEAP_SZ,
             PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] kernel heap failed\n"); }
    else printf("  0x300000000: kernel heap 1GB OK\n");

    /* App heap (1GB, NORESERVE) */
    p = mmap((void*)LIBOS_APP_HEAP, LIBOS_APP_HEAP_SZ,
             PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] app heap failed\n"); }
    else printf("  0x500000000: app heap 1GB OK\n");

    /* Control pages */
    mmap((void*)LIBOS_CONTROL_600, 4096, PROT_READ|PROT_WRITE,
         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    mmap((void*)LIBOS_CONTROL_700, 4096, PROT_READ|PROT_WRITE,
         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    mmap((void*)LIBOS_CONFIG, 65536, PROT_READ|PROT_WRITE,
         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|MAP_NORESERVE, -1, 0);
    mmap((void*)LIBOS_ADDITIONAL, 65536, PROT_READ|PROT_WRITE,
         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|MAP_NORESERVE, -1, 0);

    /* High control + thread environment */
    mmap((void*)LIBOS_HIGH_CONTROL, 4096, PROT_READ|PROT_WRITE,
         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    mmap((void*)LIBOS_THREAD_ENV, LIBOS_THREAD_ENV_SZ, PROT_READ|PROT_WRITE,
         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);

    /* KUSER_SHARED_DATA at 0x7ffe0000.
     * The PE (sqlpal.dll) RVA 0x211650 allocates this via DK PAL
     * (VirtualAllocate through FUN_0x378c10). Multiple PE init
     * functions (RVA 0x276bd5, 0x277fc, 0x27840b, 0x25ca63...)
     * READ from 0x7ffe0008/0x7ffe0014/0x7ffe0030 before the
     * allocation runs in our boot order. Pre-map the page with
     * zero content so those early reads succeed — the PE's own
     * allocator will still run later and MAP_FIXED_NOREPLACE
     * falls through to mprotect in DK_VirtualMemoryAllocate. */
    p = mmap((void*)0x7ffe0000ULL, 4096, PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] KUSER_SHARED_DATA 0x7ffe0000 failed\n"); }
    else {
        printf("  0x7ffe0000: KUSER_SHARED_DATA page OK\n");
        /* Populate a few known fields of KUSER_SHARED_DATA that the PE reads.
         * Layout from Windows Research Kernel / public headers:
         *   +0x00  uint32  TickCountLowDeprecated
         *   +0x04  uint32  TickCountMultiplier  (e.g. 0x0fa00000)
         *   +0x08  uint64  InterruptTime       (100ns units)
         *   +0x14  uint64  SystemTime          (100ns since 1601-01-01)
         *   +0x20  uint64  TimeZoneBias
         *   +0x30  ???     Various
         * Leave mostly zero; fill the ones the PE loads right at startup. */
        *(volatile uint32_t*)(0x7ffe0000ULL + 0x04) = 0x0fa00000; /* multiplier */
    }

    printf("  All memory regions configured\n\n");
    return 0;
}

/* ================================================================
 * Main Entry Point
 * ================================================================ */

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  Drawbridge Host v2.0 - Generic NTUM Runtime    ║\n");
    printf("║  Reimplemented from SQLPAL reverse engineering   ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <windows.exe> [--sfp-dir <path>]\n", argv[0]);
        fprintf(stderr, "\nRuns a Windows PE64 through the real NTUM (sqlpal.dll).\n");
        fprintf(stderr, "Requires extracted SFP packages in --sfp-dir.\n");
        return 1;
    }

    const char *target_exe = argv[1];
    const char *sfp_dir = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sfp-dir") == 0 && i+1 < argc) {
            sfp_dir = argv[++i];
        }
    }

    if (!sfp_dir) {
        sfp_dir = "deps/mssql-extracted/opt/mssql/lib";
        printf("[HOST] Using default SFP dir: %s\n", sfp_dir);
    }

    /* Step 1: Set up LibOS memory regions */
    setup_libos_memory();

    /* Step 2: Load SFP archives */
    printf("[HOST] Loading SFP archives from %s\n", sfp_dir);

    char path[512];
    sfp_archive_t system_sfp = {0};
    sfp_archive_t common_sfp = {0};

    snprintf(path, sizeof(path), "%s/system.sfp", sfp_dir);
    if (load_sfp(path, &system_sfp) != 0) {
        fprintf(stderr, "[HOST] Cannot load system.sfp\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/system.common.sfp", sfp_dir);
    if (load_sfp(path, &common_sfp) != 0) {
        printf("[HOST] system.common.sfp not found (optional)\n");
    }

    /* Step 3: Map sqlpal.dll (the NTUM kernel) from system.sfp */
    printf("\n[HOST] Loading NTUM kernel (sqlpal.dll)...\n");
    void *ntum = map_pe_from_sfp(&system_sfp, "sqlpal.dll", NULL);
    void *ntum_raw = ntum;  /* Save raw PE data pointer for demand-paging */
    if (!ntum) {
        fprintf(stderr, "[HOST] Cannot load sqlpal.dll from system.sfp\n");
        return 1;
    }

    /* Step 4: Map other key DLLs */
    printf("[HOST] Loading support DLLs...\n");
    map_pe_from_sfp(&system_sfp, "DkDll.dll", NULL);
    map_pe_from_sfp(&system_sfp, "AppLoader.exe", NULL);
    map_pe_from_sfp(&system_sfp, "vcruntime140.dll", NULL);

    /* Step 4b: Parse sqlpal.dll PE using proper structures and map sections */
    printf("\n[HOST] Parsing NTUM PE with proper structures...\n");
    uint32_t pe_entry_rva = 0;
    uint32_t pe_size_of_image = 0;
    {
        uint8_t *pe_data = (uint8_t*)ntum;
        pe_dos_header_t *dos = (pe_dos_header_t*)pe_data;

        if (dos->e_magic != PE_DOS_MAGIC) {
            fprintf(stderr, "[HOST] Bad DOS magic: 0x%x\n", dos->e_magic);
            return 1;
        }

        uint32_t *pe_sig = (uint32_t*)(pe_data + dos->e_lfanew);
        if (*pe_sig != PE_SIGNATURE) {
            fprintf(stderr, "[HOST] Bad PE signature: 0x%x\n", *pe_sig);
            return 1;
        }

        pe_file_header_t *file_hdr = (pe_file_header_t*)((uint8_t*)pe_sig + 4);
        pe_optional_header_64_t *opt = (pe_optional_header_64_t*)(
            (uint8_t*)file_hdr + sizeof(pe_file_header_t));

        if (opt->Magic != PE_OPT_MAGIC_64) {
            fprintf(stderr, "[HOST] Not PE32+: magic=0x%x\n", opt->Magic);
            return 1;
        }

        pe_entry_rva = opt->AddressOfEntryPoint;
        pe_size_of_image = opt->SizeOfImage;
        uint64_t image_base = opt->ImageBase;

        pe_section_header_t *sections = (pe_section_header_t*)(
            (uint8_t*)opt + file_hdr->SizeOfOptionalHeader);

        printf("  Machine:  0x%x (%s)\n", file_hdr->Machine,
               file_hdr->Machine == PE_MACHINE_AMD64 ? "AMD64" : "other");
        printf("  Sections: %d\n", file_hdr->NumberOfSections);
        printf("  ImageBase:    0x%lx\n", (unsigned long)image_base);
        printf("  SizeOfImage:  0x%x\n", pe_size_of_image);
        printf("  EntryPoint:   0x%x\n", pe_entry_rva);
        printf("  SizeOfHeaders: 0x%x\n", opt->SizeOfHeaders);
        printf("  Subsystem:    %d\n", opt->Subsystem);

        /* Map at the PE's preferred ImageBase */
        munmap((void*)LIBOS_IMAGE_BASE, 4096);
        void *img_base = mmap((void*)image_base, pe_size_of_image + 0x10000,
                               PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
                               -1, 0);
        if (img_base == MAP_FAILED) {
            fprintf(stderr, "[HOST] Cannot map PE at 0x%lx\n", (unsigned long)image_base);
            return 1;
        }

        /* Copy PE headers */
        memcpy(img_base, pe_data, opt->SizeOfHeaders);

        /* Copy each section using pe_section_header_t */
        size_t raw_file_size = 0;
        for (int i = 0; i < file_hdr->NumberOfSections; i++) {
            pe_section_header_t *sec = &sections[i];
            char name[9] = {0};
            memcpy(name, sec->Name, 8);

            uint32_t copy_sz = sec->SizeOfRawData < sec->VirtualSize
                             ? sec->SizeOfRawData : sec->VirtualSize;

            if (sec->SizeOfRawData > 0) {
                memcpy((uint8_t*)img_base + sec->VirtualAddress,
                       pe_data + sec->PointerToRawData, copy_sz);
                size_t end = sec->PointerToRawData + sec->SizeOfRawData;
                if (end > raw_file_size) raw_file_size = end;
            }

            printf("  %-8s VA=0x%08x VSize=0x%06x RawSz=0x%06x %c%c%c\n",
                   name, sec->VirtualAddress, sec->VirtualSize,
                   sec->SizeOfRawData,
                   (sec->Characteristics & PE_SCN_MEM_READ)    ? 'r' : '-',
                   (sec->Characteristics & PE_SCN_MEM_WRITE)   ? 'w' : '-',
                   (sec->Characteristics & PE_SCN_MEM_EXECUTE) ? 'x' : '-');
        }

        printf("  Mapped at %p, raw file size %lu bytes\n",
               img_base, (unsigned long)raw_file_size);

        /* Tell the signal handler where the raw PE data is */
        ntum_signal_set_pe_data(ntum_raw, raw_file_size, image_base);

        ntum = img_base;
    }

    /* Step 5: Load target EXE */
    printf("\n[HOST] Target: %s\n", target_exe);
    struct stat st;
    if (stat(target_exe, &st) != 0) {
        fprintf(stderr, "[HOST] Cannot find: %s\n", target_exe);
        return 1;
    }
    printf("[HOST] Size: %lu bytes\n", (unsigned long)st.st_size);

    /* Step 6: Bootstrap the NTUM */
    printf("\n[HOST] ═══════════════════════════════════════════\n");
    printf("[HOST] Bootstrapping NTUM kernel...\n");
    printf("[HOST] ═══════════════════════════════════════════\n\n");

    /* Initialize signal handling FIRST (before any NTUM code runs) */
    ntum_signal_init();

    /* Initialize DK PAL */
    dk_pal_init();

    /* Allocate params in LibOS address space (NTUM requires addr < 0x400000000000) */
    WINDOWS_LIBOS_PARAMETERS *libos_params_ptr = (WINDOWS_LIBOS_PARAMETERS*)
        mmap((void*)0x100010000ULL, sizeof(WINDOWS_LIBOS_PARAMETERS),
             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (libos_params_ptr == MAP_FAILED) {
        libos_params_ptr = (WINDOWS_LIBOS_PARAMETERS*)
            mmap(NULL, sizeof(WINDOWS_LIBOS_PARAMETERS),
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    WINDOWS_LIBOS_PARAMETERS *libos_params = libos_params_ptr;
    printf("[HOST] LIBOS_PARAMS at %p (in LibOS address space)\n", (void*)libos_params);
    ntum_bootstrap_init(libos_params, ntum,
                        pe_size_of_image ? pe_size_of_image : 16 * 1024 * 1024,
                        pe_entry_rva ? pe_entry_rva : 0x3A04D0,
                        dk_pal_get_table());

    printf("\n[HOST] Launching NTUM boot thread...\n");
    printf("[HOST] This will switch to Windows x64 ABI and enter sqlpal.dll\n\n");

    int boot_result = ntum_bootstrap_launch(libos_params);
    if (boot_result != 0) {
        fprintf(stderr, "[HOST] NTUM boot failed\n");
    }

    /* Cleanup */
    if (system_sfp.fd > 0) close(system_sfp.fd);
    if (common_sfp.fd > 0) close(common_sfp.fd);
    free(system_sfp.name_table);
    free(common_sfp.name_table);

    return 0;
}
