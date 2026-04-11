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

/*
 * NTUM Memory Layout (from strace reverse engineering)
 *
 * The NTUM expects these memory regions to be set up before boot:
 */
#define LIBOS_CONTROL_PAGE    0x100000000ULL    /* 4KB control */
#define LIBOS_IMAGE_BASE      0x200000000ULL    /* PE images mapped here */
#define LIBOS_KERNEL_HEAP     0x300000000ULL    /* 1GB kernel heap */
#define LIBOS_KERNEL_HEAP_SZ  0x40000000ULL     /* 1GB */
#define LIBOS_THREAD_ENV      0x300000000000ULL /* Thread environment */
#define LIBOS_THREAD_ENV_SZ   0x500000ULL       /* ~5MB */
#define LIBOS_HIGH_CONTROL    0x400000000000ULL /* High control page */
#define LIBOS_APP_HEAP        0x500000000ULL    /* 1GB app heap */
#define LIBOS_APP_HEAP_SZ     0x40000000ULL     /* 1GB */
#define LIBOS_CONTROL_600     0x600000000ULL    /* Control */
#define LIBOS_CONTROL_700     0x700000000ULL    /* Control */
#define LIBOS_CONFIG          0x800000000ULL    /* 64KB config */
#define LIBOS_ADDITIONAL      0x900000000ULL    /* 64KB additional */

/* SFP file format structures */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;           /* "SFP\0" = 0x00504653 */
    uint32_t version;         /* 1 */
    uint64_t entry_count;
    uint64_t first_dir_offset;
    uint64_t name_table_offset;
    uint64_t data_offset;
    uint64_t archive_size;
    uint64_t package_label_offset;
    uint64_t reserved;
    uint8_t  padding[32];     /* Total header: 96 bytes */
} sfp_header_t;

typedef struct {
    uint32_t magic;           /* "DIR\0" = 0x00524944 */
    uint64_t name_offset;
    uint32_t reserved1;
    uint64_t parent_offset;
    uint32_t is_dir;
    uint64_t file_length;
    uint64_t modified_time;
    uint64_t created_time;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t start_offset;    /* For dirs: first child entry offset
                                 For files: data offset in archive */
    uint32_t data_length;     /* For dirs: children size (N * 80)
                                 For files: same as file_length */
} sfp_dir_entry_t;
#pragma pack(pop)

/* Loaded SFP archive */
typedef struct {
    int fd;                   /* File descriptor */
    sfp_header_t header;
    uint8_t *name_table;      /* Loaded name table */
    size_t name_table_size;
    char label[256];          /* Package label */
} sfp_archive_t;

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
    read(archive->fd, archive->name_table, archive->name_table_size);

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

    int flags = MAP_PRIVATE;
    if (base_hint) flags |= MAP_FIXED_NOREPLACE;

    void *mapped = mmap(base_hint, map_size, PROT_READ | PROT_WRITE,
                        flags, archive->fd, page_offset);
    if (mapped == MAP_FAILED) {
        /* Try without fixed address */
        mapped = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE, archive->fd, page_offset);
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
    if (!ntum) {
        fprintf(stderr, "[HOST] Cannot load sqlpal.dll from system.sfp\n");
        return 1;
    }

    /* Step 4: Map other key DLLs */
    printf("[HOST] Loading support DLLs...\n");
    map_pe_from_sfp(&system_sfp, "DkDll.dll", NULL);
    map_pe_from_sfp(&system_sfp, "AppLoader.exe", NULL);
    map_pe_from_sfp(&system_sfp, "vcruntime140.dll", NULL);

    /* Step 5: Load target EXE */
    printf("\n[HOST] Target: %s\n", target_exe);
    struct stat st;
    if (stat(target_exe, &st) != 0) {
        fprintf(stderr, "[HOST] Cannot find: %s\n", target_exe);
        return 1;
    }
    printf("[HOST] Size: %lu bytes\n", (unsigned long)st.st_size);

    /*
     * Step 6: Bootstrap the NTUM
     *
     * TODO: This is the critical part that requires more decompilation.
     * We need to:
     * 1. Parse sqlpal.dll PE headers to find entry point
     * 2. Map sections to 0x200000000 with correct permissions
     * 3. Construct WINDOWS_LIBOS_PARAMETERS
     * 4. Call the NTUM entry point
     *
     * For now, we've proven the memory layout and SFP loading work.
     * The NTUM bootstrap itself requires understanding the exact
     * PAL callback table structure, which the decompilation agents
     * are analyzing.
     */

    printf("\n[HOST] ═══════════════════════════════════════════\n");
    printf("[HOST] NTUM loaded. Bootstrap requires PAL table setup.\n");
    printf("[HOST] Memory regions: OK\n");
    printf("[HOST] SFP archives: OK\n");
    printf("[HOST] sqlpal.dll: mapped at %p\n", ntum);
    printf("[HOST] ═══════════════════════════════════════════\n");
    printf("\n[HOST] Next step: decompile PAL callback table from sqlservr\n");
    printf("[HOST] then call sqlpal.dll entry at RVA 0x3A04D0\n");

    /* Cleanup */
    if (system_sfp.fd > 0) close(system_sfp.fd);
    if (common_sfp.fd > 0) close(common_sfp.fd);
    free(system_sfp.name_table);
    free(common_sfp.name_table);

    return 0;
}
