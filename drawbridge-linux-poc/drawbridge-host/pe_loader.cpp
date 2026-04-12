/*
 * pe_loader.c — Component C1 (PE Loader & SFP).
 *
 * Carved out of drawbridge-host/main.c per
 * /root/.claude/plans/hashed-sparking-lake.md (Wave 1, Agent G, M7).
 *
 * Source mapping:
 *   analysis/sqlservr_FULL.c FUN_002051e0 / map_pe_from_sfp / SFP
 *   parser — this file is the *translation* of the ELF host's PE
 *   loader into the Linux-host body that main.c calls out to.
 *   drawbridge-host/main.c lines 52..257 (original) become the
 *   implementations in this TU; main.c becomes a ~50 line shell.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "drawbridge_types.h"
#include "pe_loader.h"

/* ================================================================
 * pe_loader_init — no module-local state today.  Kept as a visible
 * init hook so main.c can call pe_loader_init(); before boot.
 * ================================================================ */
void pe_loader_init(void) { /* no-op */ }

/* ================================================================
 * SFP archive loader — verbatim translation from main.c.
 * ================================================================ */

static const char *sfp_get_name(sfp_archive_t *archive, uint64_t offset)
{
    if (offset >= archive->name_table_size) return "?";
    return (const char *)(archive->name_table + offset);
}

int pe_loader_load_sfp(const char *path, sfp_archive_t *archive)
{
    archive->fd = open(path, O_RDONLY);
    if (archive->fd < 0) return -1;

    if (read(archive->fd, &archive->header, sizeof(sfp_header_t))
        != sizeof(sfp_header_t)) {
        close(archive->fd);
        return -1;
    }

    if (archive->header.magic != 0x00504653) {  /* "SFP\0" */
        fprintf(stderr, "[SFP] Bad magic in %s: 0x%08x\n",
                path, archive->header.magic);
        close(archive->fd);
        return -1;
    }

    archive->name_table_size =
        archive->header.data_offset - archive->header.name_table_offset;
    archive->name_table = malloc(archive->name_table_size);
    if (!archive->name_table) { close(archive->fd); return -1; }

    lseek(archive->fd, archive->header.name_table_offset, SEEK_SET);
    ssize_t nr = read(archive->fd, archive->name_table,
                      archive->name_table_size);
    (void)nr;

    uint64_t label_rel =
        archive->header.package_label_offset - archive->header.name_table_offset;
    const char *label = sfp_get_name(archive, label_rel);
    if (label) {
        strncpy(archive->label, label, sizeof(archive->label) - 1);
    }

    uint64_t dir_size =
        archive->header.name_table_offset - archive->header.first_dir_offset;
    unsigned long num_entries = dir_size / 80;  /* sizeof(sfp_dir_entry) */

    printf("[SFP] Loaded: %s (label=%s, %lu entries)\n",
           path, archive->label, num_entries);
    return 0;
}

/* ================================================================
 * SFP directory recursive search.
 * ================================================================ */

static int sfp_find_file_r(sfp_archive_t *archive, uint64_t dir_offset,
                           const char *target, uint64_t *data_offset,
                           uint64_t *data_size)
{
    sfp_dir_entry_t entry;
    lseek(archive->fd, dir_offset, SEEK_SET);
    if (read(archive->fd, &entry, sizeof(entry)) != sizeof(entry))
        return -1;

    uint64_t name_idx =
        entry.name_offset >= archive->header.name_table_offset
            ? entry.name_offset - archive->header.name_table_offset
            : entry.name_offset;
    const char *name = sfp_get_name(archive, name_idx);

    if (!entry.is_dir) {
        if (strcasecmp(name, target) == 0) {
            *data_offset = entry.start_offset;
            *data_size   = entry.file_length;
            return 0;
        }
        return -1;
    }

    for (uint64_t off = entry.start_offset;
         off < entry.start_offset + entry.data_length;
         off += sizeof(sfp_dir_entry_t)) {
        if (sfp_find_file_r(archive, off, target, data_offset, data_size) == 0)
            return 0;
    }
    return -1;
}

int pe_loader_sfp_find_file(sfp_archive_t *archive, const char *name,
                            uint64_t *data_offset, uint64_t *data_size)
{
    return sfp_find_file_r(archive, archive->header.first_dir_offset,
                           name, data_offset, data_size);
}

/* ================================================================
 * Map a PE file from inside an SFP archive directly into memory.
 * ================================================================ */

void *pe_loader_map_pe_from_sfp(sfp_archive_t *archive, const char *name,
                                void *base_hint)
{
    uint64_t data_offset, data_size;
    if (pe_loader_sfp_find_file(archive, name, &data_offset, &data_size) != 0) {
        fprintf(stderr, "[SFP] File not found: %s\n", name);
        return NULL;
    }

    uint64_t page_offset = data_offset & ~0xFFFULL;
    uint64_t offset_adj  = data_offset - page_offset;
    size_t   map_size    = (data_size + offset_adj + 4095) & ~4095ULL;

    /* All SFP mappings must land in the LibOS address range.
     * The NTUM uses these addresses in thread context frames and
     * expects them to be within the valid LibOS range. */
    static uint64_t sfp_map_next = 0x3FFF80000000ULL;
    int flags = MAP_PRIVATE;
    if (base_hint) {
        flags |= MAP_FIXED_NOREPLACE;
    } else {
        base_hint = (void *)__atomic_fetch_add(&sfp_map_next,
                                                map_size + 0x1000,
                                                __ATOMIC_SEQ_CST);
    }

    void *mapped = mmap(base_hint, map_size, PROT_READ | PROT_WRITE,
                        flags, archive->fd, page_offset);
    if (mapped == MAP_FAILED && base_hint) {
        /* Fall back to MAP_FIXED (overwrite). */
        mapped = mmap(base_hint, map_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_FIXED, archive->fd, page_offset);
    }
    if (mapped == MAP_FAILED) return NULL;

    printf("[HOST] Mapped %s from SFP at %p (%lu KB)\n",
           name, mapped, (unsigned long)(data_size / 1024));
    return (uint8_t *)mapped + offset_adj;
}

/* ================================================================
 * PE parser + section mapper — previously inline in main.c at the
 * "Parsing NTUM PE with proper structures..." block.
 * ================================================================ */

void *pe_loader_parse_and_map(void *raw_pe_data,
                              void **out_image_base,
                              uint32_t *out_size_of_image,
                              uint32_t *out_entry_rva,
                              size_t   *out_raw_size)
{
    uint8_t *pe_data = (uint8_t *)raw_pe_data;
    pe_dos_header_t *dos = (pe_dos_header_t *)pe_data;

    if (dos->e_magic != PE_DOS_MAGIC) {
        fprintf(stderr, "[HOST] Bad DOS magic: 0x%x\n", dos->e_magic);
        return NULL;
    }

    uint32_t *pe_sig = (uint32_t *)(pe_data + dos->e_lfanew);
    if (*pe_sig != PE_SIGNATURE) {
        fprintf(stderr, "[HOST] Bad PE signature: 0x%x\n", *pe_sig);
        return NULL;
    }

    pe_file_header_t *file_hdr = (pe_file_header_t *)((uint8_t *)pe_sig + 4);
    pe_optional_header_64_t *opt = (pe_optional_header_64_t *)(
        (uint8_t *)file_hdr + sizeof(pe_file_header_t));

    if (opt->Magic != PE_OPT_MAGIC_64) {
        fprintf(stderr, "[HOST] Not PE32+: magic=0x%x\n", opt->Magic);
        return NULL;
    }

    uint32_t entry_rva     = opt->AddressOfEntryPoint;
    uint32_t size_of_image = opt->SizeOfImage;
    uint64_t image_base    = opt->ImageBase;

    pe_section_header_t *sections = (pe_section_header_t *)(
        (uint8_t *)opt + file_hdr->SizeOfOptionalHeader);

    printf("  Machine:  0x%x (%s)\n", file_hdr->Machine,
           file_hdr->Machine == PE_MACHINE_AMD64 ? "AMD64" : "other");
    printf("  Sections: %d\n", file_hdr->NumberOfSections);
    printf("  ImageBase:    0x%lx\n", (unsigned long)image_base);
    printf("  SizeOfImage:  0x%x\n", size_of_image);
    printf("  EntryPoint:   0x%x\n", entry_rva);
    printf("  SizeOfHeaders: 0x%x\n", opt->SizeOfHeaders);
    printf("  Subsystem:    %d\n", opt->Subsystem);

    /* Map at the PE's preferred ImageBase.  The caller (main.c) has
     * already munmap'd the placeholder at LIBOS_IMAGE_BASE. */
    munmap((void *)LIBOS_IMAGE_BASE, 4096);
    void *img_base = mmap((void *)image_base, size_of_image + 0x10000,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
                          -1, 0);
    if (img_base == MAP_FAILED) {
        fprintf(stderr, "[HOST] Cannot map PE at 0x%lx\n",
                (unsigned long)image_base);
        return NULL;
    }

    /* Copy PE headers. */
    memcpy(img_base, pe_data, opt->SizeOfHeaders);

    /* Copy each section using pe_section_header_t. */
    size_t raw_file_size = 0;
    for (int i = 0; i < file_hdr->NumberOfSections; i++) {
        pe_section_header_t *sec = &sections[i];
        char name[9] = {0};
        memcpy(name, sec->Name, 8);

        uint32_t copy_sz = sec->SizeOfRawData < sec->VirtualSize
                         ? sec->SizeOfRawData : sec->VirtualSize;

        if (sec->SizeOfRawData > 0) {
            memcpy((uint8_t *)img_base + sec->VirtualAddress,
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

    if (out_image_base)    *out_image_base    = (void *)image_base;
    if (out_size_of_image) *out_size_of_image = size_of_image;
    if (out_entry_rva)     *out_entry_rva     = entry_rva;
    if (out_raw_size)      *out_raw_size      = raw_file_size;

    return img_base;
}

/* ================================================================
 * LibOS memory region setup — was setup_libos_memory() in main.c.
 * ================================================================ */

int pe_loader_setup_libos_memory(void)
{
    printf("[HOST] Setting up LibOS memory regions...\n");

    void *p;

    p = mmap((void *)LIBOS_CONTROL_PAGE, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] 0x100000000 failed\n"); }
    else printf("  0x100000000: control page OK\n");

    p = mmap((void *)LIBOS_IMAGE_BASE, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] 0x200000000 failed\n"); }
    else printf("  0x200000000: image base OK\n");

    p = mmap((void *)LIBOS_KERNEL_HEAP, LIBOS_KERNEL_HEAP_SZ,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
             -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] kernel heap failed\n"); }
    else printf("  0x300000000: kernel heap 1GB OK\n");

    p = mmap((void *)LIBOS_APP_HEAP, LIBOS_APP_HEAP_SZ,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
             -1, 0);
    if (p == MAP_FAILED) { printf("  [WARN] app heap failed\n"); }
    else printf("  0x500000000: app heap 1GB OK\n");

    mmap((void *)LIBOS_CONTROL_600, 4096, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    mmap((void *)LIBOS_CONTROL_700, 4096, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    mmap((void *)LIBOS_CONFIG, 65536, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
         -1, 0);
    mmap((void *)LIBOS_ADDITIONAL, 65536, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
         -1, 0);

    mmap((void *)LIBOS_HIGH_CONTROL, 4096, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    mmap((void *)LIBOS_THREAD_ENV, LIBOS_THREAD_ENV_SZ, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

    /* KUSER_SHARED_DATA at 0x7ffe0000: pre-map with zero content so
     * early PE reads succeed.  See main.c for the full rationale. */
    p = mmap((void *)0x7ffe0000ULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) {
        printf("  [WARN] KUSER_SHARED_DATA 0x7ffe0000 failed\n");
    } else {
        printf("  0x7ffe0000: KUSER_SHARED_DATA page OK\n");
        /* TickCountMultiplier — read by the PE during early boot. */
        *(volatile uint32_t *)(0x7ffe0000ULL + 0x04) = 0x0fa00000;
    }

    printf("  All memory regions configured\n\n");
    return 0;
}
