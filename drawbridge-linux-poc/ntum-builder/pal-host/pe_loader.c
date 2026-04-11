/*
 * PE Loader for Linux PAL Host
 *
 * Loads Windows PE executables and DLLs into Linux process memory.
 * Based on reverse engineering of sqlservr's BinaryPeParser and
 * PalMemoryMapPeBinary components.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "pe_loader.h"

/* Read entire file into memory */
static uint8_t *read_file(const char *path, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }

    uint8_t *data = malloc(st.st_size);
    if (!data) { close(fd); return NULL; }

    ssize_t n = read(fd, data, st.st_size);
    close(fd);
    if (n != st.st_size) { free(data); return NULL; }

    *out_size = st.st_size;
    return data;
}

/* Convert PE section characteristics to mmap protection flags */
static int pe_prot_to_linux(uint32_t characteristics) {
    int prot = 0;
    if (characteristics & 0x20000000) prot |= PROT_EXEC;
    if (characteristics & 0x40000000) prot |= PROT_READ;
    if (characteristics & 0x80000000) prot |= PROT_WRITE;
    return prot ? prot : PROT_READ;
}

int pe_load_image(const char *path, pe_loaded_image_t *image) {
    size_t file_size;
    uint8_t *file_data = read_file(path, &file_size);
    if (!file_data) {
        fprintf(stderr, "[PE] Cannot read: %s\n", path);
        return -1;
    }

    /* Parse DOS header */
    if (file_size < sizeof(IMAGE_DOS_HEADER)) goto fail;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)file_data;
    if (dos->e_magic != 0x5A4D) {
        fprintf(stderr, "[PE] Bad DOS signature in %s\n", path);
        goto fail;
    }

    /* Parse PE signature */
    uint32_t pe_offset = dos->e_lfanew;
    if (pe_offset + 4 + sizeof(IMAGE_FILE_HEADER) > file_size) goto fail;

    uint32_t pe_sig = *(uint32_t*)(file_data + pe_offset);
    if (pe_sig != 0x00004550) {
        fprintf(stderr, "[PE] Bad PE signature in %s\n", path);
        goto fail;
    }

    /* Parse COFF header */
    IMAGE_FILE_HEADER *coff = (IMAGE_FILE_HEADER*)(file_data + pe_offset + 4);
    int is_64bit = (coff->Machine == 0x8664);
    int is_32bit = (coff->Machine == 0x014C);
    if (!is_64bit && !is_32bit) {
        fprintf(stderr, "[PE] Unsupported machine 0x%x in %s\n", coff->Machine, path);
        goto fail;
    }

    image->is_64bit = is_64bit;
    image->is_dll = (coff->Characteristics & 0x2000) != 0;

    /* Parse optional header */
    uint8_t *opt_hdr = (uint8_t*)coff + sizeof(IMAGE_FILE_HEADER);
    uint64_t image_base, entry_rva, size_of_image;
    uint32_t section_alignment;
    uint32_t num_data_dirs;
    IMAGE_DATA_DIRECTORY *data_dirs;

    if (is_64bit) {
        IMAGE_OPTIONAL_HEADER64 *opt = (IMAGE_OPTIONAL_HEADER64*)opt_hdr;
        image_base = opt->ImageBase;
        entry_rva = opt->AddressOfEntryPoint;
        size_of_image = opt->SizeOfImage;
        section_alignment = opt->SectionAlignment;
        num_data_dirs = opt->NumberOfRvaAndSizes;
        data_dirs = opt->DataDirectory;
    } else {
        IMAGE_OPTIONAL_HEADER32 *opt = (IMAGE_OPTIONAL_HEADER32*)opt_hdr;
        image_base = opt->ImageBase;
        entry_rva = opt->AddressOfEntryPoint;
        size_of_image = opt->SizeOfImage;
        section_alignment = opt->SectionAlignment;
        num_data_dirs = opt->NumberOfRvaAndSizes;
        data_dirs = opt->DataDirectory;
    }

    /* Try to allocate at preferred base address first (avoids relocation) */
    void *base = mmap((void*)image_base, size_of_image,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (base == MAP_FAILED) {
        /* Fall back to any address */
        printf("[PE] Cannot map at preferred base 0x%lx, trying any address...\n",
               (unsigned long)image_base);
        base = mmap(NULL, size_of_image,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (base == MAP_FAILED) {
        fprintf(stderr, "[PE] Cannot mmap %lu bytes for %s\n",
                (unsigned long)size_of_image, path);
        goto fail;
    }

    image->base = (uint8_t*)base;
    image->size = size_of_image;
    image->preferred_base = image_base;
    image->actual_base = (uint64_t)base;
    image->entry_point = (uint64_t)base + entry_rva;
    image->relocated = (image->actual_base != image->preferred_base);

    /* Copy headers */
    uint32_t headers_size = is_64bit ?
        (uint32_t)((IMAGE_OPTIONAL_HEADER64*)opt_hdr)->SizeOfHeaders :
        (uint32_t)((IMAGE_OPTIONAL_HEADER32*)opt_hdr)->SizeOfHeaders;
    memcpy(base, file_data, headers_size);

    /* Map sections */
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER*)(
        opt_hdr + coff->SizeOfOptionalHeader);
    image->num_sections = coff->NumberOfSections;

    printf("[PE] Loading %s at %p (preferred 0x%lx, size %lu KB)\n",
           path, base, (unsigned long)image_base,
           (unsigned long)size_of_image / 1024);

    for (int i = 0; i < coff->NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *sec = &sections[i];
        char name[9] = {0};
        memcpy(name, sec->Name, 8);

        uint8_t *dst = (uint8_t*)base + sec->VirtualAddress;
        size_t copy_size = sec->SizeOfRawData < sec->VirtualSize ?
                            sec->SizeOfRawData : sec->VirtualSize;

        if (sec->SizeOfRawData > 0 && sec->PointerToRawData + sec->SizeOfRawData <= file_size) {
            memcpy(dst, file_data + sec->PointerToRawData, copy_size);
        }

        /* Zero remainder of section */
        if (sec->VirtualSize > copy_size) {
            memset(dst + copy_size, 0, sec->VirtualSize - copy_size);
        }

        printf("  Section %-8s at +0x%08x (%6u bytes) %c%c%c\n",
               name, sec->VirtualAddress, sec->VirtualSize,
               (sec->Characteristics & 0x40000000) ? 'r' : '-',
               (sec->Characteristics & 0x80000000) ? 'w' : '-',
               (sec->Characteristics & 0x20000000) ? 'x' : '-');
    }

    /* Apply relocations if needed */
    if (image->relocated && num_data_dirs > 5 && data_dirs[5].VirtualAddress) {
        uint8_t *reloc_data = (uint8_t*)base + data_dirs[5].VirtualAddress;
        uint8_t *reloc_end = reloc_data + data_dirs[5].Size;
        int64_t delta = (int64_t)base - (int64_t)image_base;
        int reloc_count = 0;

        while (reloc_data < reloc_end) {
            uint32_t page_rva = *(uint32_t*)reloc_data;
            uint32_t block_size = *(uint32_t*)(reloc_data + 4);
            if (block_size == 0) break;

            int num_entries = (block_size - 8) / 2;
            uint16_t *entries = (uint16_t*)(reloc_data + 8);

            for (int i = 0; i < num_entries; i++) {
                uint16_t entry = entries[i];
                int type = entry >> 12;
                int offset = entry & 0xFFF;
                uint8_t *target = (uint8_t*)base + page_rva + offset;

                switch (type) {
                    case 0:  /* ABSOLUTE - skip */
                        break;
                    case 3:  /* HIGHLOW (32-bit) */
                        *(uint32_t*)target += (uint32_t)delta;
                        reloc_count++;
                        break;
                    case 10: /* DIR64 (64-bit) */
                        *(uint64_t*)target += delta;
                        reloc_count++;
                        break;
                    default:
                        fprintf(stderr, "[PE] Unknown relocation type %d\n", type);
                        break;
                }
            }
            reloc_data += block_size;
        }
        printf("  Applied %d relocations (delta: 0x%lx)\n", reloc_count, (unsigned long)delta);
    }

    /* Store import directory info for later resolution */
    if (num_data_dirs > 1 && data_dirs[1].VirtualAddress) {
        image->import_dir = (uint8_t*)base + data_dirs[1].VirtualAddress;
        image->import_dir_size = data_dirs[1].Size;
    } else {
        image->import_dir = NULL;
        image->import_dir_size = 0;
    }

    /* Store export directory */
    if (num_data_dirs > 0 && data_dirs[0].VirtualAddress) {
        image->export_dir = (uint8_t*)base + data_dirs[0].VirtualAddress;
        image->export_dir_size = data_dirs[0].Size;
    } else {
        image->export_dir = NULL;
        image->export_dir_size = 0;
    }

    /* Keep all sections RWX for PoC - real implementation would
     * set proper permissions after import resolution */
    mprotect(base, size_of_image, PROT_READ | PROT_WRITE | PROT_EXEC);

    free(file_data);
    return 0;

fail:
    free(file_data);
    return -1;
}

/* Resolve imports for a loaded PE image */
int pe_resolve_imports(pe_loaded_image_t *image,
                       import_resolver_fn resolver, void *resolver_ctx) {
    if (!image->import_dir) return 0;  /* No imports */

    typedef struct {
        uint32_t OriginalFirstThunk;
        uint32_t TimeDateStamp;
        uint32_t ForwarderChain;
        uint32_t Name;
        uint32_t FirstThunk;
    } IMPORT_DESC;

    IMPORT_DESC *imp = (IMPORT_DESC*)image->import_dir;
    int total_resolved = 0;
    int total_failed = 0;

    while (imp->Name != 0) {
        const char *dll_name = (const char*)(image->base + imp->Name);

        /* Walk the IAT */
        uint8_t *thunk_data = image->base + (imp->OriginalFirstThunk ?
                               imp->OriginalFirstThunk : imp->FirstThunk);
        uint8_t *iat = image->base + imp->FirstThunk;

        printf("  Resolving imports from %s:\n", dll_name);

        while (1) {
            uint64_t thunk_val;
            if (image->is_64bit) {
                thunk_val = *(uint64_t*)thunk_data;
                if (thunk_val == 0) break;
            } else {
                thunk_val = *(uint32_t*)thunk_data;
                if (thunk_val == 0) break;
            }

            const char *func_name = NULL;
            uint16_t ordinal = 0;
            int is_ordinal;

            if (image->is_64bit) {
                is_ordinal = (thunk_val >> 63) & 1;
            } else {
                is_ordinal = (thunk_val >> 31) & 1;
            }

            if (is_ordinal) {
                ordinal = (uint16_t)(thunk_val & 0xFFFF);
            } else {
                uint8_t *hint_name = image->base + (uint32_t)thunk_val;
                ordinal = *(uint16_t*)hint_name;
                func_name = (const char*)(hint_name + 2);
            }

            /* Resolve through callback */
            void *addr = resolver(dll_name, func_name, ordinal, resolver_ctx);

            if (addr) {
                if (image->is_64bit)
                    *(uint64_t*)iat = (uint64_t)addr;
                else
                    *(uint32_t*)iat = (uint32_t)(uintptr_t)addr;
                total_resolved++;
            } else {
                if (func_name)
                    fprintf(stderr, "    [MISS] %s!%s\n", dll_name, func_name);
                else
                    fprintf(stderr, "    [MISS] %s!ordinal_%u\n", dll_name, ordinal);
                total_failed++;
            }

            thunk_data += image->is_64bit ? 8 : 4;
            iat += image->is_64bit ? 8 : 4;
        }

        imp++;
    }

    printf("  Imports: %d resolved, %d failed\n", total_resolved, total_failed);
    return total_failed == 0 ? 0 : -1;
}

/* Find an export by name in a loaded PE */
void *pe_find_export(pe_loaded_image_t *image, const char *name) {
    if (!image->export_dir) return NULL;

    typedef struct {
        uint32_t Characteristics;
        uint32_t TimeDateStamp;
        uint16_t MajorVersion;
        uint16_t MinorVersion;
        uint32_t Name;
        uint32_t Base;
        uint32_t NumberOfFunctions;
        uint32_t NumberOfNames;
        uint32_t AddressOfFunctions;
        uint32_t AddressOfNames;
        uint32_t AddressOfNameOrdinals;
    } EXPORT_DIR;

    EXPORT_DIR *exp = (EXPORT_DIR*)image->export_dir;
    uint32_t *names = (uint32_t*)(image->base + exp->AddressOfNames);
    uint16_t *ordinals = (uint16_t*)(image->base + exp->AddressOfNameOrdinals);
    uint32_t *functions = (uint32_t*)(image->base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char *exp_name = (const char*)(image->base + names[i]);
        if (strcmp(exp_name, name) == 0) {
            uint16_t ordinal = ordinals[i];
            return (void*)(image->base + functions[ordinal]);
        }
    }
    return NULL;
}

void pe_unload_image(pe_loaded_image_t *image) {
    if (image->base) {
        munmap(image->base, image->size);
        image->base = NULL;
    }
}
