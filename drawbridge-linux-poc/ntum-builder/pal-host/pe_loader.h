#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <stdint.h>
#include <stddef.h>

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr;
    uint16_t e_minalloc, e_maxalloc, e_ss, e_sp, e_csum;
    uint16_t e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit;
    uint64_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit;
    uint32_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

/* Loaded PE image */
typedef struct {
    uint8_t  *base;
    size_t    size;
    uint64_t  preferred_base;
    uint64_t  actual_base;
    uint64_t  entry_point;
    int       is_64bit;
    int       is_dll;
    int       relocated;
    int       num_sections;
    uint8_t  *import_dir;
    uint32_t  import_dir_size;
    uint8_t  *export_dir;
    uint32_t  export_dir_size;
} pe_loaded_image_t;

/* Import resolver callback */
typedef void *(*import_resolver_fn)(const char *dll_name,
                                     const char *func_name,
                                     uint16_t ordinal,
                                     void *ctx);

/* Load a PE image from disk */
int pe_load_image(const char *path, pe_loaded_image_t *image);

/* Resolve imports using a callback */
int pe_resolve_imports(pe_loaded_image_t *image,
                       import_resolver_fn resolver, void *ctx);

/* Find an export by name */
void *pe_find_export(pe_loaded_image_t *image, const char *name);

/* Unload a PE image */
void pe_unload_image(pe_loaded_image_t *image);

#endif
