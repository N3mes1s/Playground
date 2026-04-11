#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <stdint.h>
#include <stddef.h>

/*
 * PE/COFF Binary Loader
 *
 * Parses Windows PE (Portable Executable) files and maps them into
 * Linux process memory. Resolves imports against our libos stubs.
 *
 * PE file structure:
 *   DOS Header -> PE Signature -> COFF Header -> Optional Header
 *   -> Section Headers -> Section Data
 */

/* ---- PE/COFF Structures (matching Windows definitions) ---- */

#define IMAGE_DOS_SIGNATURE    0x5A4D      /* "MZ" */
#define IMAGE_NT_SIGNATURE     0x00004550  /* "PE\0\0" */

#define IMAGE_FILE_MACHINE_AMD64  0x8664
#define IMAGE_FILE_MACHINE_I386   0x014C

/* Section characteristics flags */
#define IMAGE_SCN_CNT_CODE                0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA    0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA  0x00000080
#define IMAGE_SCN_MEM_EXECUTE             0x20000000
#define IMAGE_SCN_MEM_READ                0x40000000
#define IMAGE_SCN_MEM_WRITE               0x80000000

/* Directory entries */
#define IMAGE_DIRECTORY_ENTRY_IMPORT      1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES   16

/* Relocation types */
#define IMAGE_REL_BASED_ABSOLUTE          0
#define IMAGE_REL_BASED_HIGH              1
#define IMAGE_REL_BASED_LOW               2
#define IMAGE_REL_BASED_HIGHLOW           3
#define IMAGE_REL_BASED_DIR64             10

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;       /* MZ signature */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;      /* Offset to PE header */
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

/* PE32+ Optional Header (64-bit) */
typedef struct {
    uint16_t Magic;                     /* 0x20b for PE32+ */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

/* PE32 Optional Header (32-bit) */
typedef struct {
    uint16_t Magic;                     /* 0x10b for PE32 */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint32_t             Signature;     /* "PE\0\0" */
    IMAGE_FILE_HEADER    FileHeader;
    /* Optional header follows - size varies by architecture */
} IMAGE_NT_HEADERS_COMMON;

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

/* Import directory structures */
typedef struct {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;    /* RVA to Import Lookup Table */
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                      /* RVA to DLL name */
    uint32_t FirstThunk;                /* RVA to Import Address Table */
} IMAGE_IMPORT_DESCRIPTOR;

/* Base relocation block */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    /* uint16_t TypeOffset[] follows */
} IMAGE_BASE_RELOCATION;

#pragma pack(pop)

/* ---- Loader API ---- */

/* Import resolver callback: given a DLL name and function name, return
   the address of our stub implementation (or NULL if not found). */
typedef void *(*import_resolver_fn)(const char *dll_name,
                                     const char *func_name,
                                     uint16_t ordinal);

/* Loaded PE image handle */
typedef struct {
    uint8_t  *base;             /* Base address of mapped image */
    size_t    image_size;       /* Total mapped size */
    uint64_t  entry_point;      /* Absolute address of entry point */
    int       is_64bit;         /* 1 if PE32+, 0 if PE32 */
    uint16_t  machine;          /* Machine type */
    uint64_t  preferred_base;   /* Preferred image base from PE header */
    uint64_t  actual_base;      /* Actual base address where loaded */
    int       relocated;        /* 1 if relocations were applied */
    int       num_sections;     /* Number of sections mapped */
    int       num_imports;      /* Number of imports resolved */
} pe_image_t;

/*
 * Load a PE executable from a file.
 *
 * @param path      Path to the .exe file
 * @param resolver  Callback to resolve imported functions
 * @param image     Output: filled with loaded image information
 * @return          0 on success, negative error code on failure
 */
int pe_load(const char *path, import_resolver_fn resolver, pe_image_t *image);

/*
 * Unload a previously loaded PE image.
 */
void pe_unload(pe_image_t *image);

/*
 * Get a human-readable error description for the last pe_load failure.
 */
const char *pe_strerror(int err);

/* Error codes */
#define PE_OK                   0
#define PE_ERR_FILE            -1   /* Cannot open/read file */
#define PE_ERR_DOS_HEADER      -2   /* Invalid DOS header */
#define PE_ERR_PE_SIGNATURE    -3   /* Invalid PE signature */
#define PE_ERR_MACHINE         -4   /* Unsupported machine type */
#define PE_ERR_MMAP            -5   /* Memory mapping failed */
#define PE_ERR_SECTION         -6   /* Section mapping failed */
#define PE_ERR_IMPORT          -7   /* Import resolution failed */
#define PE_ERR_RELOC           -8   /* Relocation failed */
#define PE_ERR_OPTIONAL_HDR    -9   /* Invalid optional header */

#endif /* PE_LOADER_H */
