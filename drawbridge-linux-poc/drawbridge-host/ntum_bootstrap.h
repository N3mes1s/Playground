/*
 * NTUM Bootstrap - Initialize and call the Drawbridge NTUM kernel
 *
 * Based on reverse engineering of sqlservr's boot sequence.
 * Sets up WINDOWS_LIBOS_PARAMETERS and calls sqlpal.dll entry.
 */

#ifndef NTUM_BOOTSTRAP_H
#define NTUM_BOOTSTRAP_H

#include <stdint.h>

/*
 * WINDOWS_LIBOS_PARAMETERS structure (0x190 = 400 bytes)
 *
 * Reverse-engineered from sqlservr at function 0x10ba60.
 * The NTUM entry point receives a pointer to this structure.
 */
#pragma pack(push, 1)
typedef struct {
    uint64_t Size;                    /* 0x000: = 0x90 (header size) */
    uint32_t SubHeaderSize;           /* 0x008: = 0x38 */
    uint32_t _pad0;                   /* 0x00C */
    void    *HostAbiTable;            /* 0x010: PAL function dispatch table */
    void    *RuntimeCallbackState;    /* 0x018: host callback state */
    void    *StackReservation;        /* 0x020: stack size (0x18) */
    uint16_t MajorVersion;            /* 0x028: OS major version */
    uint16_t MinorVersion;            /* 0x02A: OS minor version */
    uint32_t _pad1;                   /* 0x02C */
    void    *HostExtensionEntryPoint; /* 0x030 */
    void    *ImageBase;               /* 0x038: sqlpal.dll image base */
    uint64_t ImageLength;             /* 0x040: sqlpal.dll image size */
    void    *ParameterBuffer;         /* 0x048: allocated param buffer */
    uint64_t ParameterBufferSize;     /* 0x050 */
    uint8_t  HasEnclave;              /* 0x058: SGX flag */
    uint8_t  _pad2[7];               /* 0x059 */
    void    *ProcessorInfo;           /* 0x060 */
    uint32_t NumaNodeCount;           /* 0x068 */
    uint32_t _pad3;                   /* 0x06C */
    uint8_t  FeatureFlags[0x20];      /* 0x070: capability flags */
    /* 0x090: ABI dispatch sub-structure follows */
    uint8_t  AbiDispatch[0xE0];       /* 0x090: 31 entries × varies */
    void    *BootEntryPoint;          /* 0x170: StartModule function */
    uint8_t  _remaining[0x18];        /* 0x178-0x18F */
} WINDOWS_LIBOS_PARAMETERS;
#pragma pack(pop)

/* Feature flag constants */
#define FEATURE_BASE_PAL        0x40000     /* Always set */
#define FEATURE_LARGE_PAGE_DLLS 0x800000
#define FEATURE_TLS             0x20000
#define FEATURE_SHARED_MEM      0x200000
#define FEATURE_IO_EXTRA        0x80000
#define FEATURE_IO_URING        0x100000    /* kernel >= 5.11 */

/*
 * PAL function dispatch entry (in the ABI table)
 * Each entry is 0x20 bytes.
 */
typedef struct {
    uint64_t version;
    void    *function_ptr;
    uint64_t reserved[2];
} pal_abi_entry_t;

/*
 * Initialize the bootstrap parameters.
 *
 * @param params       Output: filled WINDOWS_LIBOS_PARAMETERS
 * @param image_base   Mapped base address of sqlpal.dll
 * @param image_size   Size of the mapped PE image
 * @param entry_rva    RVA of the DllMain/StartModule entry
 * @param pal_table    PAL function dispatch table
 */
void ntum_bootstrap_init(WINDOWS_LIBOS_PARAMETERS *params,
                          void *image_base, uint64_t image_size,
                          uint64_t entry_rva, void *pal_table);

/*
 * Launch the NTUM boot thread.
 *
 * This creates a new thread with a fresh stack in the LibOS
 * address space, switches to Windows x64 calling convention,
 * and jumps to the StartModule entry point.
 *
 * @param params   Filled WINDOWS_LIBOS_PARAMETERS
 * @return         0 on success, -1 on failure
 */
int ntum_bootstrap_launch(WINDOWS_LIBOS_PARAMETERS *params);

/*
 * The trampoline function that switches ABI and enters the NTUM.
 * Implemented in assembly.
 *
 * Converts from Linux SysV ABI to Windows x64:
 *   - Moves args from rdi/rsi to rcx/rdx
 *   - Sets up fresh stack in LibOS space
 *   - Jumps to StartModule entry
 */
void ntum_trampoline(void *entry_point, void *stack_ptr,
                     void *param1, void *param2);

#endif /* NTUM_BOOTSTRAP_H */
