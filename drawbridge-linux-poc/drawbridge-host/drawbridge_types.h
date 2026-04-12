/*
 * drawbridge_types.h - Core type definitions for the Drawbridge host
 *
 * All structures reverse-engineered from the sqlservr ELF binary
 * and sqlpal.dll PE using Ghidra decompilation and strace analysis.
 *
 * Reference decompiled functions:
 *   FUN_0020ba60 - Guest OS initialization (sets WINDOWS_LIBOS_PARAMETERS)
 *   FUN_0020bcf0 - Stream/feature initialization
 *   FUN_002051e0 - PE loading ("Loading guest - %s")
 *   FUN_0025a520 - Thread creation trampoline
 */

#ifndef DRAWBRIDGE_TYPES_H
#define DRAWBRIDGE_TYPES_H

#include <stdint.h>

/* ================================================================
 * Status Codes (NTSTATUS-compatible)
 * ================================================================ */

#define DK_STATUS_SUCCESS            0x00000000
#define DK_STATUS_NOT_IMPLEMENTED    0xC0000002
#define DK_STATUS_INVALID_PARAM      0xC000000D
#define DK_STATUS_NO_MEMORY          0xC0000017

/* ================================================================
 * Handle Types
 * ================================================================ */

typedef uint64_t DK_HANDLE;
#define DK_NULL_HANDLE 0

/* Handle table entry - maps DK_HANDLE to Linux fd/pointer */
#define MAX_HANDLES 4096

typedef enum {
    HANDLE_FREE    = 0,
    HANDLE_FD      = 1,
    HANDLE_EVENT   = 2,
    HANDLE_THREAD  = 3,
    HANDLE_MUTEX   = 4,
    HANDLE_MAPPED  = 5
} handle_type_t;

/* ================================================================
 * Calling Convention
 *
 * All DK functions use Windows x64 calling convention (ms_abi).
 * On Linux (SysV ABI), we receive args in rdi,rsi,rdx,rcx
 * but the NTUM calls us with args in rcx,rdx,r8,r9.
 * ================================================================ */

#ifdef __GNUC__
#define DK_API __attribute__((ms_abi))
#else
#define DK_API
#endif

/* ================================================================
 * Feature Flags
 *
 * OR'd into WINDOWS_LIBOS_PARAMETERS.FeatureFlags at offset 0x070.
 * From decompiled FUN_0020bcf0 (stream/feature init):
 *   FUN_0029fd70(param_1, 0x40000)   -- always set
 *   FUN_0029fd70(param_1, 0x800000)  -- if large pages
 *   FUN_0029fd70(param_1, 0x20000)   -- if TLS
 *   FUN_0029fd70(param_1, 0x200000)  -- if shared memory
 *   FUN_0029fd70(param_1, 0x80000)   -- if additional I/O
 *   FUN_0029fd70(param_1, 0x100000)  -- if io_uring (kernel >= 5.11)
 * ================================================================ */

#define FEATURE_BASE_PAL          0x40000    /* Always set */
#define FEATURE_TLS               0x20000    /* TLS support */
#define FEATURE_IO_EXTRA          0x80000    /* Additional I/O */
#define FEATURE_IO_URING          0x100000   /* io_uring (kernel >= 5.11) */
#define FEATURE_SHARED_MEM        0x200000   /* Container shared memory */
#define FEATURE_LARGE_PAGE_DLLS   0x800000   /* Large page DLL support */

/* ================================================================
 * LibOS Memory Layout
 *
 * From strace reverse engineering of the NTUM boot sequence.
 * The NTUM expects these memory regions before boot.
 *
 * Valid LibOS address range: 0x10000 .. 0x400000000000
 * (Validated by IsValidLibOSAddress() in the NTUM)
 * ================================================================ */

#define LIBOS_VM_START           0x10000ULL
#define LIBOS_VM_END             0x400000000000ULL

#define LIBOS_CONTROL_PAGE       0x100000000ULL    /* 4KB control (PEB-like) */
#define LIBOS_IMAGE_BASE         0x200000000ULL    /* PE images mapped here */
#define LIBOS_KERNEL_HEAP        0x300000000ULL    /* 1GB kernel heap */
#define LIBOS_KERNEL_HEAP_SZ     0x40000000ULL     /* 1GB */
#define LIBOS_THREAD_ENV         0x300000000000ULL /* Thread environment blocks */
#define LIBOS_THREAD_ENV_SZ      0x500000ULL       /* ~5MB */
#define LIBOS_HIGH_CONTROL       0x400000000000ULL /* High control page */
#define LIBOS_APP_HEAP           0x500000000ULL    /* 1GB app heap */
#define LIBOS_APP_HEAP_SZ        0x40000000ULL     /* 1GB */
#define LIBOS_CONTROL_600        0x600000000ULL    /* Control */
#define LIBOS_CONTROL_700        0x700000000ULL    /* Control */
#define LIBOS_CONFIG             0x800000000ULL    /* 64KB config/registry */
#define LIBOS_ADDITIONAL         0x900000000ULL    /* 64KB additional */

/* PE image range (sqlpal.dll at preferred base) */
#define PE_IMAGE_START           0x180000000ULL
#define PE_IMAGE_END             0x181010000ULL    /* SizeOfImage + extra */

/* Heap ranges for fault handling */
#define KERNEL_HEAP_START        0x300000000ULL
#define KERNEL_HEAP_END          0x340000000ULL
#define APP_HEAP_START           0x500000000ULL
#define APP_HEAP_END             0x540000000ULL

/* ================================================================
 * PAL ABI Entry
 *
 * Each entry in the HostAbiTable is 0x20 bytes.
 * The NTUM reads HostAbiTable[1] (offset 8) to get the ABI dispatcher.
 * Discovered from decompiled call site at RVA 0x213e75:
 *   mov rax, [rbx+8]  ; RBX = HostAbiTable
 *   call [guard_dispatch_icall]  ; CFG dispatch -> jmp *rax
 * ================================================================ */

typedef struct {
    uint64_t version;           /* ABI version */
    void    *function_ptr;      /* Function pointer */
    uint64_t reserved[2];       /* Padding to 0x20 bytes */
} pal_abi_entry_t;

/* ABI table header layout:
 *   +0x00: Size=0x10, SubSize=0x38
 *   +0x08: ABI dispatcher function pointer
 *   +0x30: 0xFFFFFFFFFFFFFFFF (sentinel)
 *
 * From DAT_00369ec8 (HostAbiTable template)
 */
#define PAL_TABLE_SIZE_FIELD     0x10
#define PAL_TABLE_SUBSIZE_FIELD  0x38
#define PAL_TABLE_SENTINEL       0xFFFFFFFFFFFFFFFFULL

/* ================================================================
 * WINDOWS_LIBOS_PARAMETERS (0x190 = 400 bytes)
 *
 * Reverse-engineered from sqlservr at FUN_0020ba60.
 * The NTUM entry point receives a pointer to this structure.
 *
 * Key initialization sequence from decompiled code:
 *   *param_1       = 0x90      (Size)
 *   *(param_1 + 1) = 0x38      (SubHeaderSize)
 *   param_1[2]     = param_5   (HostAbiTable)
 *   param_1[3]     = param_6   (RuntimeCallbackState)
 *   param_1[4]     = param_7   (StackReservation)
 *   param_1[7]     = param_3   (ImageBase)
 *   param_1[8]     = param_4   (ImageLength)
 * ================================================================ */

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
    /* 0x090: ABI dispatch sub-structure (31 entries x varies) */
    uint8_t  AbiDispatch[0xE0];       /* 0x090 */
    void    *BootEntryPoint;          /* 0x170: StartModule function */
    uint8_t  _remaining[0x18];        /* 0x178-0x18F */
} WINDOWS_LIBOS_PARAMETERS;
#pragma pack(pop)

/* ================================================================
 * SFP Archive Format
 *
 * SFP (SQL Server Fusion Package) is the archive format used to
 * bundle DLLs, registry hives, and other files for the NTUM.
 *
 * system.sfp (13MB) contains:
 *   sqlpal.dll (2.7MB)  - NTUM kernel (1407 exports)
 *   DkDll.dll (35KB)    - PAL bridge (10 exports)
 *   AppLoader.exe (112KB) - PE app loader
 *   vcruntime140.dll, msvcp140.dll - MSVC runtime
 *   windows.hiv          - Registry hive
 *   Afd.sys, ndis.sys    - Network drivers
 * ================================================================ */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;               /* "SFP\0" = 0x00504653 */
    uint32_t version;             /* 1 */
    uint64_t entry_count;
    uint64_t first_dir_offset;
    uint64_t name_table_offset;
    uint64_t data_offset;
    uint64_t archive_size;
    uint64_t package_label_offset;
    uint64_t reserved;
    uint8_t  padding[32];         /* Total header: 96 bytes */
} sfp_header_t;

#define SFP_MAGIC    0x00504653   /* "SFP\0" */
#define SFP_DIR_MAGIC 0x00524944  /* "DIR\0" */

typedef struct {
    uint32_t magic;               /* "DIR\0" = 0x00524944 */
    uint64_t name_offset;
    uint32_t reserved1;
    uint64_t parent_offset;
    uint32_t is_dir;
    uint64_t file_length;
    uint64_t modified_time;
    uint64_t created_time;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t start_offset;        /* For dirs: first child entry offset
                                     For files: data offset in archive */
    uint32_t data_length;         /* For dirs: children size (N * 80)
                                     For files: same as file_length */
} sfp_dir_entry_t;
#pragma pack(pop)

/* Loaded SFP archive state */
typedef struct {
    int fd;                       /* File descriptor */
    sfp_header_t header;
    uint8_t *name_table;          /* Loaded name table */
    size_t name_table_size;
    char label[256];              /* Package label */
} sfp_archive_t;

/* sizeof(sfp_dir_entry_t) should be 80 bytes */
#define SFP_DIR_ENTRY_SIZE 80

/* ================================================================
 * PE Section Info (for demand-paging)
 *
 * Extracted from PE headers during load.  Used by the signal
 * handler to copy section data into faulted pages.
 * ================================================================ */

typedef struct {
    uint32_t virtual_address;     /* Section RVA */
    uint32_t virtual_size;        /* Virtual size */
    uint32_t raw_offset;          /* PointerToRawData in file */
    uint32_t raw_size;            /* SizeOfRawData */
} pe_section_info_t;

#define MAX_PE_SECTIONS 16

/* ================================================================
 * NTUM Kernel Structures (clean typed access)
 *
 * These are the KTHREAD/scheduler/TEB layouts the PE expects.
 * Fields are documented with their discovery source (RVA / function).
 * ================================================================ */

#define THREAD_BLOCK_SIZE         0xAA0
#define KTHREAD_BLOCK_SIZE        0x4200   /* full KTHREAD w/ +0x40b0 thread_local ref */
#define SCHED_BLOCK_SIZE          0x1000
#define THREAD_LOCAL_BLOCK_SIZE   0x5000
#define STACK_DESC_SIZE           0x100
#define POOL_OBJ_SIZE             0x1000

/* NTUM KTHREAD - Windows-style kernel thread block.
 * Layout from decompiled FUN_00020f03c and PE accesses at various RVAs. */
typedef struct ntum_kthread {
    uint8_t   _pre[0x20];                      /* 0x000: headers / locks */
    struct { uint64_t flink, blink; } list1;   /* 0x020: self-referencing list */
    uint64_t  ref_count;                       /* 0x030: initially 1 */
    uint8_t   _pad1[0x08];                     /* 0x038 */
    void     *teb;                             /* 0x040: -> ntum_teb */
    uint8_t   _pad2[0x18];                     /* 0x048 */
    struct { uint64_t flink, blink; } list2;   /* 0x060: self-referencing list */
    void     *sched_block;                     /* 0x070: -> ntum_sched_block */
    uint8_t   _pad3[0x4038];                   /* 0x078-0x40AF */
    void     *thread_local_alt;                /* 0x40B0: alt thread-local ptr */
    uint8_t   _pad4[0x108];                    /* 0x40B8-0x41BF */
    void     *thread_local;                    /* 0x41C0: -> thread_local_block */
    uint8_t   _tail[0x38];                     /* 0x41C8-0x41FF */
} ntum_kthread_t;

/* NTUM Scheduler Block (linked from KTHREAD+0x70).
 * The PE's FUN_00276b68 reads [+0x948] (affinity mask) and [+0x950] (CPU id). */
typedef struct ntum_sched_block {
    uint8_t   _pre[0xF0];                      /* 0x000: schedulable fields */
    uint8_t   sched_info[0x858];               /* 0x0F0: scheduler substructure */
    uint64_t  affinity_mask;                   /* 0x948: CPU bitmap (popcount input) */
    uint16_t  preferred_cpu;                   /* 0x950: preferred CPU id */
    uint8_t   _tail[0x6AE];                    /* 0x952-0x0FFF */
} ntum_sched_block_t;

/* Stack descriptor - referenced from TEB[0x1478] and pool allocations.
 * Field at +0x30 must be a valid stack top pointer. */
typedef struct ntum_stack_desc {
    uint8_t   _pre[0x30];                      /* 0x00: header */
    uint64_t  stack_top;                       /* 0x30: top of stack (required) */
    uint8_t   _mid[0x58];                      /* 0x38-0x8F */
    uint64_t  stack_handler;                   /* 0x90: 0x18021ff10 (guard_check) */
    uint8_t   _tail[0x68];                     /* 0x98-0xFF */
} ntum_stack_desc_t;

/* Pool allocator object (at [0x1806456e8]).
 * Fields discovered from PE vtable dispatches. */
typedef struct ntum_pool_obj {
    void     *vtable;                          /* 0x000: vtable ptr (2KB of func ptrs) */
    uint8_t   _pad1[0x38];                     /* 0x008-0x03F */
    void     *sub_allocator;                   /* 0x040: sub-allocator object */
    uint8_t   _pad2[0x210];                    /* 0x048-0x257 */
    uint32_t  flags;                           /* 0x258: flags */
    uint8_t   _tail[0xDA4];                    /* 0x25C-0xFFF */
} ntum_pool_obj_t;

/* Kernel Object Type Registry at PE .data 0x1806472c0.
 * PE FUN_0x2bcf9c sets [0x180648c00] = &type_registry.
 * Reader FUN_0x31a58c dispatches based on exec_ctx[+4]:
 *   case 1: (size, dispatch) from [+0x10, +0x18]
 *   case 2: (size, dispatch) from [+0x28, +0x30] */
typedef struct ntum_type_registry {
    uint8_t   _pre[0x10];                      /* 0x00: header */
    uint16_t  size1;                           /* 0x10: size for case 1 */
    uint8_t   _pad1[0x06];                     /* 0x12 */
    void     *dispatch1;                       /* 0x18: dispatch table for case 1 */
    uint8_t   _pad2[0x08];                     /* 0x20 */
    uint16_t  size2;                           /* 0x28: size for case 2 */
    uint8_t   _pad3[0x06];                     /* 0x2A */
    void     *dispatch2;                       /* 0x30: dispatch table for case 2 */
    uint8_t   _tail[0x10];                     /* 0x38-0x47 (registry itself ends ~here) */
    /* NOTE: actual type entries live at a SEPARATE .data address
     * (0x180648c48), not inside this struct. They are 64 entries of
     * 0x58 bytes initialized by FUN_0x31a348 in a loop. */
} ntum_type_registry_t;

/* KUSER_SHARED_DATA at 0x7ffe0000 (Windows-standard).
 * sqlpal.dll has code at PE RVA 0x211650 that VirtualAllocates this page.
 * Many PE init functions read specific fields before that runs. */
typedef struct kuser_shared_data {
    uint32_t TickCountLowDeprecated;           /* 0x00 */
    uint32_t TickCountMultiplier;              /* 0x04: e.g. 0x0fa00000 */
    uint64_t InterruptTime;                    /* 0x08: 100ns units (read at 0x276bd5) */
    uint32_t _pad0;                            /* 0x10 */
    uint64_t SystemTime;                       /* 0x14: 100ns since 1601 (read at 0x257b27) */
    uint32_t _pad1;                            /* 0x1C */
    uint64_t TimeZoneBias;                     /* 0x20 (read at 0x26c655) */
    uint8_t  _rest[0x1000 - 0x28];
} kuser_shared_data_t;

#define KUSER_SHARED_DATA_ADDR    0x7ffe0000ULL

/* NTUM .data kernel globals */
#define NTUM_TYPE_REGISTRY_ADDR   0x1806472c0ULL   /* static type_registry */
#define NTUM_TYPE_GLOBAL_ADDR     0x180648c00ULL   /* → type_registry ptr */
#define NTUM_TYPE_GLOBAL2_ADDR    0x1806475d0ULL   /* → alt type_registry ptr */
#define NTUM_POOL_OBJ_ADDR        0x1806456e8ULL   /* → pool_obj */
#define NTUM_GLOBAL_TEB_ADDR      0x1806092c0ULL   /* → TEB */
#define NTUM_STACK_DESC_ADDR      0x18063b218ULL   /* → stack_desc */

/* ================================================================
 * Thread Environment Block (TEB) - Windows-style, gs:0x30 points here.
 *
 * The NTUM reads gs:0x30 to get the TEB self-pointer. It then follows
 * TEB[0x1838] -> KTHREAD to get scheduler state.
 * ================================================================ */

#define TEB_STACK_BASE_OFFSET   0x08
#define TEB_STACK_LIMIT_OFFSET  0x10
#define TEB_SELF_OFFSET         0x30
#define TEB_THREAD_STATE_OFFSET 0x58

typedef struct ntum_teb {
    uint8_t   _pre0[0x08];                     /* 0x000: ExceptionList (32-bit), Nt_Tib */
    uint64_t  StackBase;                       /* 0x008: top of stack */
    uint64_t  StackLimit;                      /* 0x010: bottom of stack */
    uint8_t   _pre1[0x18];                     /* 0x018 */
    struct ntum_teb *Self;                     /* 0x030: self-pointer (gs:0x30) */
    uint8_t   _pre2[0x20];                     /* 0x038 */
    uint64_t  ThreadState;                     /* 0x058: often self-ref */
    uint8_t   _pad[0x1418];                    /* 0x060-0x1477 */
    void     *StackDesc;                       /* 0x1478: -> ntum_stack_desc */
    uint8_t   _gap[0x3B8];                     /* 0x1480-0x1837 */
    /* Windows TEB has KThread pointer at 0x1838 in Drawbridge extension */
    void     *KThread;                         /* 0x1838: -> ntum_kthread */
    uint8_t   _after_kt[0x28];                 /* 0x1840-0x1867 */
    void     *PalObject;                       /* 0x1868: PAL object handle */
    uint8_t   _tail[0xE790];                   /* 0x1870-0xFFFF */
} ntum_teb_t;

/* NTUM stack addresses (from entry point disassembly):
 *   lea rsp, [rip+0x296b29] -> 0x180637000
 *   add rsp, [rip+0x72fa2]  -> +0x4000 = 0x18063b000
 */
#define NTUM_STACK_BASE         0x180637000ULL
#define NTUM_STACK_TOP          0x18063b000ULL
#define NTUM_STACK_SIZE         0x4000

/* ================================================================
 * NTUM .data Global Addresses
 *
 * These are the ONLY addresses we write to in the PE image:
 *   [0x18063f8c0] = boot ready flag (1 = PAL ready)
 *   [0x18063f8c8] = PAL dispatcher function pointer
 *   [0x180c00008] = params/config pointer
 *   [0x180c00010] = params->Size
 *   [0x180c00820] = ParameterBuffer pointer
 *
 * We do NOT touch:
 *   .00cfg section (has built-in guard_check=ret, guard_dispatch=jmp *rax)
 *   .text section (no int3 patches, no fastfail patches)
 * ================================================================ */

#define NTUM_BOOT_FLAG_ADDR       0x18063f8c0ULL
#define NTUM_ABI_DISPATCHER_ADDR  0x18063f8c8ULL
#define NTUM_PARAMS_ADDR          0x180c00008ULL
#define NTUM_PARAMS_SIZE_ADDR     0x180c00010ULL
#define NTUM_PARAM_BUF_ADDR       0x180c00820ULL

/* .data section range (protected from demand-paging overwrite) */
#define NTUM_DATA_START           0x180600000ULL
#define NTUM_DATA_END             0x180670000ULL

/* .roafter section range (protected from demand-paging overwrite) */
#define NTUM_ROAFTER_START        0x180c00000ULL
#define NTUM_ROAFTER_END          0x180c02000ULL

/* .00cfg section (PE's built-in CFG functions - NOT our code) */
#define NTUM_CFG_SECTION          0x180a00000ULL
#define NTUM_GUARD_CHECK_ADDR     0x180a00000ULL  /* -> 0x18021ff10 (ret) */
#define NTUM_GUARD_DISPATCH_ADDR  0x180a00008ULL  /* -> 0x1803a86f0 (jmp *rax) */

/* Expected guard function addresses (PE's own implementations) */
#define NTUM_GUARD_CHECK_RVA      0x18021ff10ULL
#define NTUM_GUARD_DISPATCH_RVA   0x1803a86f0ULL

/* Security cookie location in .data */
#define NTUM_COOKIE_ADDR          0x180600000ULL
#define NTUM_COOKIE_INV_ADDR      0x180600008ULL
#define NTUM_COOKIE_DEFAULT       0x2b992ddfa232ULL

/* sqlpal.dll entry point RVA and related addresses */
#define NTUM_ENTRY_RVA            0x3A04D0
#define NTUM_STACK_ADJ_ADDR       0x180413480ULL  /* .rdata: stack adjust = 0x4000 */
#define NTUM_INIT_WRAPPER_ADDR    0x180204ad0ULL  /* jmp target from entry */
#define NTUM_COOKIE_INIT_ADDR     0x180204704ULL  /* Cookie init function */

/* ================================================================
 * ABI Dispatch Protocol
 *
 * The NTUM calls the ABI dispatcher through [0x180a00008]:
 *   rcx = HostAbiTable pointer
 *   rdx = ABI call type ID (e.g., 0x7002002 = GetFunction_v2)
 *   r8  = data size
 *   r9  = input buffer pointer
 *   [rsp+0x28] = output size (5th Win64 stack arg)
 *   [rsp+0x30] = output buffer pointer (6th Win64 stack arg)
 *
 * For GetFunction_v2 (0x7002002):
 *   input[0] = uint32_t function_id (e.g., 0x1001000)
 *   input[1] = uint32_t version_info
 *   output = function pointer via double-deref
 *
 * Function ID format: 0xCCFFF000
 *   CC  = category (01=Stream, 02=Memory, 04=Thread, ...)
 *   FFF = function number within category
 * ================================================================ */

#define ABI_GET_FUNCTION_V2  0x7002002
#define ABI_GET_VERSION_V2   0x7002001

/* ABI function ID categories */
#define ABI_CAT_STREAM       0x01
#define ABI_CAT_MEMORY       0x02
#define ABI_CAT_THREAD       0x04
#define ABI_CAT_SYNC         0x05
#define ABI_CAT_CONSOLE      0x06
#define ABI_CAT_ABI          0x07
#define ABI_CAT_SYSTEM       0x08
#define ABI_CAT_PROCESS      0x09
#define ABI_CAT_EXCEPTION    0x0A
#define ABI_CAT_OBJECT       0x0B
#define ABI_CAT_CACHE        0x0C
#define ABI_CAT_ENCLAVE      0x0D
#define ABI_CAT_EXTENDED     0x0E
#define ABI_CAT_STREAM_EXT   0x0F
#define ABI_CAT_ASYNC        0x10
#define ABI_CAT_STREAM_V2    0x11
#define ABI_CAT_MEMORY_V2    0x12
#define ABI_CAT_RANDOM       0x13

/* ================================================================
 * Boot Thread Configuration
 * ================================================================ */

#define BOOT_STACK_SIZE       (2 * 1024 * 1024)   /* 2MB */
#define BOOT_STACK_ADDR       0x300100000ULL       /* In kernel heap */

/* Boot structures allocation in LibOS kernel heap */
#define BOOT_STRUCTS_SIZE     0x20000
#define BOOT_STRUCTS_ADDR     (LIBOS_KERNEL_HEAP + 0x20000000ULL) /* +512MB = 0x320000000 */

/* Thread args passed to the boot thread function */
typedef struct {
    void *entry_point;
    void *stack_top;
    WINDOWS_LIBOS_PARAMETERS *params;
} boot_thread_args_t;

/* ================================================================
 * Windows Memory Protection Constants
 *
 * Used by DK_VirtualMemoryAllocate/Protect to translate
 * Windows PAGE_* constants to Linux PROT_* flags.
 * ================================================================ */

#define WIN_PAGE_NOACCESS          0x01
#define WIN_PAGE_READONLY          0x02
#define WIN_PAGE_READWRITE         0x04
#define WIN_PAGE_EXECUTE           0x10
#define WIN_PAGE_EXECUTE_READ      0x20
#define WIN_PAGE_EXECUTE_READWRITE 0x40

#define WIN_MEM_COMMIT             0x1000
#define WIN_MEM_RESERVE            0x2000
#define WIN_MEM_RELEASE            0x8000

/* ================================================================
 * DK Function Table Entry (for AbiGetFunction lookups)
 * ================================================================ */

typedef struct {
    uint64_t id;
    void *func;
    const char *name;
} dk_func_entry_t;

/* ================================================================
 * PE64 Format Structures
 *
 * Standard Portable Executable structures for loading Windows
 * PE64 binaries on Linux. These match the Microsoft PE/COFF
 * specification exactly.
 * ================================================================ */

#define PE_DOS_MAGIC      0x5A4D      /* "MZ" */
#define PE_SIGNATURE      0x00004550  /* "PE\0\0" */
#define PE_OPT_MAGIC_64   0x020B      /* PE32+ (64-bit) */

/* IMAGE_FILE_HEADER.Machine */
#define PE_MACHINE_AMD64  0x8664

/* IMAGE_SECTION_HEADER.Characteristics */
#define PE_SCN_CNT_CODE            0x00000020
#define PE_SCN_CNT_INITIALIZED     0x00000040
#define PE_SCN_CNT_UNINITIALIZED   0x00000080
#define PE_SCN_MEM_EXECUTE         0x20000000
#define PE_SCN_MEM_READ            0x40000000
#define PE_SCN_MEM_WRITE           0x80000000

/* IMAGE_DATA_DIRECTORY indices */
#define PE_DIR_EXPORT      0
#define PE_DIR_IMPORT      1
#define PE_DIR_RESOURCE    2
#define PE_DIR_EXCEPTION   3
#define PE_DIR_BASERELOC   5
#define PE_DIR_TLS         9
#define PE_DIR_IAT        12

/* Base relocation types */
#define PE_REL_BASED_ABSOLUTE   0
#define PE_REL_BASED_DIR64     10

#pragma pack(push, 1)

/* DOS Header (first 64 bytes of any PE file) */
typedef struct {
    uint16_t e_magic;          /* "MZ" = 0x5A4D */
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
    uint32_t e_lfanew;         /* Offset to PE signature */
} pe_dos_header_t;

/* COFF File Header (20 bytes) */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_file_header_t;

/* Data Directory entry */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} pe_data_directory_t;

/* PE32+ Optional Header (64-bit) */
typedef struct {
    uint16_t Magic;                    /* 0x020B for PE32+ */
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
    pe_data_directory_t DataDirectory[16];
} pe_optional_header_64_t;

/* Section Header (40 bytes each) */
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
} pe_section_header_t;

/* Import Directory entry */
typedef struct {
    uint32_t OriginalFirstThunk;   /* RVA to INT (Import Name Table) */
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                 /* RVA to DLL name string */
    uint32_t FirstThunk;           /* RVA to IAT (Import Address Table) */
} pe_import_descriptor_t;

/* Import By Name (pointed to by INT/IAT entries) */
typedef struct {
    uint16_t Hint;
    char     Name[1];              /* Variable-length null-terminated */
} pe_import_by_name_t;

/* Base Relocation Block */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    /* Followed by variable number of uint16_t entries */
} pe_base_relocation_t;

/* Export Directory */
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
} pe_export_directory_t;

#pragma pack(pop)

/* ================================================================
 * Loaded PE Image State
 * ================================================================ */

#define PE_MAX_IMPORTS 32

typedef struct {
    void    *base;                     /* Mapped image base address */
    uint64_t image_size;               /* SizeOfImage */
    void    *entry_point;              /* AddressOfEntryPoint (absolute) */
    uint64_t preferred_base;           /* ImageBase from optional header */
    int      relocated;                /* 1 if base relocations applied */
    pe_section_header_t *sections;     /* Section headers (in mapped image) */
    int      num_sections;
} loaded_pe_t;

/* ================================================================
 * Win32 Shim DLL Registration
 * ================================================================ */

typedef struct {
    const char *name;                  /* Function name */
    void       *impl;                  /* Our implementation */
} win32_export_t;

typedef struct {
    const char       *dll_name;        /* e.g. "kernel32.dll" */
    const win32_export_t *exports;     /* Array of exports */
    int               num_exports;
} win32_shim_dll_t;

#endif /* DRAWBRIDGE_TYPES_H */
