/*
 * pal_except.h — Component C9: Exception Dispatch
 *
 * Translation of ELF exception dispatch machinery from
 * analysis/sqlservr_FULL.c:
 *
 *   FUN_002897e0 @ 0x2897e0  (line 157267)  — Build exception record
 *                                              from guest-CPU context.
 *                                              (KiFillExceptionRecord)
 *   FUN_002899d0 @ 0x2899d0  (line 157386)  — KiDispatchException:
 *                                              classify signal, allocate
 *                                              dk_exception_record_t,
 *                                              fill it, rewrite ucontext
 *                                              RIP to KiUserException-
 *                                              Dispatcher (stored at
 *                                              RuntimeCallbackState+0x10,
 *                                              DAT_003b2148).
 *   FUN_00252b10 @ 0x252b10  (line 123269)  — alloc_exception_record:
 *                                              calloc(1,0x280); copies
 *                                              caller's exception_info_t.
 *   FUN_00253f80 @ 0x253f80  (line 124308)  — DK_ExceptionRecordFree:
 *                                              host-side free; decrements
 *                                              TEB exception counter,
 *                                              validates addr via
 *                                              FUN_002801d0 (LibOS range)
 *                                              then free()s.
 *   FUN_0028a410 @ 0x28a410  (line 157774)  — SIGFPE code -> NTSTATUS.
 *   FUN_002801d0 @ 0x2801d0  (line 152617)  — LibOS address validator.
 *
 * Also referenced in the decompiled handler:
 *   FUN_00254f80 — per-thread in-signal guard bit
 *   FUN_0027aab0 — abort/terminate dispatcher for unhandled signals
 *   FUN_0028e0d0/0x28e530 — error_info helpers (status < 0 on failure)
 *
 * Windows x64 layouts (Microsoft "pshpack4.h"):
 *   CONTEXT       (sizeof == 0x4d0) — not used on the record path; the
 *                  ELF builds its own 0x280-byte "dk_exception_record_t"
 *                  that is a *compressed* CONTEXT (GPR+FPU/XMM only, in
 *                  NT GPR order). The KiUserExceptionDispatcher reads
 *                  this compressed form from RCX.
 *   EXCEPTION_RECORD (sizeof == 0x98) — standard NT record; embedded
 *                  at rec+0x28..0xa0 (local_58/uStack_50/local_48/...
 *                  in FUN_002899d0).
 *
 * Both layouts are declared here for completeness with _Static_assert on
 * critical offsets so a compiler drift is loud.
 */

#ifndef PAL_EXCEPT_H
#define PAL_EXCEPT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Windows x64 CONTEXT (kept for reference — full 0x4d0 layout).
 * Only the offsets needed for the dispatcher path are validated.
 * ELF src: native/GuestCpu.cpp (FUN_002897e0 reads guest CPU at
 *          param_1+0x28..0xe8 and writes a *compressed* form).
 * ============================================================ */
typedef struct _NT_M128A {
    uint64_t Low;
    int64_t  High;
} NT_M128A;

typedef struct _NT_XMM_SAVE_AREA32 {
    uint16_t ControlWord;       /* 0x000 */
    uint16_t StatusWord;        /* 0x002 */
    uint8_t  TagWord;           /* 0x004 */
    uint8_t  Reserved1;         /* 0x005 */
    uint16_t ErrorOpcode;       /* 0x006 */
    uint32_t ErrorOffset;       /* 0x008 */
    uint16_t ErrorSelector;     /* 0x00c */
    uint16_t Reserved2;         /* 0x00e */
    uint32_t DataOffset;        /* 0x010 */
    uint16_t DataSelector;      /* 0x014 */
    uint16_t Reserved3;         /* 0x016 */
    uint32_t MxCsr;             /* 0x018 */
    uint32_t MxCsr_Mask;        /* 0x01c */
    NT_M128A FloatRegisters[8]; /* 0x020 */
    NT_M128A XmmRegisters[16];  /* 0x0a0 */
    uint8_t  Reserved4[96];     /* 0x1a0 */
} NT_XMM_SAVE_AREA32;            /* sizeof 0x200 */

typedef struct _NT_CONTEXT {
    uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home; /* 0x000 */
    uint32_t ContextFlags;                                    /* 0x030 */
    uint32_t MxCsr;                                           /* 0x034 */
    uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;        /* 0x038 */
    uint32_t EFlags;                                          /* 0x044 */
    uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;                    /* 0x048 */
    uint64_t Rax;  /* 0x078 */
    uint64_t Rcx;  /* 0x080 */
    uint64_t Rdx;  /* 0x088 */
    uint64_t Rbx;  /* 0x090 */
    uint64_t Rsp;  /* 0x098 */
    uint64_t Rbp;  /* 0x0a0 */
    uint64_t Rsi;  /* 0x0a8 */
    uint64_t Rdi;  /* 0x0b0 */
    uint64_t R8,R9,R10,R11,R12,R13,R14,R15;                   /* 0x0b8 */
    uint64_t Rip;                                             /* 0x0f8 */
    NT_XMM_SAVE_AREA32 FltSave;                               /* 0x100 */
    NT_M128A VectorRegister[26];                              /* 0x300 */
    uint64_t VectorControl;                                   /* 0x4a0 */
    uint64_t DebugControl;                                    /* 0x4a8 */
    uint64_t LastBranchToRip;                                 /* 0x4b0 */
    uint64_t LastBranchFromRip;                               /* 0x4b8 */
    uint64_t LastExceptionToRip;                              /* 0x4c0 */
    uint64_t LastExceptionFromRip;                            /* 0x4c8 */
} NT_CONTEXT;

_Static_assert(offsetof(NT_CONTEXT, ContextFlags) == 0x030, "ContextFlags");
_Static_assert(offsetof(NT_CONTEXT, EFlags)       == 0x044, "EFlags");
_Static_assert(offsetof(NT_CONTEXT, Rax)          == 0x078, "Rax");
_Static_assert(offsetof(NT_CONTEXT, Rip)          == 0x0f8, "Rip");
_Static_assert(offsetof(NT_CONTEXT, FltSave)      == 0x100, "FltSave");
_Static_assert(sizeof(NT_CONTEXT)                 == 0x4d0, "CONTEXT size");

/* ============================================================
 * Windows x64 EXCEPTION_RECORD (Microsoft SDK "winnt.h").
 * Used by NT exception handlers. In FUN_002899d0 the fields
 * occupy local_58/uStack_54/uStack_50/local_48/local_38/local_28
 * (C++ ISO layout maps to same offsets).
 * ============================================================ */
#define NT_EXCEPTION_MAXIMUM_PARAMETERS 15

typedef struct _NT_EXCEPTION_RECORD NT_EXCEPTION_RECORD;
struct _NT_EXCEPTION_RECORD {
    uint32_t            ExceptionCode;        /* 0x00 NTSTATUS */
    uint32_t            ExceptionFlags;       /* 0x04 */
    NT_EXCEPTION_RECORD *ExceptionRecord;     /* 0x08 nested */
    void               *ExceptionAddress;     /* 0x10 faulting RIP */
    uint32_t            NumberParameters;     /* 0x18 */
    uint32_t            _pad;                 /* 0x1c */
    uint64_t            ExceptionInformation[NT_EXCEPTION_MAXIMUM_PARAMETERS]; /* 0x20 */
};
_Static_assert(offsetof(NT_EXCEPTION_RECORD, ExceptionAddress) == 0x10, "ExceptionAddress");
_Static_assert(offsetof(NT_EXCEPTION_RECORD, NumberParameters) == 0x18, "NumberParameters");
_Static_assert(offsetof(NT_EXCEPTION_RECORD, ExceptionInformation) == 0x20, "ExceptionInformation");
_Static_assert(sizeof(NT_EXCEPTION_RECORD) == 0x98, "EXCEPTION_RECORD size");

/* ============================================================
 * dk_exception_record_t — the 0x280-byte compressed-CONTEXT
 * record that the NTUM's KiUserExceptionDispatcher expects in
 * RCX. Written by FUN_002897e0 at ELF line 157267ff.
 * Field order is derived from the ELF: (byte offset, source
 * field in guest-CPU context param_1):
 *   0x00: EFL               (param_1+0xb0, u32)
 *   0x04: CS low            (param_1+0xb8, u16)
 *   0x06: 0
 *   0x0a: CS >> 32          (u16)
 *   0x0c: 0x2b              (selector, u16)
 *   0x10: RAX               (+0x90)
 *   0x18: RBX               (+0x80)
 *   0x20: RCX               (+0x98)
 *   0x28: RDX               (+0x88)
 *   0x30: RSI               (+0xa0)
 *   0x38: R8,R9             (+0x70 [16])
 *   0x48: RDI               (+0x68)
 *   0x50: RBP               (+0x28, swapped hi/lo; here mirrored)
 *   0x58: RSP               (+0x30)
 *   0x60: R10               (+0x38)
 *   0x68: R11               (+0x40)
 *   0x70: R12               (+0x48)
 *   0x78: R13               (+0x50)
 *   0x80: R14               (+0x58)
 *   0x88: R15               (+0x60)
 *   0x90: RIP               (+0xa8)
 *   0xa0: FPU/XMM (0x1a0 bytes, from fpregs at param_1+0xe0
 *         when non-NULL; zeroed otherwise per GuestCpu.cpp:0xc4)
 *   0x240: reserved pad to 0x280
 * ============================================================ */
typedef struct __attribute__((packed)) {
    uint32_t error_code;            /* 0x000 u32 EFL from guest ctx +0xb0 */
    uint16_t cs_low;                /* 0x004 CS (low 16 of guest +0xb8)   */
    uint32_t zero_06;               /* 0x006 cleared by FUN_002897e0      */
    uint16_t cs_high;               /* 0x00a (guest +0xb8 >> 32) u16      */
    uint16_t selector_0x2b;         /* 0x00c constant 0x2b                */
    uint16_t _pad_0e;               /* 0x00e                              */
    uint64_t rax;                   /* 0x010 */
    uint64_t rbx;                   /* 0x018 */
    uint64_t rcx;                   /* 0x020 */
    uint64_t rdx;                   /* 0x028 */
    uint64_t rsi;                   /* 0x030 */
    uint64_t r8;                    /* 0x038 */
    uint64_t r9;                    /* 0x040 */
    uint64_t rdi;                   /* 0x048 */
    uint64_t rbp;                   /* 0x050 */
    uint64_t rsp;                   /* 0x058 */
    uint64_t r10;                   /* 0x060 */
    uint64_t r11;                   /* 0x068 */
    uint64_t r12;                   /* 0x070 */
    uint64_t r13;                   /* 0x078 */
    uint64_t r14;                   /* 0x080 */
    uint64_t r15;                   /* 0x088 */
    uint64_t rip;                   /* 0x090 */
    uint8_t  _pad_98[8];            /* 0x098 */
    uint8_t  fpu_state[0x1a0];      /* 0x0a0 */
    uint8_t  _reserved[0x40];       /* 0x240 */
} dk_exception_record_t;

_Static_assert(offsetof(dk_exception_record_t, rax) == 0x010, "rax off");
_Static_assert(offsetof(dk_exception_record_t, rip) == 0x090, "rip off");
_Static_assert(offsetof(dk_exception_record_t, fpu_state) == 0x0a0, "fpu off");
_Static_assert(sizeof(dk_exception_record_t) == 0x280, "record size");

/* ============================================================
 * Public API
 * ============================================================ */

/* Publish the PE raw image data so the exception path can copy
 * section bytes to newly-mapped pages during demand-paging.
 * Wire-compatible with the old ntum_signal_set_pe_data(). */
void pal_exception_set_pe_data(void *raw, size_t size, uint64_t image_base);

/* Demand-page a host-side fault in the LibOS address space.
 * Returns 1 if the page was mapped and the signal should be
 * returned from; 0 if this fault is not demand-pageable. */
int pal_exception_demand_page(void *fault_addr, void *ucontext_ptr);

/* Core entry: build a dk_exception_record_t from the Linux
 * ucontext, rewrite RIP/RCX/RDX to hand control to the NTUM's
 * KiUserExceptionDispatcher (RuntimeCallbackState+0x10).
 *
 * Returns:
 *    1  — exception forwarded; signal handler must return.
 *    0  — dispatcher not yet installed (early boot); caller
 *         should take its SIGTRAP/SIGSEGV fallback path.
 *
 * Mirrors LAB_0028a269 of FUN_002899d0 (ELF line 157737).
 */
int pal_exception_forward(int signo,
                          void *siginfo_ptr,
                          void *ucontext_ptr);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* PAL_EXCEPT_H */
