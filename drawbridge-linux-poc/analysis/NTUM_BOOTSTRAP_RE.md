# NTUM Bootstrap - Full Reverse Engineering

## WINDOWS_LIBOS_PARAMETERS (0x190 = 400 bytes)

```c
struct WINDOWS_LIBOS_PARAMETERS {
    /* 0x000 */ uint64_t Size;                 // = 0x90
    /* 0x008 */ uint32_t SubHeaderSize;        // = 0x38
    /* 0x00C */ uint32_t _pad0;
    /* 0x010 */ void*    HostAbiTable;          // PAL function dispatch table
    /* 0x018 */ void*    RuntimeCallbackState;  // host callback state (BSS)
    /* 0x020 */ void*    StackReservation;      // stack size param (0x18)
    /* 0x028 */ uint16_t MajorVersion;
    /* 0x02A */ uint16_t MinorVersion;
    /* 0x02C */ uint32_t _pad1;
    /* 0x030 */ void*    HostExtensionEntryPoint;
    /* 0x038 */ void*    ImageBase;             // PE image base of sqlpal.dll
    /* 0x040 */ uint64_t ImageLength;           // PE image size
    /* 0x048 */ void*    ParameterBuffer;
    /* 0x050 */ uint64_t ParameterBufferSize;
    /* 0x058 */ uint8_t  HasEnclave;            // SGX flag
    /* 0x060 */ void*    ProcessorInfo;
    /* 0x068 */ uint32_t NumaNodeCount;
    /* 0x070 */ uint8_t  FeatureFlags[0x20];    // capability flags
    /* 0x090 */ // ABI dispatch sub-structure (31 entries × 0x20)
    /* 0x170 */ void*    BootEntryPoint;        // StartModule function ptr
};
```

## Boot Thread Trampoline (at 0x15a520)

```asm
push   %rbp
mov    %rsp,%rbp
mov    %rcx,%rax       ; save rcx
mov    %rdx,%rcx       ; rdx -> rcx (Windows param2)
mov    %rax,%rdx       ; old rcx -> rdx (Windows param3)
mov    $0x0,%rbp       ; zero frame pointer
mov    %rsi,%rsp       ; SET STACK TO LIBOS STACK
jmp    *%rdi           ; JUMP TO StartModule ENTRY POINT
```

This switches from Linux SysV ABI to Windows x64 and sets a fresh stack.

## Feature Flags (OR'd at offset 0x30)
- 0x40000  = base PAL (always)
- 0x800000 = large page DLLs
- 0x20000  = TLS support
- 0x200000 = container shared memory
- 0x80000  = additional I/O
- 0x100000 = io_uring (kernel >= 5.11)

## HostAbiTable Template (at 0x269ec8)
```
+0x00: Size=0x10, SubSize=0x38
+0x08: zeros
+0x30: 0xFFFFFFFFFFFFFFFF (sentinel)
```

## LibOS VM Range
- Start: 0x10000 (64KB)
- End:   0x400000000000 (4TB)
- Validated by IsValidLibOSAddress()
