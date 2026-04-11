# NTUM Exception Dispatch - Complete Reverse Engineering

## Overview

The NTUM (sqlpal.dll) uses Linux signals as a mechanism to implement Windows
Structured Exception Handling (SEH). When an exception occurs in NTUM code
(SIGSEGV, SIGTRAP, etc.), the ELF host's signal handler converts the Linux
signal context into a Windows EXCEPTION_RECORD, then redirects execution
to the NTUM's internal KiUserExceptionDispatcher.

This is the key mechanism that was blocking boot after 84 DK function
resolutions. The NTUM uses `int3` as an intentional callback mechanism,
not just for debug assertions.

## Signal Handler Flow (FUN_002899d0 @ sqlservr 0x2899d0)

```
Signal occurs in NTUM code
  ↓
Linux delivers signal to host signal handler
  ↓
Host reads ucontext (RIP, RSP, registers)
  ↓
Host validates addresses (IsValidLibOSAddress)
  ↓
Host checks thread state from FS_OFFSET
  ↓
Host builds exception info based on signal type
  ↓
Host allocates 0x280-byte exception record on heap
  ↓
Host fills record with CPU state (FUN_002897e0)
  ↓
Host rewrites RIP → KiUserExceptionDispatcher
  ↓
Host passes exception record ptr in RCX
  ↓
Signal handler returns → NTUM resumes at dispatcher
```

## Key Address: KiUserExceptionDispatcher

- Stored at: `DAT_003b2148` in the sqlservr ELF
- `DAT_003b2148 = DAT_003b2138 + 0x10`
- `DAT_003b2138` is passed as `RuntimeCallbackState` to FUN_0020ba60
- **In our host**: `g_runtime_callback_state + 0x10`
- The NTUM writes this address during its boot initialization
- It points to a function inside sqlpal.dll (PE address space)

### How to read it in our host:
```c
static uint8_t g_runtime_callback_state[256];
// After NTUM boot, the dispatcher address is at:
uint64_t ki_user_exception_dispatcher = *(uint64_t*)(g_runtime_callback_state + 0x10);
```

## ucontext_t Register Offsets (x86_64 Linux)

These map to `param_3` in the decompiled code:

| Offset | Register | ucontext field |
|--------|----------|----------------|
| 0x28 | R8 | gregs[REG_R8] |
| 0x30 | R9 | gregs[REG_R9] |
| 0x38 | R10 | gregs[REG_R10] |
| 0x40 | R11 | gregs[REG_R11] |
| 0x48 | R12 | gregs[REG_R12] |
| 0x50 | R13 | gregs[REG_R13] |
| 0x58 | R14 | gregs[REG_R14] |
| 0x60 | R15 | gregs[REG_R15] |
| 0x68 | RDI | gregs[REG_RDI] |
| 0x70 | RSI | gregs[REG_RSI] |
| 0x78 | RBP | gregs[REG_RBP] |
| 0x80 | RBX | gregs[REG_RBX] |
| 0x88 | RDX | gregs[REG_RDX] |
| 0x90 | RAX | gregs[REG_RAX] |
| 0x98 | RCX | gregs[REG_RCX] |
| 0xa0 | RSP | gregs[REG_RSP] |
| 0xa8 | RIP | gregs[REG_RIP] |
| 0xb0 | EFLAGS | gregs[REG_EFL] |
| 0xb8 | CS | gregs[REG_CSGSFS] |
| 0xc0 | ERR | gregs[REG_ERR] |
| 0xe0 | FPU ptr | uc_mcontext.fpregs |
| 200 (0xc8) | TRAPNO | gregs[REG_TRAPNO] |

## Exception Record (built by FUN_002897e0)

The exception record is 0x280 bytes (640 bytes), allocated by FUN_00252b10.
It's filled from the ucontext (param_1) into param_2:

```c
struct dk_exception_record {
    /* 0x000 */ uint32_t error_code;        // from ucontext.gregs[REG_EFL] (param_1+0xb0)
    /* 0x004 */ uint16_t cs_low;            // from CSGSFS low 16 bits (param_1+0xb8)
    /* 0x006 */ uint32_t zero;              // = 0
    /* 0x00a */ uint16_t cs_high;           // CSGSFS >> 32
    /* 0x00c */ uint16_t selector;          // = 0x2b (code segment selector)
    /* 0x010 */ uint64_t rax;               // param_1 + 0x90
    /* 0x018 */ uint64_t rbx;               // param_1 + 0x80
    /* 0x020 */ uint64_t rcx;               // param_1 + 0x98
    /* 0x028 */ uint64_t rdx;               // param_1 + 0x88
    /* 0x030 */ uint64_t rsi;               // param_1 + 0xa0
    /* 0x038-0x048 */ R8-R15;               // param_1 + 0x70 area (reordered)
    /* 0x048 */ uint64_t rdi;               // param_1 + 0x68
    /* 0x050-0x058 */ RBP, RSP;             // param_1 + 0x28, 0x30
    /* 0x060-0x070 */ R10-R13;              // param_1 + 0x38-0x50
    /* 0x080-0x090 */ R14, R15;             // param_1 + 0x58, 0x60
    /* 0x090 */ uint64_t rip;               // param_1 + 0xa8
    /* 0x0a0-0x280 */ FPU/XMM state;        // from param_1 + 0xe0 (fpregs)
};
```

Note: field 0x0a0+ is FPU state. If fpregs pointer is NULL, it zero-fills
0x1a0 bytes and logs "inventing FPU register state to satisfy ABI".

## Exception Info Structure (local_58 in signal handler)

Before the exception record is allocated, the signal handler builds an
exception info structure based on the signal type:

```c
struct exception_info {
    /* 0x00 */ uint32_t exception_code;     // Windows exception code
    /* 0x04 */ uint32_t reserved;
    /* 0x08 */ uint64_t fault_address;      // RIP at time of fault
    /* 0x10 */ uint64_t param1;             // Exception parameter 1
    /* 0x18 */ uint64_t param2;             // Exception parameter 2
    /* 0x20 */ uint64_t param3;
    /* 0x28 */ uint64_t param4;
    /* 0x30 */ uint64_t param5;
};
```

### Signal → Exception Code Mapping

| Signal | Exception Code | Notes |
|--------|---------------|-------|
| SIGILL (4) | 3 | EXCEPTION_BREAKPOINT (illegal instruction treated as BP) |
| SIGTRAP (5), no TF | 2 | EXCEPTION_BREAKPOINT, RIP adjusted -1, nparams=1 |
| SIGTRAP (5), TF set | 2 | EXCEPTION_SINGLE_STEP, nparams=4 |
| SIGSEGV (7), trap 0xe | 7 | EXCEPTION_ACCESS_VIOLATION, fault addr in params |
| SIGSEGV (7), trap 0xd | 7/2 | GP fault - depends on error code bits |
| SIGFPE (8) | varies | Called via FUN_0028a410 |
| SIGBUS (0xb) | 1 | EXCEPTION_ACCESS_VIOLATION (alignment) |
| SIGABRT (0xc) | 2/3 | Depends on address validity |

### For SIGTRAP (int3 callback):
```c
// From decompiled (lines 157554-157590):
if (param_1 == 5) {  // SIGTRAP
    if (!(EFLAGS & 0x100)) {  // Not single-step (TF not set)
        // int3 breakpoint
        exception_code = 2;   // STATUS_BREAKPOINT
        rip_adjusted = RIP - 1;  // Back up past the int3 byte
        *(param_3 + 0xa8) = rip_adjusted;  // Update RIP in context
        nparams = 1;
        param1 = (ERR >> 3) | 0x100000000;  // Encode error info
    } else {
        // Single-step trap (TF was set)
        exception_code = 2;
        nparams = 4;
        fault_address = RIP;  // Don't adjust
    }
}
```

## Thread Exception Stack

The host maintains a per-thread exception nesting stack:

```c
// Thread Control Block (TCB) at FS_OFFSET - 0x10
struct thread_control_block {
    // ...
    /* 0x068 */ uint64_t thread_state_ptr;   // Passed as RDX to dispatcher
    /* 0x088 */ uint64_t signal_stack_base;   // Alt signal stack base
    // ...
    /* 0x9e8 */ int32_t  exception_nesting;  // Current nesting depth (max 16)
    // ...
    /* 0xa20 */ uint64_t exception_records[16]; // Pointers to active records
};
```

### Nesting logic:
```c
tcb = *(FS_OFFSET - 0x10);
nesting = *(int*)(tcb + 0x9e8);
*(int*)(tcb + 0x9e8) = nesting + 1;
if (nesting > 15) FATAL("too many nested exceptions");

// Allocate and store exception record
record = allocate_exception_record(&exception_info, &out_buf);
*(tcb + 0xa20 + nesting * 8) = record;
```

## Context Rewriting (the key trick)

After building the exception record, the signal handler rewrites the
saved ucontext so that when it returns, the NTUM resumes at the
exception dispatcher instead of the faulting instruction:

```c
// Line 157755 in sqlservr_FULL.c
*(uint64_t*)(ucontext + 0xa8) = ki_user_exception_dispatcher;  // RIP
*(uint64_t*)(ucontext + 0x98) = exception_record_ptr;          // RCX
*(uint64_t*)(ucontext + 0x88) = *(uint64_t*)(tcb + 0x68);      // RDX = thread_state
*(uint64_t*)(ucontext + 0xb0) &= ~0x100;                       // Clear TF
```

So the NTUM's KiUserExceptionDispatcher is called as:
```
KiUserExceptionDispatcher(rcx=exception_record, rdx=thread_state)
```

## Exception Record Allocation (FUN_00252b10)

```c
// Allocates from the PE heap at ~0x300000000 (kernel heap)
// Input: pointer to exception_info struct (0x38 bytes)
// Output: pointer to allocated dk_exception_record (0x280 bytes)
// Returns: pointer to the record (same as *out_buf)
//
// The record is freed later via DK_ExceptionRecordFree (ABI 0xa001000)
```

## Post-Resolution Config Calls

After the 84 GetFunction_v2 calls and boot sync, the NTUM makes
configuration calls with .data address types:

| Call# | Type | data_size | in_buf | Purpose |
|-------|------|-----------|--------|---------|
| 85 | 0x18063af08 | 0x2 | 0xC0000002 | Report error status |
| 86 | 0x18063af18 | 0x3e | NULL | Config query |
| 87 | 0x18063af28 | 0x2000000 | NULL | Memory config |
| 88 | 0x18063af38 | 0x8 | NULL | Config |
| 89 | 0x18063aca0 | data addr | 0x18063a900 | Internal dispatch |
| 90 | 0x18063aca0 | data addr | 0x18063a900 | Internal dispatch |

**Call #85's in_buf = 0xC0000002 (STATUS_NOT_IMPLEMENTED)** indicates that
the NTUM received this error from a previous GetFunction_v2 call. This
means our output protocol for writing function pointers is incorrect.

### GetFunction_v2 Output Protocol Issue

Our code writes:
```c
uint64_t *result_area = *(uint64_t**)out_buf;  // double-deref
*result_area = (uint64_t)func;
```

The NTUM may expect:
```c
*(uint64_t*)out_buf = (uint64_t)func;  // single-deref
```

Or the return value of DK_AbiDispatcher itself may carry the function pointer.

## Implementation Plan

1. **Exception forwarding**: Rewrite ntum_signals.c to:
   - Build dk_exception_record (0x280 bytes) from ucontext
   - Read KiUserExceptionDispatcher from `g_runtime_callback_state + 0x10`
   - Rewrite RIP, RCX, RDX in ucontext
   - Maintain per-thread exception nesting

2. **Fix ABI dispatch**: Try alternative output protocols for GetFunction_v2

3. **Thread state setup**: Ensure FS_OFFSET - 0x10 points to valid TCB with
   fields at 0x68, 0x88, 0x9e8, 0xa20
