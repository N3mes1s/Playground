# Drawbridge Boot Sequence - Complete Debug Log & Findings

## Boot Flow (confirmed working path)

```
Entry point (RVA 0x3a04d0)
  │ lea rsp, [rip+0x296b29] → sets stack to 0x180637000
  │ add rsp, [rip+0x72fa2]  → +0x4000 = 0x18063b000
  │ sub rsp, 0x28
  │ jmp 0x180204ad0          → init wrapper
  │
  ├─ Init wrapper (0x180204ad0)
  │   │ sub rsp, 0x28
  │   │ mov r9, rdx     ; save params
  │   │ Call cookie init (0x180204704)
  │   │   └─ rdtsc, compute cookie, store at [0x180600000]
  │   │      We pre-store cookie so this passes through
  │   │
  │   └─ Call real_init at 0x180204754 with rcx=params from r9
  │
  ├─ real_init calls the boot function chain:
  │   │ FUN_002053e0 → FUN_0020ba60 (WINDOWS_LIBOS_PARAMETERS setup)
  │   │ Then calls FUN_002051e0 (loading guest)
  │   │ Then calls FUN_00204680 (PAL boot) ← THIS IS WHERE IT FAILS
  │   │
  │   └─ FUN_00204680 (PAL boot) sequence:
  │       1. FUN_0028e070(local_80)          ← Result object init
  │       2. Check DAT_0036f618 (first-time flag)
  │       3. FUN_00354250/60 (setup logger)
  │       4. FUN_00279cd0 (config init)
  │       5. FUN_0027a2f0 (if param_2 set)
  │       6. FUN_001bd660 → FUN_00204bb0 (create boot thread)
  │       7. FUN_0021a7d0 (subsystem init)
  │       8. FUN_0021d1c0 → FUN_0028e530 check ← OpenSSL init
  │       9. FUN_002285a0 / FUN_00235a80 / FUN_00244790
  │       10. FUN_001f1c50(local_58, 0, param_1+0x410)  ← FileIO init
  │           └─ FUN_001f1fd0 (completion port constructor)
  │       11. FUN_0028e530 check ← THIS FAILS → assert
  │       12. FUN_00279f10 (if success)
  │       13. FUN_00204da0 (final init)
  │
  └─ Assert at 0x180204ac9 (CC EB FD pattern)
      ESI = 0xC0000002 (STATUS_NOT_IMPLEMENTED)
```

## What We Confirmed

### 1. GetFunction_v2 Output Protocol = Double-Deref
```
out_buf = 0x18063ae70 (fixed .data address)
*out_buf = 0x18063aeb0 (pointer to result slot)
We write: *(*out_buf) = function_pointer  (double-deref)

ALL 84 calls use the SAME out_buf and result slot.
The NTUM copies from the result slot to its internal table between calls.
```

### 2. The 0xC0000002 is NTUM-Internal
- NOT from our DK function returns (all return SUCCESS)
- NOT from our GetFunction_v2 output (double-deref confirmed correct)
- NOT from DK_GenericStub (never called during boot - 0 stub invocations)
- IS generated inside the NTUM's C++ initialization code
- The NTUM's `FUN_001f1c50` (FileIoCompletionPort init) fails
- Error code flows through FUN_0028e530 (result check) → assert

### 3. Post-Resolution Config Calls are NOT Errors
```
Call #85: type=0x18063af08 size=0x2 in=0xC0000002  out=0x180204818
Call #86: type=0x18063af18 size=0x3e in=NULL       out=0x180204850
Call #87: type=0x18063af28 size=0x2000000 in=NULL   out=0x1802048e2
Call #88: type=0x18063af38 size=0x8 in=NULL         out=0x1802049d5
```
- `type` = .data addresses (internal function table entries)
- `out` = .text addresses (return addresses from caller)
- `in=0xC0000002` at call #85 is a PARAMETER, not our return value
- The NTUM passes its internal error code to us for logging/reporting
- We return SUCCESS, NTUM continues to the assert

### 4. No DK Stubs Are Ever Called
- 84 functions resolved (20 as DK_GenericStub, 64 as real implementations)
- The assert fires BEFORE the NTUM ever calls any resolved function
- The initialization failure is purely inside NTUM C++ constructors

## What the NTUM Init Needs (from decompiled code)

### DAT_0036f598 (PAL State Object)
The NTUM reads `DAT_0036f598 + 0x138` during FileIO init.
This is populated from the boot parameters during FUN_0020ba60.
- `+0x138` = module handle / SFP reference
- `+0x180` = image base
- `+0x188` = image length

### FUN_001f1fd0 (FileIoCompletionPort Constructor)
1. Calls `FUN_001f5120(param_1, 1)` - base I/O object init
2. Sets vtable: `*param_1 = &PTR_FUN_003594e8`
3. Calls `FUN_0029a4e0(*(DAT_0036f598 + 0x138))` - reads PAL config
4. Creates completion port structures
5. If `*(param_1 + 0x2b) != 0`, allocates 0x80 bytes for thread pool

### FUN_0021d1c0 (OpenSSL/TLS Init)
- Called during boot to initialize crypto
- If it fails, error 0x66 is returned
- Check: `FUN_0028e1f0(local_80)` - if error, logs "Unable to initialize OpenSSL"

## Mistakes Made & Lessons Learned

### Mistake 1: Single-deref output (DESTROYED NTUM internal pointer)
**What happened**: We wrote `*(uint64_t*)out_buf = func`, which overwrote
the NTUM's internal pointer at 0x18063ae70 with our function address.
**How we found it**: Added debug logging showing `out_buf` and `*out_buf`
values, realized out_buf was a pointer-to-pointer.
**Fix**: Use `**(uint64_t**)out_buf = func` (double-deref).

### Mistake 2: Returning STATUS_NOT_IMPLEMENTED from ABI_GET_VERSION_V2
**What happened**: The ABI version query returned 0xC0000002 which the NTUM
cached and reported as an error.
**How we found it**: Searched for all NOT_IMPLEMENTED returns in dk_pal.c.
**Fix**: Return STATUS_SUCCESS from all ABI calls.

### Mistake 3: Thinking 0xC0000002 came from our code
**What happened**: Spent time trying different output protocols, return
values, and stub behavior. The error was NTUM-internal.
**How we found it**: Added DK_GenericStub call logging - zero stub calls
during boot proved the error isn't from our resolved functions.
**Lesson**: Always verify assumptions with instrumentation before changing code.

### Mistake 4: Patching assert to `ret` instead of understanding root cause
**What happened**: The SIGTRAP handler patched `CC EB FD` debug assertions
to `C3 90 90` (ret + nops). This caused the caller to get RAX=0 as return
value, leading to NULL dereference at 0x180439114.
**Lesson**: Debug assertions exist for a reason. Patching them hides real
bugs. Need to fix the underlying initialization failure instead.

### Mistake 5: Not using ms_abi for Win32 stubs initially
**What happened**: Win32 stubs in ntum-builder used manual thunks to
translate between Windows x64 and SysV calling conventions.
**Fix**: Added `__attribute__((ms_abi))` (WINAPI) to all stubs, letting
the compiler handle ABI translation automatically.

## Key Constants & Addresses

```
PE ImageBase:           0x180000000
Entry RVA:              0x3a04d0
Stack (set by entry):   0x18063b000 (= 0x180637000 + 0x4000)
Cookie:                 0x180600000, ~cookie at 0x180600008
Boot flag:              0x18063f8c0 (= 1 when ready)
ABI dispatcher:         0x18063f8c8
Params pointer:         0x180c00008
Params size:            0x180c00010
ParameterBuffer ptr:    0x180c00820

Guard check (ret):      0x18021ff10 (PE-native, don't touch)
Guard dispatch (jmp):   0x1803a86f0 (PE-native, don't touch)

.00cfg section:         0x180a00000 (guard_check @ +0, guard_dispatch @ +8)
.data section:          0x180600000 - 0x18066a2a8
.roafter section:       0x180c00000 - 0x180c01ce0

RuntimeCallbackState:   host g_runtime_callback_state (256 bytes)
KiUserExceptionDispatcher: *(RuntimeCallbackState + 0x10) (set by NTUM during boot)

out_buf for GetFunc:    0x18063ae70 (fixed)
*out_buf (result slot): 0x18063aeb0 (fixed, NTUM copies from here)
```

## Critical Discovery: Boot Functions are in ELF Host, Not PE

The decompiled functions FUN_001f1c50, FUN_001f1fd0, FUN_00202100, etc.
are ALL at ELF addresses (0x1xxxxx-0x3xxxxx). These are the HOST's code,
not the NTUM PE's code. The real sqlservr ELF contains:

- FUN_00354180 → raw syscall wrapper (io_setup=0xce, io_destroy=0xcf, etc.)
- FUN_00202100 → io_setup(nr_events, ctx_ptr) wrapper
- FUN_001f1fd0 → FileIoCompletionPort constructor
- FUN_001f1e20 → io_setup initialization
- FUN_00204680 → PAL boot (creates I/O subsystem, OpenSSL, threads)

The NTUM PE calls BACK to the ELF host for these operations.
The post-resolution config calls (#85-90) ARE this callback mechanism.

### Error Handling Pattern (Result type)
```c
// Result object (used throughout - FUN_0028e0xx family)
struct pal_result {
    char    *source_file;   // +0x00: source filename
    int32_t  status;        // +0x08: HRESULT (negative = error)
    uint16_t line;          // +0x0C: source line number
    int32_t  extended;      // +0x10: sign extension of status
};

// FUN_0028e530(result) = result->status >= 0 (is success)
// FUN_0028e0d0(result, status, file, line) = set error
// FUN_0028e560(dst, src) = propagate error
// FUN_0028e070(result) = clear/init result
// FUN_0028e1f0(result) = check if error (inverse of 0028e530)
```

### FUN_0029a4e0: Simple offset accessor
```c
// Returns param + 0x46a - accesses a flag byte in the module object
long get_io_mode_flag(long module_handle) { return module_handle + 0x46a; }
```

### The io_setup Failure
The FileIoCompletionPort init calls io_setup(0x400, &ctx) via syscall 0xce.
In the real sqlservr, this is done by the ELF's FUN_00354180 (raw syscall).
In our host, the NTUM PE can't call io_setup directly because:
1. The PE uses Windows ABI, not Linux syscall convention
2. The syscall wrappers are in the ELF host, not in the PE

The NTUM expects the host to provide io_setup through the PAL or via
the config calls. We need to handle config call types properly.

## Current Status (Updated)

### Milestones Achieved
- **183 DK dispatcher calls** (84 first-pass + 89 second-pass + 10 config/internal)
- **Boot assert ELIMINATED** via feature flag fix (0xf005000 → return 1)
- **Second resolution pass WORKING** via ABI version fix ([0x63f5c0] = 2)
- **Exception forwarding LIVE**: KiUserExceptionDispatcher at 0x1803a0664
- **First DK STUB runtime call** from PE at RVA 0x204a04

### Current Blocker: Thread Switching
The NTUM crashes at thread switcher (RVA 0x3a0674) because thread context
`[rcx+0x10]` = NULL. The thread context is built on the NTUM's stack.
KiUserExceptionDispatcher IS the thread switcher - exception forwarding
loops back to the same crash.

### Key Discovery: Resolution Overwrites Critical Globals
Several function resolutions store their results at addresses that overlap
with boot-critical globals:
- 0x7001000 v0 → [0x63f8c0] (boot flag, must be 1)
- 0x7002000 v0 → [0x63f5c0] (ABI version, must be 2)
- 0x8001001 v1 → [0x63f8c8] (dispatcher pointer!)
- 0xf005000 v0 → [0x63f4f0] (feature flag, checked == 1)

All must be re-armed on every dispatcher call.

### Key Discovery: Two Resolution Passes
- **First pass** (type 0x7002002): 84 functions, stores 32-bit values at
  per-function .data addresses. Version 0 - feature flags use special values.
- **Second pass** (type 0x7001002): 89 functions, stores 64-bit function
  pointers. Version 1+ - must return callable function addresses.

## ParameterBuffer Format (from PE RVA 0x204a37)

The NTUM checks the ParameterBuffer header:
```c
if (ParameterBuffer[0] != 0x10 || ParameterBuffer[4] != 0x38) {
    // Version mismatch - set error flag 0x20
    log("Incompatible ABI parameters");
} else {
    callback = ParameterBuffer[8] ? ParameterBuffer[8] : default_0x208600;
    store RuntimeCallbackState[0x18] = callback;
}
```

There are TWO separate checks:
1. `[0x180c00820]` → ptr → `[ptr] == 0x190` (WINDOWS_LIBOS_PARAMETERS size check)
2. `ParameterBuffer[0:4:8]` = `{0x10, 0x38, callback}` (ABI header check)

## TEB Thread Chain (from PE RVA 0x244cd0)

The NTUM accesses the current thread state via:
```c
void* get_current_thread_state(void) {
    void *teb = gs:0x30;              // TEB self-pointer
    void *kthread = TEB[0x1838];      // NTUM kernel thread info
    void *sched = kthread ? kthread[0x70] : NULL;  // Scheduling object
    return sched ? sched + 0xF0 : NULL;             // Thread state
}
```

This chain requires:
- `gs:0x30` → valid TEB (set by NTUM during thread creation)
- `TEB[0x1838]` → KTHREAD structure (created by NTUM kernel init)
- `KTHREAD[0x70]` → scheduling object (created by thread scheduler)
- `SCHED[0xF0]` → thread state for the caller

Without working VirtualMemoryAllocate and ThreadCreate, these structures
are never created, and the chain returns garbage (0x9d8).

## Current Crash: rcx=0x9d8 at RVA 0x387809

Stack trace:
```
0x180387809  ← crash: [rcx+0xc] where rcx=0x9d8
0x18024c2d9  ← caller: calls get_current_thread_state(), gets garbage
0x18043a494  ← .rdata string "DrtlDelayCurrentThreadExecut..."
```

The crash happens in the NTUM's DrtlDelayCurrentThreadExecute function,
which tries to access the current thread's scheduling state. The chain
returns 0x9d8 because TEB[0x1838] was set during NTUM init but the
KTHREAD structure it points to wasn't fully initialized.

## Next Steps

1. **The NTUM needs WORKING VirtualMemoryAllocate** to allocate its internal
   structures (KTHREAD, scheduling objects, etc.). Our current implementation
   may not be returning memory in the right address range.

2. **The NTUM needs WORKING NotificationEventCreate** to create synchronization
   events for its thread scheduler.

3. **DK_ThreadCreate** will be called once the NTUM's kernel init progresses
   past the current crash. It needs to create threads with proper TEB setup.

4. **Consider: the NTUM may need us to handle the init config calls differently**.
   The config call at 0x18063af70 with data_size=0x31 might need to return
   specific data for the NTUM's internal thread pool initialization.
