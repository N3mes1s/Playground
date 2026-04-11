# NTUM Thread Switching - Reverse Engineering

## Thread Switcher at PE RVA 0x3a0650

```c
// Entry: CLD + save context
void __attribute__((naked)) thread_switch(void) {
    // rcx = rsp + 0x4f0 (caller context from stack)
    // rdx = result from call to 0x23db20 → 0x23d5c0
    
    call setup_thread_context;  // 0x23db20
    
    if (rdx == NULL)
        rdx = &default_thread_block;  // 0x18063b220
    
    r8 = context->stack_info;   // [rcx + 0x10] ← CRASHES HERE (NULL)
    r9 = r8->stack_ptr;         // [r8 + 0x30]
    
    // Validate stack pointer is within thread's stack range
    if (r9 < thread_block->stack_limit ||    // [rdx + 0x18]
        r9 > thread_block->stack_base)       // [rdx + 0x10]
        goto use_fallback_stack;
    
    // Switch to thread's stack
    old_rsp = rsp;
    rsp = r9;                   // SWITCH STACK!
    
    // Take ownership of thread
    lock cmpxchg [rdx+0x08], 1; // Atomic acquire
    
    // Set up interrupt return frame on new stack
    rsp &= 0xFFF0;             // Align
    rsp -= 0x30;
    push ss, old_rsp, 0, cs, 0;
    jmp continue;

use_fallback_stack:
    rsp = thread_block->stack_base;  // [rdx + 0x10]
    // Same interrupt frame setup
}
```

## Thread Block Structure (at 0x18063b220)

```c
struct ntum_thread_block {
    uint64_t unknown_00;       // +0x00
    uint8_t  ownership_lock;   // +0x08 (cmpxchg target)
    uint8_t  _pad[7];
    uint64_t stack_base;       // +0x10 (top of stack, highest address)
    uint64_t stack_limit;      // +0x18 (bottom of stack, lowest address)
    // ... more fields
};
```

## Context Structure

The thread context at `rcx` (from rsp + 0x4f0):

```c
struct ntum_thread_context {
    uint64_t unknown_00;
    uint64_t unknown_08;
    void    *stack_info;       // +0x10 → must point to stack descriptor
    // ...
};

struct ntum_stack_info {
    // ...
    uint64_t stack_ptr;        // +0x30 (the actual RSP value to switch to)
    // ...
};
```

## Current Issue

The context at `rcx + 0x10` is NULL because the NTUM's init code didn't
populate it. The thread context is built on the NTUM's own stack in .data
(around 0x18063ac10). The init code should have written a stack descriptor
pointer there, but it didn't.

Possible causes:
1. A config call that should have created a thread didn't do its work
2. The NTUM's C++ constructors that set up thread contexts failed silently
3. The ParameterBuffer or feature flags are missing thread-related config

## Setup Function 0x23db20

Calls:
1. `0x2962a8` - Security cookie validation (stack canary check)
2. `0x23d5c0` - Thread context initialization

The function at `0x23d5c0` takes:
- rcx = context pointer (from caller's stack)
- rdx = thread block
- r8 = some flag
- r9 = another flag

It returns with rcx/rdx set for the thread switcher.

## Next Steps

1. Check if the NTUM writes to RuntimeCallbackState+0x10 during the
   second resolution pass (it might set KiUserExceptionDispatcher there)
2. The thread context at rcx+0x10 needs to be populated - check what
   PE code writes to the stack area around 0x18063ac10-0x18063ac30
3. May need to implement DK_ThreadCreate properly to set up these
   structures
