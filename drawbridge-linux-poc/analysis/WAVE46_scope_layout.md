# Wave-46: FUN_0x37f128 analysis

## CRITICAL FINDING: FUN_0x37f128 is NOT a list traversal

The wave-39 framing ("FUN_0x37f128 walks the scope list, produces wrong
descriptor for out-of-range request") does not match the disassembly.

FUN_0x37f128 is a **slot allocator** over a fixed descriptor pool. It does
NOT take a request_va, does NOT iterate scope nodes, and does NOT do any
VA range comparison. Appending a "second scope node" to a list at
[vms+0xa8] will not work because [vms+0xa8] is not a list head.

### Call signature (verified)

From caller FUN_0x37cf68 @ 0x37d05d:
```
mov  0xa8(%r13), %rcx     ; rcx = scope_pool   = [vms+0xa8]
mov  %r13,       %rdx     ; rdx = vms          (owner pointer)
call 0x37f128             ; -> rax = descriptor*
cmp  $0x2, 0x80(%rax)     ; caller validates returned descriptor
```

Only 2 args. The PE image VA 0x180000000 is **never passed** to FUN_0x37f128.
Inside the caller, the page-aligned request_va lives in `rsi` and is later
handed to FUN_0x37e518 / FUN_0x37b2f0 (the actual VA-mapping work).

## Pool object layout at [vms+0xa8]   (rcx -> rsi inside FUN_0x37f128)

| Offset | Meaning                              | How FUN_0x37f128 uses it          |
|-------:|--------------------------------------|-----------------------------------|
| +0x10  | Descriptor array base                | `rdi = [rsi+0x10] + 0x88*slot`    |
| +0x18  | (sub-pool ptr; inspected by 0x380058)| passed via rdi to FUN_0x380058    |
| +0x28  | next-free slot index / counter       | `r14 = [rsi+0x28] - 1`; bitmap r8 |
| +0x38  | (per-descriptor stride/base)         | not touched by FUN_0x37f128 here  |
| +0x40  | Lock object                          | acquire 0x21ad20 / release 0x21ae70 |

Each descriptor entry is **0x88 bytes**. Within an entry FUN_0x37f128 sets:
  +0x18 = 1     (state := allocated)
  +0x60 = vms   (owner backpointer, from rdx/r12)
Caller then expects [desc+0x80] == 2 (set by FUN_0x3804b8 post-call).

## Bitmap search (FUN_0x384fbc, called at 0x37f18c)

Args: rcx = pool, rdx = 1 (start hint), r8 = max_slots-1.
Returns: rax = chosen slot index, or -1 on failure.
This is a pure bitmap free-bit search — there is no VA comparison anywhere.

## Scope list at [vms+0xa8]?
  - **It is NOT a linked list.** It is a single pool object pointer.
  - No next-pointer field is referenced by FUN_0x37f128.
  - No sentinel value exists.
  - No VA range field (va_base / va_limit) is examined by FUN_0x37f128.

## FUN_0x37f128 traversal pseudocode

```c
desc_t* alloc_descriptor(pool_t* pool /*rcx*/, vms_t* vms /*rdx*/) {
    enter_critical(&pool->lock /* +0x40 */);

    uint64_t hint  = pool->next_free - 1;        // [pool+0x28]-1
    int64_t  slot  = bitmap_find_free(pool, 1, hint);   // 0x384fbc
    if (slot == -1) goto out;                    // failure path

    desc_t* d = (desc_t*)((char*)pool->array_base /* +0x10 */ + 0x88*slot);
    sub_init(d);                                 // 0x380058
    d->state = 1;                                // [d+0x18] = 1
    d->owner_vms = vms;                          // [d+0x60] = vms
    sub_step(d, 1); sub_step(d, 2);              // 0x380110 x2
    sub_register(vms, d);                        // 0x37a1c8
    pool->next_free = hint;                      // commit
out:
    leave_critical(&pool->lock);
    return d;   // rdi
}
```

## Minimal scope node for PE image range

**Cannot be expressed as a node in a list — no list exists.**
Mapping the PE image at 0x180000000 cannot be done by appending to a list
at [vms+0xa8]. The pool's descriptor array uses a single implicit VA scheme;
extending it to cover an arbitrary external VA requires a different hook
point, NOT FUN_0x37f128.

## Append algorithm

There is nothing to append. Concrete options for the host:

1. **Wrong target.** Re-derive the actual VA-range scope head. Likely
   candidates to inspect next:
     - FUN_0x37b2f0  (called with vms + an alloc'd object; may be the
       AVL/range insert that records VA mapping)
     - FUN_0x37e518  (consumes the page-aligned request_va `rsi`)
     - FUN_0x381d8c  (called with vms, request_va, allocator)
   One of these owns the va_base/va_limit data the loader actually checks.

2. **Patch the validator.** Caller checks `[desc+0x80] == 2` at 0x37d073.
   For the PE image path, supply a descriptor whose +0x80 field is forced
   to 2 by host pre-population, bypassing the pool allocator entirely.

3. **Pool VA base override.** If the existing pool's implicit VA
   (encoded via +0x38 and slot_idx*0x1000) is the only knob, change
   [pool+0x38] before the call so slot 0 maps onto 0x180000000 — but this
   destroys the kernel-heap mapping. Not viable as written.

UNKNOWN: which of the three candidate routines above contains the actual
va_base / va_limit comparison. 20-min budget exhausted on FUN_0x37f128
itself; recommend wave-47 target FUN_0x37b2f0 or FUN_0x381d8c next.
