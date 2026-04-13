# Wave-50a: FUN_0x37f128 return-object (process_ctx / descriptor) layout

Object returned by `FUN_0x37f128` (entry at `/tmp/sqlpal_full.txt`
line 437101, rva 0x37f128).  Earlier waves referred to this object as
"descriptor"; Wave-48 called it `process_ctx` because the AVL-insert
consumer `FUN_0x380708` treats it as the per-process bookkeeping root.
Both names refer to the **same** 0x88-byte record; it is one slot in
the pool at `vms+0xa8`.

## Entry / exit chain

```
caller FUN_0x37cf68                      (line 434727, rva 0x37d067)
   -> FUN_0x37f128           slot alloc  (line 437101, rva 0x37f128)
        bitmap_find_free     (line 437132, call 0x384fbc)
        FUN_0x37a218         region prep (line 437161, call 0x37a218)
        FUN_0x380058         slot init   (line 437209, call 0x380058)
          FUN_0x3800ac       sub init    (line 438107, call 0x3800ac)
          FUN_0x380110       state step  (line 438138, call 0x380110)
        FUN_0x380110(d,1)    state := 1  (line 437214)
        FUN_0x380110(d,2)    state := 2  (line 437217)
        FUN_0x37a1c8         register    (line 437220)
   ret rax = rdi = pool_base + 0x88*slot (line 437238, rva 0x37f366)
```

Caller stores into `-0x28(%rbp)` (line 434729) and checks
`[desc+0x80] == 2` (line 434730).  All subsequent consumers
(`FUN_0x3804b8` at 434737, `FUN_0x208b0c`, `FUN_0x37d23c`, `FUN_0x37e4c0`,
`FUN_0x380708`) operate on this same object.

## Verified field table

Offsets relative to the object pointer (rax at 0x37d06c / rdi inside
FUN_0x37f128 after line 437207 `add 0x10(%rsi),%rdi`).  Each record is
0x88 bytes (stride confirmed at line 437206, `imul $0x88,%r15,%rdi`).

| Offset | Field                          | Type / width | Initialized where                                                                 | Read / written where                                            |
|-------:|--------------------------------|--------------|-----------------------------------------------------------------------------------|-----------------------------------------------------------------|
|  +0x00 | (unused / reserved)            | u64          | pool-construction zero-init (not touched per-alloc)                               | -                                                               |
|  +0x08 | LIST_ENTRY.Blink               | u64 ptr      | `FUN_0x37d23c` (line 434850-434854, Blink=rdi=vms+0x48)                           | List operations at vms+0x48                                     |
|  +0x10 | LIST_ENTRY.Flink (via r8+0x8)  | u64 ptr      | `FUN_0x37d23c` (line 434850, copies head Flink)                                   | same                                                            |
|  +0x18 | state-bit / init flag          | u32          | `FUN_0x37f128` line 437211 `movl $1, 0x18(%rdi)`                                  | Asserted non-zero by consumers                                  |
|  +0x18 | list-head back-pointer (desc)  | u64 ptr      | `FUN_0x37d23c` line 434856 `[rbx+0x18] = rdi`  (overwrites the state write above) | Used for unlink in sibling 0x37d300                             |
|  +0x20 | push-lock / queued-lock head   | u64 (guard)  | **Pool-construction only** (no per-alloc init observed in 0x37f128 / 0x380058)    | `FUN_0x380708` line 438548-438550 (acquire via 0x380ef8), 438574 release; `FUN_0x3804b8` line 438413 (same acquire pattern) |
|  +0x28 | AVL key / VA-start             | u64          | `FUN_0x381d8c` (wave-47) — written before FUN_0x380708 runs                       | `FUN_0x380708` line 438556 uses `0x28(rax)` as AVL key          |
|  +0x38 | pool-descriptor-array stride   | u64          | pool construction                                                                 | read at 437136, 437203 (`0x38(%rsi)`)                           |
|  +0x40 | AVL_TABLE root (RTL_AVL head)  | struct       | `FUN_0x380058` line 438108 `andq $0x0, 0x40(%rbx)` (zeroed per alloc)             | `FUN_0x380708` line 438553 `[rsi+0x40]`, 438572 insert          |
|  +0x48 | va_base                        | u64          | `FUN_0x380058` line 438106 `[rcx+0x48] = rdx + (r8<<0x1f)`                        | `FUN_0x3804b8` line 438395, 438427                              |
|  +0x50 | size (region length)           | u64          | `FUN_0x3800ac` line 438135 `mov $0x80000000, 0x50(%rbx)`                          | `FUN_0x3804b8` line 438399, 438333 assertion                    |
|  +0x58 | self-LIST head / AVL probe     | u64 ptr      | `FUN_0x3800ac` line 438137 `[rbx+0x58] = rbx` (self-link)                         | `FUN_0x380708` line 438572 `r9 = rax+0x58` (node embedded)      |
|  +0x60 | owner-tag / backpointer (vms)  | u64 ptr      | `FUN_0x3800ac` line 438132 zeros it; `FUN_0x37f128` line 437213 `[rdi+0x60] = r12(vms)` | `FUN_0x380708` line 438532 `r8 = [rcx+0x60]` (owner tag) |
|  +0x68 | va_base shifted                | u64          | `FUN_0x380058` line 438113 `[rbx+0x68] = rsi` (`slot<<12 + va_offset`)            | `FUN_0x3804b8` line 438418                                      |
|  +0x70 | page-count / bitmap-max (0x8000) | u64        | `FUN_0x380058` line 438111 and `FUN_0x3800ac` line 438139 (`$0x8000`)             | bitmap search / FUN_0x384fbc                                    |
|  +0x78 | owner-tag mirror               | u64 ptr      | `FUN_0x3800ac` line 438122 asserts it is 0 on entry, caller must supply later     | `FUN_0x380708` line 438535 `cmp [rax+0x78], r8` (must equal +0x60) |
|  +0x80 | lifecycle-state enum           | u32          | `FUN_0x37f128` via `FUN_0x380110`: 437214 (->1), 437217 (->2)                     | caller checks `==2` at line 434730                              |

Notes:

- `+0x18` is written twice: FUN_0x37f128 puts `1` as an init marker,
  then the per-vms list insert FUN_0x37d23c overwrites it with a
  back-pointer to `vms+0x48`.  Consumers that look at +0x18 after the
  chain completes see the list-head pointer, not the `1`.
- `+0x58` doubles as "self link when the AVL node is free" and "AVL
  node header when inserted".  FUN_0x380708 passes `desc+0x58` as the
  `RtlInsertElementGenericTableAvl` node pointer (r9 at line 438572).
- `+0x78` is NOT written by FUN_0x37f128.  FUN_0x3800ac line 438122
  asserts it is zero on pool-slot reuse.  The matching value for the
  FUN_0x380708 assertion (line 438535) must therefore be written by
  a caller between FUN_0x37f128 and FUN_0x380708 — most likely
  FUN_0x3804b8 (called line 434737) or FUN_0x381d8c (called
  line 434811).  It must equal `[process_ctx+0x60] == vms`.

## Self-init vs caller-init — the three "problem" offsets

| Offset | Set by 0x37f128? | Needs external writer? | Comment |
|-------:|:----------------:|:----------------------:|---------|
|  +0x20 (lock)       | NO  | NO  — pool-construction init suffices (lock object is stable across slot reuse; FUN_0x380058 does not reset it, and FUN_0x380708 just acquires/releases it) |
|  +0x40 (AVL root)   | YES | NO  — zeroed by FUN_0x380058 line 438108 every alloc |
|  +0x60 (owner tag)  | YES | NO  — FUN_0x37f128 line 437213 writes `vms` unconditionally |
|  +0x78 (owner mirror) | NO | **YES** — written by FUN_0x3804b8 / FUN_0x381d8c between alloc and AVL insert; required so FUN_0x380708 assertion at line 438535 passes |

The +0x20 lock is not re-initialized per allocation; it is part of the
pool's stable layout.  Per Wave-46 the pool object at `vms+0xa8` has
its own lock at pool+0x40 (acquired at 437126).  The per-slot lock at
slot+0x20 is created once when the pool is constructed and survives
slot free/alloc cycles.

## Source line citations (all in `/tmp/sqlpal_full.txt`)

- FUN_0x37f128 entry             : line 437101 (rva 0x37f128)
- FUN_0x37f128 return `%rdi`     : line 437238 (`mov %rdi,%rax`)
- FUN_0x37f128 writes +0x18 = 1  : line 437211
- FUN_0x37f128 writes +0x60 = r12: line 437213
- FUN_0x37f128 sets +0x80 = 1    : line 437214 (call 0x380110 with edx=1)
- FUN_0x37f128 sets +0x80 = 2    : line 437217 (call 0x380110 with edx=2)
- FUN_0x380058 zeros +0x40       : line 438108
- FUN_0x380058 writes +0x48      : line 438106
- FUN_0x380058 writes +0x68      : line 438113
- FUN_0x380058 writes +0x70      : line 438111
- FUN_0x3800ac zeros +0x60       : line 438132
- FUN_0x3800ac writes +0x50      : line 438135
- FUN_0x3800ac self-links +0x58  : line 438137
- FUN_0x3800ac asserts +0x78 = 0 : line 438122
- FUN_0x380708 reads +0x60       : line 438532
- FUN_0x380708 asserts +0x78 ==  : line 438535
- FUN_0x380708 acquires +0x20    : line 438548-438550
- FUN_0x380708 inserts into +0x40: line 438553-438572
- FUN_0x37d23c writes +0x08/+0x18: line 434850-434856
- FUN_0x37cf68 consumes ret value: line 434728 (`mov %rax,%rdi`)

## Host-side reproduction recommendation

**Option (b): call the equivalent of FUN_0x37f128 — do NOT hand-craft
a process_ctx in the host.**

Rationale:
1. The object is a pool slot, not a heap allocation.  Its address
   must be `pool_array_base + 0x88 * slot` where `pool_array_base`
   lives at `[vms+0xa8]+0x10`.  Synthesizing one outside the pool
   will fail the stride-arithmetic that FUN_0x380708 and the free
   path (FUN_0x380558) perform.
2. The lock at +0x20 and the stride/state at +0x38/+0x70 are set up
   by the pool constructor (not reconstructed per allocation).  A
   hand-rolled object would fail acquire at FUN_0x380708 line 438548.
3. Only two fields (+0x78, +0x28 AVL key) require between-alloc-and-
   AVL-insert population, and those are done by FUN_0x3804b8 and
   FUN_0x381d8c respectively — both of which must run anyway for the
   scope descriptor to be valid.

Concrete host flow for reproducing an AVL-registered descriptor:

```
(1) drive FUN_0x37f128 to acquire a pool slot       -> rax = ctx
(2) drive FUN_0x3804b8(ctx, &va, &sz)               -> +0x78, +0x48/+0x50 finalized
(3) drive FUN_0x381d8c(ctx, vms, ..., &desc_slot)   -> +0x28 AVL key set
(4) drive FUN_0x380708(ctx, &desc_slot)             -> registers in ctx+0x40 AVL
```

Attempting to skip (1) and inject a synthesized ctx pointer is not
viable: step (4) will dereference +0x20 as a lock and +0x38 as a
pool-stride, neither of which a synthesized object has correct values
for without first running the pool constructor.

## Open items / UNKNOWN

- The exact writer of `+0x78` on the normal path.  FUN_0x3800ac
  asserts it's 0 on pool-slot reuse, and FUN_0x380708 requires it
  equal +0x60.  The write must occur between those two asserts; most
  likely inside FUN_0x3804b8 (wave-51 target) or FUN_0x381d8c
  (wave-47).  20-minute budget exhausted before confirming.
- The AVL "key" at +0x28 — Wave-47 identified FUN_0x381d8c as a
  writer of +0x28; need to re-verify that the key domain matches the
  FUN_0x380708 comparison at line 438556.
