# Wave-51-a: FUN_0x37f128 — slot-descriptor allocator (outer entry)

All line/RVA citations are from `/tmp/sqlpal_full.txt`.

Function entry RVA `0x37f128`, lines 437101-437238 (epilogue extends to 437238 — the `mov %rdi,%rax` at line 437238 is cited in Wave-50a).

## Arguments

From the single call site at line 434727 (RVA 0x37d067):

```
437107:  mov 0xa8(%r13), %rcx    ; r13 = vms (per Wave-48)
437108:  mov %r13, %rdx
437109:  call FUN_0x37f128
```

| Reg | Meaning                            | Source in caller                   |
|-----|------------------------------------|------------------------------------|
| rcx | **pool object** (`*Pool`)          | `[vms+0xa8]` (line 434720)         |
| rdx | **vms** pointer                    | `r13` (line 434721)                |
| r8  | unused on the call                 | --                                 |
| r9  | unused on the call                 | --                                 |

Inside the prologue:

```
437111:  mov %rcx,%rsi          ; rsi = pool      (survives through body)
437110:  mov %rdx,%r12          ; r12 = vms       (survives through body)
```

So throughout FUN_0x37f128: `rsi = pool`, `r12 = vms`.

## Pool-object layout consumed by FUN_0x37f128

| Offset (rsi)  | Used at              | Meaning                                  |
|--------------:|----------------------|------------------------------------------|
| +0x10         | line 437207          | **Pool base address** (slot-array base)  |
| +0x18         | line 437205          | Passed as `rdx` arg to FUN_0x380058 (va_offset / base-offset) |
| +0x28         | line 437127, 437222  | 8-byte generation/epoch counter (read into r14, decremented, written back) |
| +0x38         | line 437136, 437203  | Per-slot stride or pool-descriptor-array stride (passed to FUN_0x37a218, FUN_0x380058) |
| +0x40         | line 437122          | Pool lock (acquired via FUN_0x21ad20 at 437126) |

Pool base address formula (line 437206-437207):

```
rdi = r15 * 0x88          ; slot index * stride
rdi += [rsi+0x10]         ; + pool base  =>  rdi = slot descriptor address
```

## Slot-stride

**0x88** (constant immediate, line 437206 `imul $0x88,%r15,%rdi`). Matches Wave-50a.

## Bitmap / slot-index allocation

Line 437132 calls `FUN_0x384fbc(rcx=pool, rdx=1, r8=cap-1)`:

```
437127:  mov 0x28(%rsi), %r14           ; r14 = [pool+0x28]
437128:  mov $0x1, %edx
437129:  dec %r14                        ; r14 = cap - 1
437130:  mov %rsi, %rcx                  ; rcx = pool
437131:  mov %r14, %r8                   ; r8  = cap-1
437132:  call FUN_0x384fbc               ; bitmap_find_and_set
437133:  mov %rax, %r15                  ; r15 = slot_index
437134:  cmp $-1, %rax
437135:  je  0x37f330                    ; failure -> skip to epilogue
```

So FUN_0x384fbc is the "bitmap_find_free_and_set" helper; return `-1` means pool exhausted and the whole body is skipped.

## Direct field-writes by FUN_0x37f128 body

After the slot address `rdi = pool_base + 0x88*slot` is computed:

| Line   | RVA        | Instruction                          | Descriptor field write                        | Matches Wave-50a? |
|--------|------------|--------------------------------------|-----------------------------------------------|-------------------|
| 437211 | 0x37f2fc   | `movl $0x1, 0x18(%rdi)`              | `desc[+0x18] = 1` (init-state marker)         | YES (row +0x18)   |
| 437213 | 0x37f306   | `mov %r12, 0x60(%rdi)`               | `desc[+0x60] = vms`  (owner tag)              | YES (row +0x60)   |

No other direct writes from this function's body. The rest of the descriptor's fields are populated by the sub-calls (see below). The `+0x80` transitions are delegated to FUN_0x380110.

## All calls made by FUN_0x37f128

Internal (analyzed in this wave unless noted):

| Line   | Target           | Purpose                                                            |
|--------|------------------|--------------------------------------------------------------------|
| 437113 | FUN_0x24c2d0     | Pre-lock housekeeping; return byte saved in `r13b` (restored later at 437233) |
| 437115 | FUN_0x244cd0     | Returns current thread/owner pointer `rax`; derives `rbx` via `sbb` trick |
| 437126 | FUN_0x21ad20     | **Acquire pool lock** at `pool+0x40`  (rbp = rsi+0x40)             |
| 437132 | FUN_0x384fbc     | **Bitmap allocator** — returns slot index in rax                   |
| 437161 | FUN_0x37a218     | Region prepare (inserts record into pool-descriptor table); signed-fail path at 437162-437170 invokes assertion helper FUN_0x3a0880 + FUN_0x218494 |
| 437209 | **FUN_0x380058** | Slot-descriptor initializer (see Wave-51-b)                        |
| 437214 | **FUN_0x380110** | `desc[+0x80]` state: 1 -> **1** (per edx=1 at line 437210)        |
| 437217 | **FUN_0x380110** | `desc[+0x80]` state: 1 -> **2** (per edx=2 at line 437215)        |
| 437220 | FUN_0x37a1c8     | Register slot with vms (`rcx=vms, rdx=desc`) — outside this wave's scope |
| 437226 | FUN_0x21ae70     | **Release pool lock** at `pool+0x40`                               |
| 437230 | FUN_0x244cd0     | Second call — epilogue bookkeeping                                 |

Assertion fanout calls (FUN_0x3a0880 → FUN_0x218494) at lines 437164-437170, 437176-437182, 437186-437192, 437196-437202 — all guarding `FUN_0x37a218` post-conditions (the four `cmp` / `je` gates on fields of the local `0x90..0xa8(%rsp)` out-buffer filled by FUN_0x37a218). They do NOT touch the slot descriptor.

## Local-stack out-buffer passed to FUN_0x37a218 (context only)

Lines 437136-437160 set up a 7-argument call to FUN_0x37a218 using register args + 0x20/0x28/0x30/0x38/0x40/0x48 stack slots. Out-fields verified post-call:

| Asserted field      | Line   | Expected                                    |
|---------------------|--------|---------------------------------------------|
| `[rsp+0x90]`        | 437173 | == `[pool+0x38] + slot*0x1000`              |
| `[rsp+0xa0]`        | 437183 | == 0                                        |
| `[rsp+0xa8]`        | 437193 | == 0x1000                                   |

These are checks on FUN_0x37a218's return behaviour, not descriptor writes.

## Epilogue

| Line   | RVA        | Action                                                                 |
|--------|------------|------------------------------------------------------------------------|
| 437221 | 0x37f327   | `lock orl $0, (%rsp)` — memory barrier                                 |
| 437222 | 0x37f32c   | `mov %r14, 0x28(%rsi)` — write back decremented generation counter     |
| 437223-437229 | --  | Release pool lock, cleanup r13b flag                                   |
| 437238 | 0x37f366   | `mov %rdi, %rax` — **return value = slot descriptor pointer**          |

## Summary

- Pool base = `[pool+0x10]` where `pool = [vms+0xa8]`.
- Stride = `0x88`.
- Body writes two fields only: `+0x18 = 1` and `+0x60 = vms`.
- Body delegates three classes of field-writes:
  1. `+0x48, +0x68, +0x70, +0x40, +0x50, +0x58` — FUN_0x380058 / FUN_0x3800ac (Wave-51-b / Wave-51-c).
  2. `+0x80` state machine — FUN_0x380110 (Wave-51-d) called twice directly (edx=1, edx=2) PLUS once indirectly through FUN_0x3800ac (edx=0).
- `+0x78` is **NOT** written by this function nor any of its callees in this chain (see Wave-51-c); Wave-50a's "external writer" gap remains unresolved here.
