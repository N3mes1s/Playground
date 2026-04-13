# Wave-50b: Writer of `desc[+0x80]` — identified

Source: `/tmp/sqlpal_full.txt` (all line/RVA refs).

## TL;DR

The `cmpl $0x2, 0x80(%rax)` at RVA `0x37d073` (line 434730) is **NOT reading the
PE-image descriptor** produced by `FUN_0x37b2f0` / populated by `FUN_0x37e1f0`.
It is reading a *different* object — the per-process "slot descriptor" returned
by `FUN_0x37f128` at line 434727. The writer is **`FUN_0x380110`**, an explicit
state-transition helper that mirrors `FUN_0x37e4c0` but operates on field
`+0x80` instead of `+0x74`.

`FUN_0x380110` is called three times on the slot descriptor inside
`FUN_0x37f128`, walking state `0 -> 1 -> 2`. The final value of `+0x80` is
therefore `2`, matching the downstream expectation.

## Reader (re-confirmed)

| RVA        | Line   | Insn                                   |
|------------|--------|----------------------------------------|
| `0x37d067` | 434727 | `call 0x37f128`  (returns rax = slot_desc) |
| `0x37d06c` | 434728 | `mov %rax, %rdi`                       |
| `0x37d073` | 434730 | `cmpl $0x2, 0x80(%rax)`  **(dword read)** |
| `0x37d07a` | 434731 | `je 0x37d084` (success)                |
| `0x37d07c` | 434732 | `mov $0xc0000018, %r15d` (STATUS_INVALID_PARAMETER on mismatch) |

`rax` here is the FUN_0x37f128 return value, **NOT** r15 (the PE-image
descriptor). r15 holds the FUN_0x37b2f0-allocated descriptor with fields from
FUN_0x37e1f0 (+0x00..+0x78) — that object is passed separately to
FUN_0x381d8c at 434811.

## Writer: FUN_0x380110

RVA range `0x380110 .. 0x38027a` (lines 438146-438221). Signature:

```
void FUN_0x380110(void *desc /*rcx*/, uint32_t new_state /*edx*/);
```

The final store, executed on every path, is:

| Line   | RVA        | Insn                          | Meaning                          |
|--------|------------|-------------------------------|----------------------------------|
| 438216 | `0x380269` | `mov %edi, 0x80(%rbx)`        | **desc[+0x80] = new_state**      |

Body structure:
- `edi = edx` (new_state); `rbx = rcx` (desc).
- Dispatches on `new_state` (0..5) via repeated `sub $1, %r8d; je ...`.
- Each target asserts the CURRENT value of `desc[+0x80]` is the legal
  predecessor, then falls through to the common store at 0x380269.

State-table (predecessor asserted => new value written):

| new_state (edi) | Assert branch target | Current-value check at  |
|-----------------|----------------------|-------------------------|
| 0               | 0x38022e / line 438204 | `0x80(%rcx)` must be 1 or in {bit-0 unset set} — valid initial-reset |
| 1               | 0x3801fa / line 438194 | `cmpl $0, 0x80(%rcx)`   (requires current==0) |
| 2               | 0x3801c2 / line 438184 | `cmpl $1, 0x80(%rcx)`   (requires current==1) |
| 3               | 0x3801c2               | same as 2 (shared handler) |
| 4               | 0x3801fa               | same as 1 (shared handler) |
| 5               | 0x380182 / line 438172 | current - 2 must be <= 1 (i.e. {2,3}) |

All paths converge at `0x380269: mov %edi, 0x80(%rbx)`.

## Call-graph from FUN_0x37cf68 down to the writer

```
FUN_0x37cf68  (line 434669)
  |
  +-- call FUN_0x37f128         (line 434727, RVA 0x37d067)
  |     |
  |     +-- call FUN_0x384fbc          (line 437132)  -> returns slot index (r15)
  |     +-- call FUN_0x380058          (line 437209)  -> init slot descriptor
  |     |     +-- call FUN_0x3800ac    (line 438107)
  |     |           +-- call FUN_0x380110(desc, 0)   (line 438138)
  |     |                 => writes desc[+0x80] = 0   <-- 1st write
  |     +-- mov $1, 0x18(%rdi)         (line 437211)
  |     +-- mov %r12, 0x60(%rdi)       (line 437213)
  |     +-- call FUN_0x380110(desc, 1) (line 437214)
  |     |     => writes desc[+0x80] = 1                 <-- 2nd write
  |     +-- call FUN_0x380110(desc, 2) (line 437217)
  |           => writes desc[+0x80] = 2                 <-- 3rd write (final)
  |
  +-- cmpl $2, 0x80(%rax)        (line 434730, RVA 0x37d073)   [READ]
```

After FUN_0x37f128 returns, `desc[+0x80] == 2` on the slot descriptor.

## Key clarification vs WAVE48 notes

- `FUN_0x37e4c0` writes `desc[+0x74]` on the **PE-image descriptor** (r15).
- `FUN_0x380110` writes `desc[+0x80]` on the **slot descriptor** from
  FUN_0x37f128 (the "process_ctx"/scope-slot object). These are two distinct
  descriptor types.
- The state machines are parallel but independent (4-state on +0x74,
  wider state on +0x80 with explicit predecessor checks).

## Slot-descriptor fields initialized inside FUN_0x37f128

From the call at line 437127-437217:

| Offset | Value                                     | Line   |
|--------|-------------------------------------------|--------|
| +0x18  | `1`                                       | 437211 |
| +0x40  | `0` (via `andq $0, 0x40(%rbx)` in 0x380058)| 438108 |
| +0x48  | `slot_idx*0x80000000 + rdx_arg` (from 0x380058) | 438106 |
| +0x50  | `0x80000000` (from 0x3800ac)              | 438135 |
| +0x58  | `rbx` (self-ref, from 0x3800ac)           | 438137 |
| +0x60  | `r12` (= rdx arg = vms) — written AFTER 0x3800ac zeroed it | 437213 |
| +0x68  | `rsi = slot_idx<<12 + arg9`  (from 0x380058) | 438113 |
| +0x70  | `0x8000`                                  | 438111 |
| +0x80  | `2` (via 3x FUN_0x380110)                 | 438138 / 437214 / 437217 |

## Downstream relevance

`FUN_0x380708` (AVL insert at RVA 0x380708) — reachable from FUN_0x37cf68
line 434825 — also reads `+0x80`. At line 438273 it does
`cmpl $0, 0x80(%rdi)` (asserts uninit) and at line 438285
`movl $4, 0x80(%rdi)` (transitions to 4 on splice). That is a **different
instance** again (the AVL node descriptor, arg `rdi`), not the same object
checked at 0x37d073.

## Impact on wave-44/49 crash at 0x3756a3

Since the +0x80 reader at 0x37d073 targets the slot descriptor, fixing the
PE-image descriptor alone will not satisfy it. Any emulation of FUN_0x37cf68
must also:

1. Allocate or fake a slot descriptor of at least 0x88 bytes (the slot stride
   seen in `imul $0x88` at line 437206).
2. Populate the fields in the table above, in particular +0x80 = 2.
3. Return the slot descriptor pointer from a stub of FUN_0x37f128 (or pre-seed
   whatever `r13+0xa8` points to so that the bitmap/slot machinery finds a
   valid entry).

The PE-image descriptor (r15, from FUN_0x37b2f0) does **not** itself get
+0x80 written anywhere we could find — the state on that descriptor lives at
+0x74.

## Determinism

All RVAs and line numbers above are directly cited from
`/tmp/sqlpal_full.txt`. The writer is not in any undecoded function — both
FUN_0x380110 (writer) and FUN_0x37f128 (caller chain) have been fully walked.
No follow-up wave needed to bound an undecoded function.
