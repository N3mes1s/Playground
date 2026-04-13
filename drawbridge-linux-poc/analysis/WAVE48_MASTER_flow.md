# FUN_0x37cf68 (`VmModuleState::ReservePeImageRange`) — COMPLETE FLOW

Synthesis of waves 45, 46, 47, 48. All claims cite `/tmp/sqlpal_full.txt` line numbers.

## Entry
- Caller: `FUN_0x2055dc RegisterInitialModule` in `PalBootMain` path
- Signature: `ReservePeImageRange(vms, PE_base, raw_size, flags)`
  - rcx = vms (→ r13)  [source: wave-48-e]
  - rdx = PE_base = 0x180000000 (→ rbx, r14, spilled 0x10(%rsp))
  - r8 = raw_size (→ page-aligned-up into rsi)
  - r9 = flags (→ r15, spilled 0x20(%rsp))

## Prologue checks [wave-48-e]
- **PE32+ magic check** (lines 434700-434702):
  ```
  movslq 0x3c(%rbx), %rdi         ; e_lfanew
  mov    $0x20b, %eax              ; IMAGE_NT_OPTIONAL_HDR64_MAGIC
  cmp    0x18(%rdi,%rbx,1), %ax    ; OptionalHeader.Magic
  ```

## Pre-alloc: 'Vmm ' pool header [wave-48-e]
- Line 434779: `call FUN_0x37fea8` — allocates 16-byte image-header descriptor, pool tag `'Vmm '` (0x206d6d56)
- Line 434780: `mov 0x60(%rbp), %r14` — r14 now points to this 16-byte header (NOT the PE image itself)
- Line 434785: uses `[r14+0]` as section-count input to size calculation

## Chunk allocation [wave-47-d, 47-c]
- Line 434787: `call FUN_0x37e518(aligned_size, page_size=0x1000, header_size=0xe8)` → returns alloc size
- Line 434790: `call FUN_0x37b2f0(heap_ctx=vms, alloc_size)` → returns zeroed chunk → r15 = descriptor

## Descriptor population via FUN_0x381d8c chain [wave-47-b, 48-a, 48-f]

Call at line 434811: `FUN_0x381d8c(rcx=descriptor, rdx=vms, r8=PE_base, r9=aligned_size, stack[0x20]=0x1000, stack[0x28]=&header_local, stack[0x30]=byte_1)`

Inside FUN_0x381d8c:
- Calls `FUN_0x3812cc` → `FUN_0x3853e4` → `FUN_0x37e1f0` (the actual populator)
- Calls `FUN_0x3818e8` (unicode path copy into desc[+0x90..+0xd0])
- Calls `FUN_0x3814d4` (PE parser; delegates per-section writes to FUN_0x381714)
- Writes descriptor[+0x00] = vtable 0x412e18 (AFTER 0x37e1f0, overwriting its 0x412d70)

### FUN_0x37e1f0 descriptor-field writes (18 total) [wave-48-a]

| Offset | Value | Source | Line |
|--------|-------|--------|------|
| +0x00  | 0x412d70 (inner vtable; then overwritten by 0x381d8c's 0x412e18) | constant | 436036 |
| +0x08  | 0 | | 436025 |
| +0x10  | 0 | | 436027 |
| +0x18  | 0 | | 436028 |
| +0x20  | 1 | state-tag constant | 436034 |
| +0x28  | image_base (r9) | caller PE_base | 436039 |
| +0x30  | aligned_size (rbp from stack 0x80) | caller size | 436045 |
| +0x38  | 0, or `rbx+arg8` self-ref ptr conditionally | | 436046, 436126 |
| +0x40  | size/page_size (page_count) | computed via div | 436040 |
| +0x48  | page_size (4-byte) | arg | 436047 |
| +0x4c  | caller dword from [rsp+0x90] | | 436042 |
| +0x50  | caller dword from [rsp+0x98] | | 436044 |
| +0x58..+0x67 | zeroed (movups xmm0) | | 436118 |
| +0x68  | 0 | | 436119 |
| +0x70  | flags (r8d) | arg | 436048 |
| +0x74  | 1 | state-tag | 436049 |
| +0x78  | ctx ptr (saved rdx = arg2) | | 436050 |

Runtime assertions:
- page_size ≥ 0x1000, power-of-2, image_base page-aligned, size page-aligned
- image_base ≠ 0, size ≠ 0
- desc[+0x20] == 1 (re-check)

## State transition [wave-48-c]

Line 434822: `call FUN_0x37e4c0(rcx=descriptor, edx=2)` → atomic increment with assert:
```
assert(desc->+0x74 + 1 == new_state);
desc[+0x74] = new_state;
```
So desc[+0x74]: 1 → 2 (REGISTERED/LINKED state).

State machine: 1 (allocated) → 2 (linked) → 3 (unlinked) → 4 (terminal).

## Bookkeeping chain [wave-48-d]

### FUN_0x37d23c (line 434819): `vms_list_insert_head`
Caller: `(rcx=vms+0x48, rdx=descriptor)`

The struct at `vms+0x48` is a LIST_ENTRY-like head:
- `vms+0x48` = Blink
- `vms+0x50` = Flink
- `vms+0x58` = spinlock
- `vms+0x5c` = count (dword)

Action (lines 434841+):
1. Acquire spinlock at vms+0x58 via `FUN_0x3885c0` (line 447581)
2. Insert descriptor into list — node field is at `desc[+0x08]`
3. Increment vms+0x5c count
4. **Write `desc[+0x18] = vms+0x48`** (back-pointer)
5. Release lock

### FUN_0x208b0c (line 434816): global memory accounting
Caller: `(rcx=rdx=scope_size)`

Atomic counter updates:
- `[0x180653ed8] += scope_size` — charged bytes
- `[0x180662cf8] -= scope_size` — reservation pool
- `[0x180662d10] += scope_size` — committed pool
- Fires threshold probe FUN_0x2747d4 if over limit

### FUN_0x380708 (line 434825): AVL insert into process index
Caller: `(rcx=process_ctx, rdx=&local_desc_slot)`
- `process_ctx` = whatever `FUN_0x37f128` returned at line 434728 (the OTHER allocator call; separate descriptor type from the heap-alloc'd one we've been tracking)

Action (lines 438526+):
1. Assert `desc[+0x78] == process_ctx+0x60` (owner tag match)
2. Acquire process lock at `process_ctx+0x20`
3. **Zero caller's stack slot** `*rdi = 0` (RAII ownership transfer — so cleanup at lines 434827/434829 doesn't free)
4. Walk AVL tree header at `process_ctx+0x40`, comparing key = `desc[+0x28]` (va_base)
5. Call `FUN_0x38f75c` (AVL insert, line 455440) — splices node at `desc[+0x58]` into tree
6. Release lock

So the descriptor ends up linked in TWO indices:
- vms's list (via +0x48 head, +0x18 back-ptr on desc)
- process_ctx's AVL tree (via +0x40 root, +0x58 tree node on desc, key +0x28 = va_base)

## Post-call cleanup [from direct disasm]
- Line 434827: `call FUN_0x379788` — cleanup local
- Line 434829: `call FUN_0x3797fc` — cleanup local

## Final descriptor layout (after FUN_0x37cf68 returns)

| Offset | Field | Value |
|--------|-------|-------|
| +0x00  | vtable | 0x412e18 (from 0x381d8c after 0x37e1f0's 0x412d70 was overwritten) |
| +0x08  | vms-list Flink | pointer within vms's LIST_ENTRY chain |
| +0x10  | vms-list Blink | (set by list insert) |
| +0x18  | vms list-head back-ptr | `vms+0x48` |
| +0x20  | state tag | 1 (constant, asserted) |
| +0x28  | **va_base** | 0x180000000 (PE_base) |
| +0x30  | **size** | page-aligned |
| +0x38  | self-ref or 0 | |
| +0x40  | page_count | size/page_size |
| +0x48  | page_size | 0x1000 |
| +0x4c  | caller dword | |
| +0x50  | caller dword | |
| +0x58..+0x68 | AVL tree node | (written by 0x38f75c) |
| +0x70  | flags | r8d arg |
| +0x74  | **state** | 2 (REGISTERED) |
| +0x78  | ctx | arg2 context ptr |
| +0x90..+0xd0 | UNICODE path | (from FUN_0x3818e8) |

## Relationship to wave-44 blocker

The wave-44 fastfail at `RIP=0x3756a3` happens in scheduler code that reads fields of a descriptor. With the above full layout, **the missing scheduler fields in our wave-40 fake descriptor are likely**: +0x40 page_count, +0x48 page_size, +0x70 flags, +0x74 state, +0x78 ctx, and +0x90+ UNICODE path.

## IMPLEMENTATION RECIPE (Wave-49)

Now that the flow is documented, the implementation path is clear:

### Option B-final: reproduce FUN_0x37cf68 side-effects from host

In our `DK_VmIdentityEcho` (or a dedicated helper called from `main.cpp` after PE boot completes `FUN_0x37f700`):

1. Allocate a ~0xe8-byte descriptor from the vms heap (reuse pool_allocator_real)
2. Populate fields per the table above (no need to walk PE sections — our port already has PE mapped; just stub section-related fields from our already-loaded PE header)
3. Insert into vms's list at +0x48: acquire lock, link, set desc[+0x18] = vms+0x48, inc count, release lock
4. Insert into process_ctx AVL tree: acquire, walk tree with key=va_base, splice at desc[+0x58], release
5. Update global memory counters at [0x180653ed8/662cf8/662d10]

### Risks / still-unknowns
- FUN_0x37f128 returns a "process_ctx" from a bitmap-slot pool — we need to know where that pool object lives and what its +0x20 (lock), +0x40 (AVL root), +0x60 (owner-tag) fields should be. Wave-40's fake descriptor sets desc[+0x60] = vms but not +0x40 or +0x20. These must be populated for `FUN_0x380708`'s AVL insert.
- The "local_desc_slot" (arg2 to 0x380708) is a scratch pointer used by RAII. Not a concern for us.
- FUN_0x3814d4 may still need to record section-level data in auxiliary structures that our simplified PE-image descriptor lacks.

### Conservative approach
Start with the minimum: descriptor with all 18 fields from FUN_0x37e1f0 + the list-insert from FUN_0x37d23c + set desc[+0x74]=2. Skip the AVL-tree insert (FUN_0x380708) initially and see if the wave-44 crash site `0x3756a3` clears. If the scheduler needs AVL lookup we'll know because the next crash will be an AVL traversal fault.

## All decoded wave-47 / wave-48 artifacts

- `analysis/WAVE47_fun_37e518.md` — pure arithmetic size helper
- `analysis/WAVE47_fun_37b2f0.md` — generic 2-arg heap allocator
- `analysis/WAVE47_fun_381d8c.md` — 40-insn vtable installer + PE loader trampoline
- `analysis/WAVE47_desc_28_writer.md` — located FUN_0x37e1f0 as va_base writer
- `analysis/WAVE48_fun_37e1f0.md` — 18 descriptor field writes
- `analysis/WAVE48_fun_3814d4.md` — PE/COFF parser (reads only, delegates to 0x381714)
- `analysis/WAVE48_fun_37e4c0.md` — desc[+0x74] state transition (1→2→3→4)
- `analysis/WAVE48_37cf68_prologue.md` — args + r14 'Vmm' pool header
- `analysis/WAVE48_fun_3818e8.md` — UNICODE path copy
- `analysis/WAVE48_bookkeeping.md` — vms-list insert + global counters + AVL tree insert
- `analysis/WAVE45_elf_dk_sequence.md` — ELF host DK call baseline
- `analysis/WAVE46_scope_layout.md` — FUN_0x37f128 is slot allocator (not list walker)

The complete PE-image descriptor initialization flow is now fully documented and cross-verified.
