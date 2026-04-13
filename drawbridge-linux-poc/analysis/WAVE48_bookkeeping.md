# Bookkeeping chain: FUN_0x380708, FUN_0x37d23c, FUN_0x208b0c

Final bookkeeping tail of FUN_0x37cf68 (entry line 434669) between the
FUN_0x381d8c descriptor-producer call (line 434811) and the stack cleanup
(lines 434830-434834). Call sites:

- `call 0x208b0c` at line 434816 (address 0x37d1ee)
- `call 0x37d23c` at line 434819 (address 0x37d1fa)
- `call 0x37e4c0` at line 434822 (address 0x37d207) -- sets descriptor+0x74 = 2 (state transition, see WAVE48_fun_37e4c0.md)
- `call 0x380708` at line 434825 (address 0x37d213)

Register state just prior to this tail (lines 434811-434814):

- `rdi  = -0x28(%rbp)` -- pointer returned by FUN_0x37f128 (line 434728);
  this is the per-process "context/PROC" object keyed from vms->0xa8.
- `rsi  = scope size` (in bytes, result of FUN_0x37b2f0 at line 434790),
  also used as the telemetry counter argument.
- `rbx  = rax`, the freshly allocated descriptor pointer returned by
  FUN_0x381d8c (stored into `0x50(%rbp)` at line 434813 and into `rbx`
  at line 434815).
- `r13  = vms` (moved in from `rcx` at line 434685 prologue).
- `rbp` = frame pointer (local storage area).

## FUN_0x208b0c (0x37cf68:0x37d1ee)

Entry: line 11340 (address 0x208b0c).
Args at call site (lines 434812-434814): `rcx = rsi` (scope size),
`rdx = rsi` (scope size) -- both arguments are the same byte count.

Body (lines 11340-11358):

- line 11346: `lock xadd %rcx,[0x653ed8]` -- atomically adds `rcx` (scope
  size, positive) to global counter `0x653ed8`.
- line 11348: `neg %rcx`.
- line 11349: `lock xadd %rcx,[0x662cf8]` -- atomically subtracts the
  scope size from global `0x662cf8`.
- line 11351: `call 0x2747d4` -- a notification / threshold hook fired
  whenever the first-arg branch was taken (global accounting probe).
- line 11354: `lock xadd %rbx,[0x662d10]` -- atomically adds `rdx`
  (scope size) to global `0x662d10`.

Writes:

- global `0x653ed8` += scope_size
- global `0x662cf8` -= scope_size
- global `0x662d10` += scope_size
- callee FUN_0x2747d4 may touch further globals (threshold / budget
  trigger when the first counter is nonzero).

Callees: `FUN_0x2747d4` (line 133917).

Purpose: system-wide memory accounting counters -- one pair tracks
"charged bytes" (0x653ed8 up, 0x662cf8 down) and the second tracks a
"committed/reserved" bucket (0x662d10). This is the bookkeeping half of
the reservation that FUN_0x381d8c consumed: the scope has now been
allocated to a descriptor, so reverse the prior reservation and charge
the committed pool.

## FUN_0x37d23c (0x37cf68:0x37d1fa)

Entry: line 434841 (address 0x37d23c).
Args at call site (lines 434817-434818): `rcx = r13+0x48` (i.e.
`vms->0x48`) and `rdx = rbx` (the descriptor returned by 0x381d8c). The
vms field at +0x48 is a list-head header: layout is
`{ lock@+0x10, Flink@+0x8, Blink@+0x0, count@+0x14 }` (see writes
below).

Body (lines 434841-434861):

- line 434844: `rdi = rcx` (list-head pointer, vms+0x48).
- line 434845: `rbx = rdx` (descriptor).
- lines 434846-434847: `rcx = rdi+0x10`; `call 0x3885c0` -- acquires the
  spinlock at `vms+0x48+0x10` (function 0x3885c0 at line 447581 is a
  plain test-and-set spin acquire).
- line 434849: `r8 = rbx+0x8` (descriptor+0x8: the LIST_ENTRY field
  embedded in the descriptor).
- line 434848/434850: `[r8+0x8] = [rdi+0x8]` -- new node's Flink =
  list-head's Flink.
- lines 434851-434852: `[[rdi+0x8]] = r8` -- old-Flink's Blink = new
  node.
- line 434853: `[rdi+0x8] = r8` -- list-head's Flink = new node.
- line 434854: `[r8] = rdi` -- new node's Blink = list-head.
- line 434855: `incl [rdi+0x14]` -- list count at vms+0x48+0x14 += 1.
- line 434856: `[rbx+0x18] = rdi` -- descriptor+0x18 = back-pointer to
  the list-head (i.e. to `vms+0x48`), so the descriptor knows which
  list it belongs to.
- line 434858: `movl $0, [rdi+0x10]` -- release the spinlock.

Writes:

- on vms (`r13`, list-head at vms+0x48):
  - vms+0x48+0x08 (Flink) = &descriptor+0x8
  - vms+0x48+0x14 (count) += 1
  - vms+0x48+0x10 (lock) = 1 then 0 (acquire/release)
- on descriptor (`rbx`):
  - descriptor+0x08 (LIST_ENTRY Blink) = old-Flink
  - descriptor+0x10 (LIST_ENTRY Flink) via r8+0x8 is what just wrote to
    old-Flink's Blink -- i.e. descriptor's own Flink is old Flink of
    head
  - descriptor+0x18 = vms+0x48 (owning list-head back-pointer)
- on the prior head's old Flink node: its Blink = &descriptor+0x8.

Callees: `FUN_0x3885c0` (spinlock acquire, line 447581).

Purpose: inserts the newly minted descriptor into the per-vms
descriptor list rooted at `vms+0x48`, under the list's own spinlock.
This is the canonical LIST_ENTRY-style double-linked-list insert-head,
plus a back-pointer so deletion (see the sibling function at line
434903, 0x37d300) can find the head cheaply, and a +1 to the list's
count field.

## FUN_0x380708 (0x37cf68:0x37d213)

Entry: line 438526 (address 0x380708).
Args at call site (lines 434823-434824): `rcx = rdi` and
`rdx = rbp+0x50`. In FUN_0x37cf68 at this point `rdi = -0x28(%rbp)` is
the per-process/context object returned by FUN_0x37f128 (line 434728),
and `rbp+0x50` is the local slot storing the descriptor pointer (the
same `rbx` just written at line 434813 via `mov %rax,0x50(%rbp)`). So
the two arguments are `(process_ctx, &descriptor_slot)`.

Body (lines 438526-438579):

- line 438530: `rax = *rdx` -- load the descriptor pointer from the
  caller's slot.
- line 438531: `rbx = 0`.
- line 438532: `r8 = [rcx+0x60]` -- a field of the process_ctx used as
  an owning/scope tag.
- line 438533: `rdi = rdx` (saved slot address); `rsi = rcx`
  (process_ctx).
- line 438535: `cmp [rax+0x78], r8` -- the descriptor at +0x78 must
  carry the same owner tag as `process_ctx+0x60`; if not (and r8 != 0)
  the assertion macro at line 438539 fires
  (`FUN_0x3a0880`/`FUN_0x218494` pair, source ref file `0x46f8a0`,
  check id 0x1e3, line 438545).
- line 438547: `ecx = 0x2000`, `call 0x2082a0` -- _alloca (line 10782)
  reserves a 0x2000-byte on-stack scratch area at `rsp+0x30`.
- line 438548-438550: `rdx = rsi+0x20`, `rcx = rsp+0x30`,
  `call 0x380ef8` -- copies / captures a lock-state record from
  `process_ctx+0x20` into the on-stack scratch (paired with the matching
  release at line 438574).
- line 438551: `rax = *rdi` -- reload the slot value.
- line 438552: `*rdi = rbx` (= 0) -- **clears the caller's descriptor
  pointer slot**. This transfers ownership out of the local: the caller
  stack slot `0x50(%rbp)` now reads zero, so `FUN_0x379788` /
  `FUN_0x3797fc` at the cleanup tail (lines 434827, 434829) won't
  double-release the descriptor.
- lines 438553-438569: walk the AVL tree rooted at `process_ctx+0x40`
  (`rdx = [rsi+0x40]`) comparing `0x28(rax) = process_ctx+0x28` against
  each node's `-0x30(rdx)` key; on reaching a nil slot with a set
  sibling, `bl = 1` (duplicate-key flag).
- line 438572: `rcx = rsi+0x40`, `r8 = bl`, call `FUN_0x38f75c`
  (line 455440) -- AVL insert using the tree header at
  `process_ctx+0x40`; `r9` carries `rax+0x58` = pointer to the node
  embedded at descriptor+0x58 (this is the in-tree RTL_AVL node of the
  descriptor).
- line 438574: `rcx = rsp+0x30`, `call 0x248dc0` -- release/finalize
  the lock-state record captured at line 438550.

Writes:

- on descriptor (via AVL): the node at descriptor+0x58 is linked into
  the AVL tree whose header lives at process_ctx+0x40.
- on process_ctx (`rsi`):
  - process_ctx+0x40 AVL tree gains a new node (pointers + count
    updated inside FUN_0x38f75c).
  - process_ctx+0x20 lock is taken and released around the tree edit
    (via FUN_0x380ef8 / FUN_0x248dc0).
- on the caller's stack frame (`*rdx` == `rbp+0x50`): the local
  descriptor pointer slot is zeroed so the caller's RAII-style
  destructors will not release the descriptor.
- no writes to vms (`r13`) here.

Callees: `FUN_0x3a0880`+`FUN_0x218494` (assertion pair when owner-tag
mismatch), `FUN_0x2082a0` (_alloca, line 10782), `FUN_0x380ef8`
(line 439097, acquire lock-state / push guard), `FUN_0x38f75c`
(line 455440, AVL insert), `FUN_0x248dc0` (line 83593, pop/release
guard).

Purpose: registers the descriptor into the per-process AVL index keyed
by the process_ctx-side field at +0x28, while taking the process_ctx
lock at +0x20. The descriptor-slot zeroing at line 438552 is the
ownership-handoff step: after this call, cleanup of the `rbp+0x50`
local becomes a no-op and responsibility for the descriptor is now
shared between the per-vms list (installed by FUN_0x37d23c) and the
per-process AVL (installed here).
