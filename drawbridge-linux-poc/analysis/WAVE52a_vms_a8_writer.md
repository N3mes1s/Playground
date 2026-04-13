# WAVE-52a — Writer of `vms[+0xa8]` (pool-descriptor install)

Scope: first writer of `vms[+0xa8]`. No struct decode beyond that.
Citations: `/tmp/sqlpal_full.txt` line numbers.

## Writer

- **Function**: `FUN_0x379c14` (a `VmModuleState` field-initializer)
- **Write**: line **431270**, RVA **0x379c9e** —
  `mov %rax,0xa8(%rcx)` with `%rcx` = vms (confirmed by the function's
  entry at 0x379c14 zeroing +0x00/+0x08/+0x0c/+0x10/+0x18/+0x20/+0x50
  and building self-linked list heads at +0x48/+0x60/+0x78/+0x90).

## Source of the stored value — NOT an allocator call

Immediate producer (lines 431261, 431267-431269):

```
379c7c:  mov    0x886bf5(%rip),%rdx     # 0xc00878   ; rdx = global pool-array base
...
379c93:  imul   $0x68,%r9,%rax          ; rax = r9 * 0x68
379c97:  add    $0x8,%rax                ; rax += 0x8
379c9b:  add    %rdx,%rax                ; rax = [0xc00878] + r9*0x68 + 8
379c9e:  mov    %rax,0xa8(%rcx)          ; vms[+0xa8] = &desc_array[r9].field_0x8
```

Where `%r9 = movslq %edx` (line 431 block at RVA 0x379c17), i.e. the second
parameter (`edx`) of FUN_0x379c14.

- **Descriptor-array stride**: `0x68`. **Offset into entry stored**: `+0x8`.
  So Wave-51's `[[vms+0xa8]+0x10]` (slot-pool base) maps to
  `desc_array[r9]+0x18`; pool+0x40 lock -> entry+0x48; pool+0x28 cap -> +0x30.

## The global `0xc00878` is populated by the VM init entry

In `FUN_0x37f700` (VM init, starts line 437482 / RVA 0x37f700):

- Line 437649, RVA **0x37f984**:
  `mov %rbx,0x880eed(%rip)   # 0xc00878`
  installs `%rbx` (the one combined VM allocation — see sizing below) as
  the global pool-array base.
- Line 437658, RVA 0x37f99e: `call 0x379c14` — invokes FUN_0x379c14 with
  `%rcx = %rbx` (vms) and `%edx = 1` (set at 0x37f98b). So the FIRST write
  of `vms[+0xa8]` in boot is effectively `vms[+0xa8] = rbx + 1*0x68 + 8 =
  rbx + 0x70`. The pool descriptor therefore LIVES INSIDE the same
  contiguous allocation as vms, at offset 0x70..0x70+0x68 of that block.

(Second caller of FUN_0x379c14: 0x266e1f line 118593 — out of scope.)

## Allocation size (for the combined vms/pool/bitmap block)

The block pointed to by `%rbx` is computed earlier in FUN_0x37f700
(lines ~437531-437565, RVA 0x37f7fd..0x37f89e). Symbolic size:

```
size = 0xe8                                    ; header
     + align8( (arg_rcx + 0x3f) >> 3 )         ; bitmap #1 (masked)
     + align8( ((arg_rcx >> 3)  & mask) )      ; bitmap #2 (masked)
     + 0x88 * arg_rcx                          ; slot array A (stride 0x88)
     + 0x88 * arg_rdi                          ; slot array B (stride 0x88)
     ; then rounded up + page-aligned (and    $0xfffffffffffff000,%r15)
```

Key numeric constants visible: `0xe8` (header), `0x88` (per-slot stride,
matches Wave-51), `0x68` (pool-descriptor-array stride — newly discovered
here), `0xfff`/`0xf` alignment masks, `0x80000000` sanity cap
(line 437557, `cmp $0x80000000,%r15`). The allocator call itself is NOT
in this region — vms/`%rbx` was produced earlier in the function; this
wave does not trace it further.

## Note for wave-53

Decode FUN_0x379c14 in full: it is the canonical VmModuleState
initializer. All `vms+0xNN` field writes happen here (or via its
sub-helpers). In particular, decode the pool-descriptor sub-struct at
`[0xc00878] + r9*0x68` — that's the 0x68-byte record whose field +0x8 is
exposed to callers as `[vms+0xa8]`, and whose fields +0x18, +0x28, +0x38,
+0x40, +0x48 correspond (shifted by +0x8) to Wave-51's pool offsets
+0x10, +0x20, +0x30, +0x38, +0x40.
