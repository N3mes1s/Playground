# WAVE-52b — `slot_descriptor[+0x78]` writer (and the framing correction)

All citations are line numbers in `/tmp/sqlpal_full.txt`.

## TL;DR

The wave-50a / wave-51 framing of the gap is **wrong**. The `+0x78` field
that FUN_0x380708 asserts equal to `vms` is **NOT on the slot descriptor**
— it is on the **PE-image descriptor `M`** (the heap chunk returned by
`FUN_0x37b2f0` and populated by `FUN_0x381d8c`). The slot descriptor's
`+0x78` is a separate field — a page-count accumulator initialised to 0
and incremented by `FUN_0x3804b8`, never compared against `vms`.

The writer of `M[+0x78] = vms` is at:

| Item                  | Value                                                   |
|-----------------------|---------------------------------------------------------|
| RVA of write          | `0x37e28e`                                              |
| Line of write         | **436050** (`mov %r10,0x78(%rcx)`)                      |
| Function              | `FUN_0x37e1f0` (already fully decoded in WAVE48_fun_37e1f0.md) |
| Source register       | `r10`, set from caller's `rdx` at line 436024           |
| Source value          | **`vms`** (process descriptor pointer)                  |
| Path                  | mandatory — every `FUN_0x381d8c` invocation flows here  |

## Re-reading FUN_0x380708 — what the assert actually checks

Lines 438526-438536 (RVA 0x380708 entry through the assert):

```
380708:  mov  %rbx,0x8(%rsp)         ; save rbx
38070d:  mov  %rsi,0x10(%rsp)        ; save rsi
380712:  push %rdi
380713:  sub  $0x50,%rsp
380717:  mov  (%rdx),%rax            ; rax = *rdx    <-- arg2 is a POINTER TO a pointer
38071a:  xor  %ebx,%ebx
38071c:  mov  0x60(%rcx),%r8         ; r8  = arg1[+0x60]    (= slot[+0x60] = vms)
380720:  mov  %rdx,%rdi
380723:  mov  %rcx,%rsi
380726:  cmp  %r8,0x78(%rax)         ; cmp vms , (*rdx)[+0x78]
38072a:  je   0x380757               ; pass
38072c:  test %r8,%r8                ; (or vms == 0)
38072f:  je   0x380757
380731:  call 0x3a0880               ; __fastfail
...
```

So the assert is **`(*rdx)[+0x78] == arg1[+0x60]`**, i.e.
`(*rdx)[+0x78] == vms`. The dereference `*rdx` makes `*rdx` itself a
pointer to a different descriptor.

### What `*rdx` actually is at this call site

Caller `FUN_0x37cf68`:

```
37d1dc:  call 0x381d8c          ; line 434811 — returns r15-derived PE-image desc M
37d1e1:  mov  %rsi,%rdx
37d1e4:  mov  %rax,0x50(%rbp)   ; line 434813 — store M ptr at rbp+0x50
37d1e8:  mov  %rsi,%rcx
37d1eb:  mov  %rax,%rbx
37d1ee:  call 0x208b0c          ; (interlocked op on rsi pair)
37d1f3:  lea  0x48(%r13),%rcx
37d1f7:  mov  %rbx,%rdx         ; rdx = M
37d1fa:  call 0x37d23c          ; vms-list insert (writes M[+0x08], M[+0x18])
37d1ff:  mov  $0x2,%edx
37d204:  mov  %rbx,%rcx
37d207:  call 0x37e4c0          ; M[+0x74] = 2
37d20c:  lea  0x50(%rbp),%rdx   ; line 434823 — rdx = &local@rbp+0x50
37d210:  mov  %rdi,%rcx         ; rcx = rdi = SLOT desc
37d213:  call 0x380708          ; line 434825 — AVL insert
```

Therefore at `FUN_0x380708` entry: `rdx = &(rbp+0x50)`, and
`*rdx = [rbp+0x50] = M` (the PE-image descriptor returned by 0x381d8c).

The assert is **`M[+0x78] == vms`**, not `slot[+0x78] == vms`.

This corrects the wave-50a/51 mis-attribution in
`WAVE51_MASTER_slot_ctor.md` (rows for `+0x78` and the
"Open items carried to Wave-52" entry). The slot descriptor's `+0x78`
is a separate field — see "What slot[+0x78] really is" below.

## The writer chain for `M[+0x78] = vms`

```
FUN_0x37cf68
  rdi := FUN_0x37f128(...)      ; line 434727 — slot descriptor
  r15 := FUN_0x37b2f0(vms, sz)  ; line 434790 — heap-alloc PE-image desc (zeroed by memset)
  call FUN_0x381d8c             ; line 434811
       rcx = r15 = M (descriptor)
       rdx = r13 = vms              <-- vms is passed in rdx
       r8  = rbx = image_base
       r9  = rsi = request_va
    -> FUN_0x381d8c
         entry preserves rdx (no clobber before calling 0x3812cc)
         call FUN_0x3812cc       ; line 440131
              rcx = M, rdx = vms, r8 = image_base, r9 = request_va
           -> FUN_0x3812cc
                line 439385: mov %rdx,%rbp     ; saves vms in rbp (preserved register)
                line 439386: mov %rcx,%rbx     ; rbx = M
                ... preserves rcx,rdx until ...
                line 439400: mov %r8,%r9       ; r9 = image_base (now)
                line 439401: mov $0x21,%r8d    ; r8 = 0x21 (header-block size)
                line 439403: call FUN_0x3853e4
                     rcx = M (unchanged)
                     rdx = vms (unchanged)
                     r8  = 0x21
                     r9  = image_base
                  -> FUN_0x3853e4
                       line 443997: mov %rcx,%rsi  ; rsi = M, rdx unchanged
                       (no other modification of rdx before the next call)
                       line 444014: call FUN_0x37e1f0
                            rcx = M, rdx = vms
                         -> FUN_0x37e1f0
                              line 436024: mov %rdx,%r10    ; r10 = vms
                              line 436050: mov %r10,0x78(%rcx)  ; **M[+0x78] = vms**
```

Every level above is a **mandatory** step on the alloc path. There
are no conditional branches between FUN_0x37cf68 entering 0x381d8c
and the write at 0x37e28e (the only conditional inside 0x381d8c
gates `FUN_0x3818e8`, which runs **after** 0x3812cc — see line 440131
followed by 440132's `cmpb $0,0x90(%rsp); jne 0x381de5`).

## What `slot[+0x78]` really is (the field we mis-identified)

`slot[+0x78]` is asserted == 0 on alloc (FUN_0x3800ac line 438122) and
incremented by `add %r14,0x78(%rdi)` at line 438425 inside FUN_0x3804b8
(RVA 0x38058a), with `r14` being a page count (caller's `*r8` shifted
right by 16 — see lines 438398, 438407-438409). It is decremented again
by FUN_0x37e... region-release functions (line 438479: `sub %rbx,0x78(%rbp)`
inside FUN_0x3805dc; line 438350: `add %rbx,0x78(%rdi)` inside
FUN_0x3803c4-region) — i.e., a **per-slot allocated-page counter**, not
an owner mirror. There is therefore no remaining gap on `slot[+0x78]`
to attribute to the alloc path; the slot descriptor as built by
FUN_0x37f128 leaves it at 0 and that is the correct initial state.

## Update to wave-51 row table

The `+0x78` row in `WAVE51_MASTER_slot_ctor.md`'s "Final descriptor
layout after FUN_0x37f128 returns" table is correct as-is (UNWRITTEN by
this chain, asserted == 0); the **interpretation** ("owner mirror") was
wrong. Correct semantic: **page-count accumulator**, initial value 0,
later mutated by FUN_0x3804b8 / FUN_0x3805dc as regions are mapped /
unmapped on this slot.

The `+0x78` row in the "Fields still requiring external population"
table at the bottom of WAVE51 is now obsolete — there is no caller
required to write `slot[+0x78] = vms`; the assert at line 438535
operates on a different descriptor.

## Wave-53 follow-ups

None on the slot descriptor. Suggested next probes:

1. **PE-image descriptor field map.** With `M[+0x78] = vms` confirmed,
   walk the rest of M's fields (+0x80, +0x88, +0x90..+0xe0) populated
   by FUN_0x3812cc (lines 439404-439448) and FUN_0x381714 (line 439452,
   per-section mapper). Many of these read by FUN_0x380708's downstream
   path (e.g. `mov 0x28(%rax),%rcx` at line 438554 — AVL key from
   `M[+0x28]`).
2. **Slot descriptor +0x78 lifecycle.** Confirm pairing of writers:
   FUN_0x3804b8 (`add`, alloc), FUN_0x3805dc (`sub`, free) and the
   counter goes back to 0 on slot teardown (so the next alloc's
   FUN_0x3800ac assert at 438122 still passes).

## Citation summary

- `M[+0x78]` writer: `mov %r10,0x78(%rcx)` at RVA `0x37e28e`,
  line 436050, function `FUN_0x37e1f0`. Documented in
  `analysis/WAVE48_fun_37e1f0.md` row "+0x78".
- Call chain producers: lines 434790 (alloc M), 434811 (enter 0x381d8c),
  440131 (enter 0x3812cc), 439403 (enter 0x3853e4), 444014 (enter
  0x37e1f0), 436050 (write).
- Assert consumer: `cmp %r8,0x78(%rax)` at RVA `0x380726`, line 438535,
  function `FUN_0x380708`.
- Slot-descriptor +0x78 writers (a different field): line 438425
  (FUN_0x3804b8, `add`), line 438479 (FUN_0x3805dc, `sub`), line 438350
  (other region helper, `add`).
