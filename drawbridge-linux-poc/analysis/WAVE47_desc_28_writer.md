# Writer of desc[+0x28] (va_base) and desc[+0x30] (size)

All line refs are in `/tmp/sqlpal_full.txt`.

## Confirmed writer for +0x28
- RVA of write: **0x37e25f**
- Function: **FUN_0x37e1f0**
- Instruction: `mov %r9, 0x28(%rcx)`
- Source register: **%r9** (4th-arg register at FUN_0x37e1f0 entry)
- Line: **436039**

## Confirmed writer for +0x30
- RVA of write: **0x37e27b**
- Function: **FUN_0x37e1f0**
- Instruction: `mov %rbp, 0x30(%rcx)`
- Source: **%rbp**, loaded at line 436021 from `0x80(%rsp)` — i.e. arg5 (1st stack arg) at FUN_0x37e1f0 entry
- Line: **436045**

(Bonus, in same function and not asked but useful:
- desc[+0x00] = vtable @0x412d70    (RVA 0x37e256, line 436036)
- desc[+0x08/+0x10/+0x18] = NULL    (lines 436025/436027/436028)
- desc[+0x20] = 1                   (line 436034)
- desc[+0x38] = NULL                (line 436046)
- desc[+0x40] = rbp/rsi quotient    (line 436040)
- desc[+0x48] = esi = page_size     (line 436047)
- desc[+0x4c] = stack[+0x90] u32    (line 436042)
- desc[+0x50] = stack[+0x98] u32    (line 436044)
- desc[+0x58/+0x60] = 0 (xmm)       (line 436118)
- desc[+0x68] = 0                   (line 436119)
- desc[+0x70] = r8d                 (line 436048)
- desc[+0x74] = 1                   (line 436049)
- desc[+0x78] = r10 = original rdx  (line 436050)
- desc[+0x38] = (image_base + ...)  conditional on stack[+0xa8] (line 436126))

## Call chain that delivers the values

```
FUN_0x37cf68 (line 434811)
  rcx = r15 = freshly-zero descriptor (from FUN_0x37b2f0)
  rdx = r13 = vms
  r8  = rbx = image_base   (original arg2 of 37cf68; PE base, validated by reading 0x3c/0x18 of it)
  r9  = rsi = page-aligned-up size  (rsi = (orig r8 + 0xfff) & ~0xfff, line 434681-434683)
  stk+0x20 = r12 = PE optional-header field 0x38 (size-of-image)
  stk+0x28 = ptr to (-0x18(%rbp)) local
  stk+0x30 = byte 0x01 (flag)
  call 0x381d8c
    -> rbx = rcx (descriptor); rdx,r8,r9 untouched
    -> sets up stack args at +0x20 = stk+0x20 of 37cf68 (=r12=size-of-image)
                                +0x28 = const 0xe8
                                +0x30 = byte flag
    call 0x3812cc                                  (line 440131)
      mov %r8,%r9                                  (line 439400) -> r9 = image_base
      mov $0x21,%r8d
      stack arg5 (+0x20) = original r9            (= rsi = page-aligned size) [line 439399]
      stack arg6 (+0x28) = stk[+0x90]              (= 37cf68 stk[+0x20] = r12) [lines 439394/439398]
      stack arg7 (+0x30) = $0x8                    [line 439396]
      call 0x3853e4                                (line 439403)
        rcx,rdx,r8,r9 untouched (rcx still = descriptor; r9 still = image_base)
        forwards stack args 5/6 to its own call    (lines 444008-444013)
        call 0x37e1f0                              (line 444014)
          mov %r9,0x28(%rcx)                       <-- WRITES desc[+0x28] = image_base
          mov %rbp,0x30(%rcx)  ; rbp from 0x80(%rsp)<-- WRITES desc[+0x30] = page-aligned size
```

## Verification of source values
- **desc[+0x28] source**: r9 register propagates unchanged from FUN_0x3812cc line 439400 (`mov %r8,%r9`)
  through 0x3853e4 (no r9 modification between entry 443986 and call at 444014) into 0x37e1f0.
  The value is **image_base = original arg2 of FUN_0x37cf68 (= PE base)**.
  For sqlpal this is **0x180000000** (the PE preferred ImageBase the loader is mapping).

- **desc[+0x30] source**: stack arg5 propagates as
  `r9 of 0x3812cc -> stk[+0x20] of 0x3853e4 -> stk[+0x20] of 0x37e1f0 -> rbp -> desc[+0x30]`.
  r9 of 0x3812cc = r9 of 0x381d8c = r9 of 0x37cf68's call = **rsi = page-aligned-up SIZE**
  (computed at 0x37cf68 lines 434681-434683 from raw arg3 = original mapping size).

## Why FUN_0x381d8c body itself is not the writer
WAVE47_fun_381d8c.md correctly observed that FUN_0x381d8c writes only desc[+0x00]
(line 440135). The va_base/va_limit pair is set one frame deeper, inside
`FUN_0x3812cc -> FUN_0x3853e4 -> FUN_0x37e1f0`. The agent's callee notes for
FUN_0x3812cc ("assembles a header object on local stack") were misleading: that
function actually mutates the *real* descriptor (rbx = arg1 = rcx) at offsets
0x00, 0x90, 0xb0, 0xb8, 0xc0, 0xc8, 0xd0, 0xe0 (lines 439405-439448) AND, via its
sub-call to 0x3853e4 -> 0x37e1f0, at offsets 0x08, 0x10, 0x18, 0x20, 0x28, 0x30,
0x38, 0x40, 0x48, 0x4c, 0x50, 0x70, 0x74, 0x78. The "auxiliary stack object" is
a red herring — there is no separate stack-resident header struct; the rcx
threaded through the chain is always the heap-allocated descriptor.

## Check of FUN_0x37cf68 lines 434791-434822
No store of any kind to `(%r15+0x28)` or `(%rbx+0x28)` between the alloc at
434790 and the call at 434811. The only writes are to *stack* slots
(434803/434805/434808) and to `0x50(%rbp)` (434813, after 0x381d8c returned).
Confirms: desc[+0x28] is established **inside** the 0x381d8c call.

## Implementation recipe (for our Linux host)
After `chunk = alloc_zero(0xe8)`:
```c
// Identifying header
chunk[+0x00]  = vtable_pointer;          // set in 0x3812cc / 0x37e1f0 / 0x3853e4
                                         // (each layer overwrites; final value
                                         //  is the most-derived vtable)

// VAD-style range
chunk[+0x08]  = 0;                       // forward link?
chunk[+0x10]  = 0;                       // backward link?
chunk[+0x18]  = 0;                       // owner backptr (filled later by 0x37d23c)
chunk[+0x20]  = 1;                       // state/flag
chunk[+0x28]  = image_base;              // <-- VA_BASE
chunk[+0x30]  = page_aligned_size;       // <-- SIZE (so VA_LIMIT = +0x28 + +0x30)
chunk[+0x38]  = 0;                       // (or image_base + extra, depending on flag)
chunk[+0x40]  = page_aligned_size / page_size;   // page count
chunk[+0x48]  = page_size;               // 0x1000
chunk[+0x4c] = some_u32;                 // mode/protection class
chunk[+0x50]  = some_u32;                // mode/cache attribute
chunk[+0x70]  = 0x21;                    // type tag (literal from 0x3812cc line 439401)
chunk[+0x74]  = 1;                       // active flag
chunk[+0x78]  = vms_pointer;             // owning vms (rdx of 0x37cf68)

// PE-image-specific
chunk[+0x80]  = sizeof_pe_headers;       // u16 (from 0x3853e4 line 444020)
chunk[+0x82]  = (sizeof_pe_headers + 0xf) & 0xfff0;  // aligned (line 444024-444026)
chunk[+0x88]  = ptr_to_pe_headers_in_chunk;          // (line 444023)
chunk[+0x90]  = derived_vtable_2;        // (set in 0x3812cc line 439413/439428)
chunk[+0xb0]  = unique_id (from atomic ctr); // line 439423
chunk[+0xb8]  = image_base;              // (rsi in 0x3812cc, line 439443)
chunk[+0xc0]  = page_aligned_size;       // (rdi in 0x3812cc, line 439444)
chunk[+0xc8]  = -0x758(%rbp) value;      // some caller-frame value, line 439440
chunk[+0xd0]  = 0 / xmm copy;            // 16-byte field, lines 439425/439448
chunk[+0xe0]  = self pointer;            // lines 439442
```

After this is done you can call the equivalent of FUN_0x381714 (line 439452,
takes rcx=descriptor, rdx=desc[+0x28], r8=desc[+0x30]) which performs the
actual page-table mapping for the VA range.
