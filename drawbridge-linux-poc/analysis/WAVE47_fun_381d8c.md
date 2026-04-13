# FUN_0x381d8c decode

## Entry
RVA: 0x381d8c
Line: 440116 in /tmp/sqlpal_full.txt
Caller context: FUN_0x37cf68 @ 0x37d1dc (line 434811) with
  rcx = result of FUN_0x37b2f0 (a freshly-allocated "module"/PE-image
        descriptor; see line 434790-434791),
  rdx = r13 = vms (process descriptor),
  r8  = rbx = module image base,
  r9  = rsi = page-aligned request_va,
  stack [+0x20] = r12 (image size, line 434808),
  stack [+0x28] = -0x18(%rbp) (xmm0 source pair, lines 434801-434810),
  stack [+0x30] = byte 0x01 (line 434803).

## Instruction flow (verbatim from /tmp/sqlpal_full.txt lines 440116-440163)

| RVA      | Insn                              | Semantic                                                  | Line# |
|----------|-----------------------------------|-----------------------------------------------------------|-------|
| 381d8c   | mov %rsp,%r11                     | frame anchor (Win64 prolog)                               | 440116 |
| 381d8f   | push %rbx                         | save rbx                                                  | 440117 |
| 381d90   | sub  $0x50,%rsp                   | reserve 0x50 stack frame                                  | 440118 |
| 381d94   | mov  0x88(%rsp),%rax              | load stack-arg5 (caller's [rsp+0x28] = lea -0x18(%rbp))   | 440119 |
| 381d9c   | mov  %rcx,%rbx                    | rbx = descriptor (arg1)                                   | 440121 |
| 381d9f   | movups (%rax),%xmm0               | load 16 bytes pointed to by stack-arg5                    | 440122 |
| 381da2   | lea  -0x18(%r11),%rax             | rax = home-area slot 5 (shadow)                           | 440123 |
| 381da6   | mov  %rax,-0x28(%r11)             | store ptr arg into shadow for nested call                 | 440124 |
| 381daa   | mov  0x80(%rsp),%rax              | load stack-arg4 (caller [rsp+0x20] = r12 = image size)    | 440125 |
| 381db2   | movq $0xe8,-0x30(%r11)            | constant 0xe8 stored in shadow (header-block size)        | 440127 |
| 381dba   | mov  %rax,-0x38(%r11)             | image size into shadow slot                               | 440129 |
| 381dbe   | movdqu %xmm0,0x40(%rsp)           | copy 16 bytes (xmm0) onto local stack 0x40(%rsp)          | 440130 |
| 381dc4   | call 0x3812cc                     | initialise auxiliary header object on stack 0x40(%rsp)    | 440131 |
| 381dc9   | cmpb $0x0,0x90(%rsp)              | compare stack-arg6 (the byte 0x01 from caller +0x30) to 0 | 440132 |
| 381dd1   | lea  0x91040(%rip),%rax  # 0x412e18 | rax = vtable pointer constant                           | 440134 |
| 381dd8   | mov  %rax,(%rbx)                  | **WRITE descriptor[+0x00] = vtable @0x412e18**            | 440135 |
| 381ddb   | jne  0x381de5                     | skip helper if flag was non-zero                          | 440136 |
| 381ddd   | mov  %rbx,%rcx                    | rcx = descriptor                                          | 440137 |
| 381de0   | call 0x3818e8                     | run vtable-side init on descriptor                        | 440138 |
| 381de5   | mov  0x30(%rbx),%rax              | rax = descriptor[+0x30] (page size? - unverified)         | 440139 |
| 381de9   | lea  0x60(%rsp),%r8               | r8 = ptr to local out-slot                                | 440140 |
| 381dee   | cmpl $0x2,0x87ea73(%rip) # 0xc00868 | global mode flag == 2 ?                                 | 440141 |
| 381df5   | lea  0x88(%rsp),%rdx              | rdx = ptr to caller's stack-arg5 slot (header ptr)        | 440142 |
| 381dfd   | mov  %rax,0x88(%rsp)              | overwrite that slot with descriptor[+0x30]                | 440144 |
| 381e05   | mov  $0x1,%r9b                    | r9b = 1                                                   | 440146 |
| 381e08   | sete %al                          | al = (mode==2)                                            | 440147 |
| 381e0b   | mov  %rbx,%rcx                    | rcx = descriptor                                          | 440148 |
| 381e0e   | mov  %al,0x20(%rsp)               | shadow byte for callee                                    | 440149 |
| 381e12   | call 0x3814d4                     | **PE-loader: parse MZ/PE, walk sections** (line 439503)   | 440150 |
| 381e17   | test %eax,%eax                    | check NTSTATUS                                            | 440151 |
| 381e19   | jns  0x381e43                     | jump on success                                           | 440152 |
| 381e1b   | call 0x3a0880                     | get telemetry/stack-frame                                 | 440153 |
| 381e20.. | ... assert helpers ...            | assertion-fault path -> 0x218494                          | 440154-440159 |
| 381e43   | mov  %rbx,%rax                    | return descriptor                                         | 440160 |
| 381e46   | add  $0x50,%rsp                   | epilogue                                                  | 440161 |
| 381e4a   | pop  %rbx                         |                                                           | 440162 |
| 381e4b   | ret                               | return descriptor (rax)                                   | 440163 |

## Field writes on descriptor (arg rdx of caller = arg rcx here = rbx)

| Offset | Value                          | RVA of write | Source                                  |
|-------:|--------------------------------|-------------:|------------------------------------------|
| +0x00  | vtable ptr 0x412e18            | 0x381dd8     | line 440135 — `mov %rax,(%rbx)`         |

That is the **only direct write** of FUN_0x381d8c to the descriptor body.
All further writes to descriptor fields happen inside callees:
- FUN_0x3818e8 (line 439788) writes to (%rbx)[+0x90 .. +0xd0] — pathname/string state.
- FUN_0x3814d4 (line 439503) reads from descriptor at +0x28, +0x30, +0x48
  and writes section descriptors via FUN_0x381714 (line 439662) to a
  separate per-section table — NOT to a +va_base/+va_limit pair on the
  module descriptor.

## Field reads on rcx-as-descriptor (rbx) inside this function

| Offset | RVA of read | Purpose                                                   |
|-------:|------------:|------------------------------------------------------------|
| +0x30  | 0x381de5    | loaded into rax then stashed at 0x88(%rsp) for FUN_0x3814d4 (line 440139) |

## Field reads on vms (caller's r13)

NONE inside FUN_0x381d8c. The `vms` pointer that the caller had in r13
is **not passed** to FUN_0x381d8c. The four register args here are
(descriptor, header_ptr, image_base, image_size_or_request_va). The
"vms" never enters this function. (Verified by reading lines 440116-440163;
no use of r13 and no read of any vms-offset.)

## VA-range storage

**NOT STORED HERE.**

FUN_0x381d8c writes exactly ONE descriptor field: the vtable pointer at
offset +0x00 (line 440135). It never writes a base address, a limit,
or an end pointer onto rbx. The image-base value (caller r8 = rbx_caller)
and the size value (caller r12) reach this function only as STACK args at
[rsp+0x80]/[rsp+0x88]; both are forwarded into the auxiliary stack object
at 0x40(%rsp) (lines 440127-440130) and consumed by FUN_0x3812cc and
FUN_0x3814d4 — never written to descriptor[+offset].

Therefore Agent D's wave-46 hypothesis ("MOST LIKELY location where
va_base/va_limit is stored") is **REFUTED** for FUN_0x381d8c.

The va_base / va_limit pair, if it exists in the module-descriptor
struct, is written either:
  - inside FUN_0x37b2f0 / FUN_0x37b3c4 (the descriptor allocator,
    lines 432758, 432820 — sets +0x100 payload slots), or
  - inside FUN_0x37d23c (the post-call list-link, line 434841 — writes
    +0x08 list pointers and +0x18 owner backptr), or
  - is not stored as a packed pair at all; the loader keeps base/size
    in a separate "header object" assembled by FUN_0x3812cc on stack
    (the 16-byte xmm0 image at 0x40(%rsp)).

## Internal callees

| RVA       | Purpose                                                              |
|-----------|----------------------------------------------------------------------|
| 0x3812cc  | constructs the on-stack 0x40(%rsp) header object from (image_base, image_size, ptr-arg) — line 439375 |
| 0x3818e8  | conditional vtable-side init: copies a path/UNICODE_STRING from descriptor[+0x90..+0xd0] into a global; verified at line 439788-439809 |
| 0x3814d4  | PE/COFF parser: validates MZ (0x5a4d) and PE\0\0 (0x4550), walks section table, calls FUN_0x381714 per section to map them — line 439503 |
| 0x3a0880  | telemetry frame (assertion path)                                     |
| 0x218494  | assertion / fail-fast handler                                        |

FUN_0x3814d4 internal note: it reads desc[+0x28] (image base, line 439636)
and desc[+0x48] (page-mask, line 439619) — i.e., descriptor +0x28 already
contains the image base BEFORE FUN_0x381d8c runs. Therefore the va_base
field at desc[+0x28] is established by the caller (FUN_0x37cf68) or by
the allocator FUN_0x37b2f0 — **not by FUN_0x381d8c**.

## Downstream consumers

PE functions that read desc[+0x28] (image base) — i.e., the actual
va_base field if one exists:

| RVA      | Line#  | Context                                                     |
|----------|-------:|-------------------------------------------------------------|
| 0x381e75 | 440182 | `mov 0x28(%rcx),%rdx` — module helper reads image base      |
| 0x3815eb -> via 0x3814d4 | 439636 | `mov 0x28(%rbp),%rdx` — PE-loader uses image base while mapping sections |
| 0x381745 | 439675 | `cmp 0x28(%rcx),%rdx` — section-mapper bounds-check vs image base |
| 0x38179d | 439695 | `add 0x28(%rbx),%rcx` — image base + section size (forms the implicit limit) |
| 0x38208d | 440335 | `mov 0x28(%rbp),%rcx` (in FUN_0x381ef0, the page-table walker) |
| 0x382030 -> 0x3820a1 | 440340 | `lea 0x40000000(%r10),%rax` — implicit limit = base+size, NOT a stored field |

The "limit" is computed everywhere as `base + [+0x30]` (size) on demand;
no stored va_limit field is read by any function inspected. The container
that does the `va_base <= request_va < va_limit` check the wave-39/46
narrative described therefore must use `desc[+0x28]` as base and
`desc[+0x28] + desc[+0x30]` as limit — both fields populated upstream
of FUN_0x381d8c.

## Summary for the wave-47 candidate matrix

- FUN_0x381d8c: vtable installer + PE-loader entrypoint.
  Writes desc[+0x00] only. NOT the va_base/va_limit writer.
- FUN_0x37b2f0 / 0x37b3c4: descriptor allocator (lines 432758, 432820).
  Most likely site for the initial desc[+0x28]=base, desc[+0x30]=size
  store — confirm in next wave.
- FUN_0x37e518 (already analysed in WAVE47_fun_37e518.md): VA-mapping
  primitive that may patch desc[+0x28] indirectly.
