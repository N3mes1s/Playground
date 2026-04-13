# FUN_0x37e1f0 full body decode

## Entry
RVA: 0x37e1f0
Line: 436009 (/tmp/sqlpal_full.txt)
Args (Win64 ABI):
- rcx = descriptor pointer (stored into rbx at line 436033)
- rdx = caller-provided ptr (saved into r10 at line 436024, later written to desc+0x78)
- r8  = 32-bit flag/value (written as r8d to desc+0x70 at line 436048)
- r9  = image_base (written to desc+0x28 at line 436039; copied to r14 at line 436031)
- [rsp+0x80] = page_aligned_size (loaded into rbp at line 436021)
- [rsp+0x88] = page_size / divisor (loaded into rsi at line 436018)
- [rsp+0x90] = dword (written to desc+0x4c at line 436042)
- [rsp+0x98] = dword (written to desc+0x50 at line 436044)
- [rsp+0xa0] / [rsp+0xa8] = optional add-offset + flag byte (lines 436120-436126)

## Instruction flow (full table)
| RVA      | Line   | Insn                                         | Purpose |
|----------|--------|----------------------------------------------|---------|
| 0x37e1f0 | 436009 | mov  %rbx,0x8(%rsp)                          | save rbx (home) |
| 0x37e1f5 | 436010 | mov  %rbp,0x10(%rsp)                         | save rbp |
| 0x37e1fa | 436011 | mov  %rsi,0x20(%rsp)                         | save rsi |
| 0x37e1ff | 436012 | push %rdi                                    | prologue |
| 0x37e200 | 436013 | push %r12                                    | prologue |
| 0x37e202 | 436014 | push %r13                                    | prologue |
| 0x37e204 | 436015 | push %r14                                    | prologue |
| 0x37e206 | 436016 | push %r15                                    | prologue |
| 0x37e208 | 436017 | sub  $0x30,%rsp                              | alloc locals |
| 0x37e20c | 436018 | mov  0x88(%rsp),%rsi                         | rsi = arg5 (page_size/divisor) |
| 0x37e214 | 436020 | lea  0xf1645(%rip),%r13 # 0x46f860           | r13 = &assert-file-name string |
| 0x37e21b | 436021 | mov  0x80(%rsp),%rbp                         | rbp = arg4 (page_aligned_size) |
| 0x37e223 | 436023 | xor  %r15d,%r15d                             | r15 = 0 (NULL constant) |
| 0x37e226 | 436024 | mov  %rdx,%r10                               | r10 = arg2 (saved for +0x78) |
| 0x37e229 | 436025 | mov  %r15,0x8(%rcx)                          | desc[+0x08] = 0 |
| 0x37e22d | 436026 | mov  $0x1,%r12d                              | r12 = 1 (true/flag const) |
| 0x37e233 | 436027 | mov  %r15,0x10(%rcx)                         | desc[+0x10] = 0 |
| 0x37e237 | 436028 | mov  %r15,0x18(%rcx)                         | desc[+0x18] = 0 |
| 0x37e23b | 436029 | xor  %edx,%edx                               | clear edx (for div) |
| 0x37e23d | 436030 | mov  %r12d,0x70(%rsp)                        | local = 1 |
| 0x37e242 | 436031 | mov  %r9,%r14                                | r14 = image_base |
| 0x37e245 | 436032 | mov  0x70(%rsp),%eax                         | eax = 1 |
| 0x37e249 | 436033 | mov  %rcx,%rbx                               | rbx = descriptor |
| 0x37e24c | 436034 | mov  %eax,0x20(%rcx)                         | desc[+0x20] = 1 (state/tag) |
| 0x37e24f | 436035 | lea  0x94b1a(%rip),%rax # 0x412d70           | rax = &vtable @ 0x412d70 |
| 0x37e256 | 436036 | mov  %rax,(%rcx)                             | desc[+0x00] = vtable 0x412d70 |
| 0x37e259 | 436037 | mov  %rbp,%rax                               | rax = page_aligned_size |
| 0x37e25c | 436038 | div  %rsi                                    | rax = size / page_size |
| 0x37e25f | 436039 | mov  %r9,0x28(%rcx)                          | desc[+0x28] = image_base |
| 0x37e263 | 436040 | mov  %rax,0x40(%rcx)                         | desc[+0x40] = size/page_size (page count) |
| 0x37e267 | 436041 | mov  0x90(%rsp),%eax                         | eax = arg6 dword |
| 0x37e26e | 436042 | mov  %eax,0x4c(%rcx)                         | desc[+0x4c] = arg6 dword |
| 0x37e271 | 436043 | mov  0x98(%rsp),%eax                         | eax = arg7 dword |
| 0x37e278 | 436044 | mov  %eax,0x50(%rcx)                         | desc[+0x50] = arg7 dword |
| 0x37e27b | 436045 | mov  %rbp,0x30(%rcx)                         | desc[+0x30] = page_aligned_size |
| 0x37e27f | 436046 | mov  %r15,0x38(%rcx)                         | desc[+0x38] = 0 (conditionally overwritten below) |
| 0x37e283 | 436047 | mov  %esi,0x48(%rcx)                         | desc[+0x48] = page_size (dword) |
| 0x37e286 | 436048 | mov  %r8d,0x70(%rcx)                         | desc[+0x70] = arg3 dword (flags) |
| 0x37e28a | 436049 | mov  %r12d,0x74(%rcx)                        | desc[+0x74] = 1 |
| 0x37e28e | 436050 | mov  %r10,0x78(%rcx)                         | desc[+0x78] = arg2 (saved rdx) |
| 0x37e292 | 436051 | cmp  $0x1000,%rsi                            | assert page_size >= 0x1000 |
| 0x37e299 | 436052 | jae  0x37e2bd                                | skip fastfail if ok |
| 0x37e29b | 436053 | call 0x3a0880                                | __fastfail (int 0x2c) |
| 0x37e2a0 | 436054 | mov  $0x354,%r9d                             | assert line #852 |
| 0x37e2a6 | 436055 | mov  %r15,0x20(%rsp)                         | |
| 0x37e2ab | 436056 | mov  %r13,%r8                                | filename |
| 0x37e2ae | 436057 | lea  0xf584b(%rip),%rdx # 0x473b00           | msg "PageSize >= 0x1000" |
| 0x37e2b5 | 436058 | mov  %r12d,%ecx                              | |
| 0x37e2b8 | 436059 | call 0x218494                                | assert-report |
| 0x37e2bd | 436060 | lea  -0x1(%rsi),%rdi                         | rdi = page_size-1 (mask) |
| 0x37e2c1 | 436061 | test %rdi,%rsi                               | assert page_size is pow2 |
| 0x37e2c4 | 436062 | je   0x37e2e8                                | |
| 0x37e2c6 | 436063 | call 0x3a0880                                | __fastfail |
| 0x37e2cb | 436064 | mov  $0x355,%r9d                             | assert line #853 |
| 0x37e2d1 | 436065 | mov  %r15,0x20(%rsp)                         | |
| 0x37e2d6 | 436066 | mov  %r13,%r8                                | |
| 0x37e2d9 | 436067 | lea  0xf5d58(%rip),%rdx # 0x474038           | msg |
| 0x37e2e0 | 436068 | mov  %r12d,%ecx                              | |
| 0x37e2e3 | 436069 | call 0x218494                                | assert-report |
| 0x37e2e8 | 436070 | test %rdi,%r14                               | assert image_base page-aligned |
| 0x37e2eb | 436071 | je   0x37e30f                                | |
| 0x37e2ed | 436072 | call 0x3a0880                                | __fastfail |
| 0x37e2f2 | 436073 | mov  $0x356,%r9d                             | assert line #854 |
| 0x37e2f8..0x37e2e3 | 436074-436078 | setup + assert-report           | |
| 0x37e30f | 436079 | test %rdi,%rbp                               | assert size page-aligned |
| 0x37e312 | 436080 | je   0x37e336                                | |
| 0x37e314..0x37e331 | 436081-436087 | __fastfail + assert-report (#0x357) | |
| 0x37e336 | 436088 | test %r14,%r14                               | assert image_base != 0 |
| 0x37e339 | 436089 | jne  0x37e35d                                | |
| 0x37e33b..0x37e358 | 436090-436096 | __fastfail + assert-report (#0x358) | |
| 0x37e35d | 436097 | test %rbp,%rbp                               | assert size != 0 |
| 0x37e360 | 436098 | jne  0x37e384                                | |
| 0x37e362..0x37e37f | 436099-436105 | __fastfail + assert-report (#0x359) | |
| 0x37e384 | 436106 | mov  0x20(%rbx),%eax                         | reload desc[+0x20] |
| 0x37e387 | 436107 | cmp  %r12d,%eax                              | assert == 1 (paranoid check) |
| 0x37e38a | 436108 | je   0x37e3ae                                | |
| 0x37e38c..0x37e3a9 | 436109-436115 | __fastfail + assert-report (#0x35a) | |
| 0x37e3ae | 436116 | xor  %eax,%eax                               | rax = 0 |
| 0x37e3b0 | 436117 | xorps %xmm0,%xmm0                            | xmm0 = 0 |
| 0x37e3b3 | 436118 | movups %xmm0,0x58(%rbx)                      | desc[+0x58..+0x67] = 0 (16 bytes) |
| 0x37e3b7 | 436119 | mov  %rax,0x68(%rbx)                         | desc[+0x68] = 0 |
| 0x37e3bb | 436120 | cmp  %r15b,0xa8(%rsp)                        | if (arg9_byte != 0) |
| 0x37e3c3 | 436122 | je   0x37e3d4                                | |
| 0x37e3c5 | 436123 | mov  0xa0(%rsp),%rcx                         | rcx = arg8 (offset) |
| 0x37e3cd | 436125 | add  %rbx,%rcx                               | rcx = descriptor + offset |
| 0x37e3d0 | 436126 | mov  %rcx,0x38(%rbx)                         | desc[+0x38] = desc + arg8 (self-relative ptr) |
| 0x37e3d4 | 436127 | mov  0x68(%rsp),%rbp                         | restore rbp |
| 0x37e3d9 | 436128 | mov  %rbx,%rax                               | return descriptor |
| 0x37e3dc | 436129 | mov  0x60(%rsp),%rbx                         | restore rbx |
| 0x37e3e1 | 436130 | mov  0x78(%rsp),%rsi                         | restore rsi |
| 0x37e3e6 | 436131 | add  $0x30,%rsp                              | epilogue |
| 0x37e3ea..0x37e3f2 | 436132-436136 | pop r15..rdi                         | epilogue |
| 0x37e3f3 | 436137 | ret                                          | returns descriptor in rax |

## Descriptor field writes (authoritative list)
| Offset | Value (source)                                  | RVA of write | Line#  | Semantic |
|--------|-------------------------------------------------|--------------|--------|----------|
| +0x00  | 0x412d70 (RIP-relative lea)                     | 0x37e256     | 436036 | vtable / type-tag pointer |
| +0x08  | 0 (r15)                                         | 0x37e229     | 436025 | zero |
| +0x10  | 0 (r15)                                         | 0x37e233     | 436027 | zero (list prev?) |
| +0x18  | 0 (r15)                                         | 0x37e237     | 436028 | zero (list next?) |
| +0x20  | 1 (via stack local)                             | 0x37e24c     | 436034 | state/initialized tag (asserted ==1 at line 436107) |
| +0x28  | r9 = image_base                                 | 0x37e25f     | 436039 | va_base |
| +0x30  | rbp = page_aligned_size                         | 0x37e27b     | 436045 | size |
| +0x38  | 0 (r15) initially; optionally (rbx + arg8_offset) | 0x37e27f / 0x37e3d0 | 436046 / 436126 | self-relative aux pointer (only if arg9 byte != 0) |
| +0x40  | rax = page_aligned_size / page_size             | 0x37e263     | 436040 | page_count |
| +0x48  | esi = page_size (dword)                         | 0x37e283     | 436047 | page_size |
| +0x4c  | [rsp+0x90] dword (arg6)                         | 0x37e26e     | 436042 | caller dword (perm/flag) |
| +0x50  | [rsp+0x98] dword (arg7)                         | 0x37e278     | 436044 | caller dword (perm/flag) |
| +0x58  | 0 (xmm0, 16 bytes)                              | 0x37e3b3     | 436118 | zero two quadwords (+0x58, +0x60) |
| +0x60  | 0 (upper half of xmm0 write)                    | 0x37e3b3     | 436118 | zero |
| +0x68  | 0 (rax)                                         | 0x37e3b7     | 436119 | zero |
| +0x70  | r8d (arg3 dword)                                | 0x37e286     | 436048 | flags |
| +0x74  | 1 (r12d)                                        | 0x37e28a     | 436049 | flag (ref count or enabled bit) |
| +0x78  | r10 = original rdx (arg2)                       | 0x37e28e     | 436050 | caller pointer (context) |

Total descriptor size touched: 0x00..0x80 (128 bytes).

## Internal callees
| RVA       | Purpose                              | Lines where called |
|-----------|--------------------------------------|--------------------|
| 0x3a0880  | __fastfail (`int $0x2c`) — defined at line 475782 | 436053, 436063, 436072, 436081, 436090, 436099, 436109 |
| 0x218494  | Assertion/failure reporter (ecx=flag, rdx=msg, r8=file, r9d=line) | 436059, 436069, 436078, 436087, 436096, 436105, 436115 |

(No other calls — function is leaf aside from fast-fail/assert paths.)

## What fields does the PE scheduler/downstream expect this function to have set?

Entire descriptor at offsets 0x00..0x78 is initialized here:
- +0x00 vtable: consumed by any virtual dispatch on this descriptor.
- +0x08 / +0x10 / +0x18: zeroed — these are list-link / owner slots filled in by later code (FUN_0x3853e4 caller is a plausible site).
- +0x20 = 1: "initialized" tag; re-asserted at line 436107 before returning.
- +0x28 va_base and +0x30 size: the core range pair the PE memory/scheduler reads when walking module regions (matches prior wave-47-e note on 436039/436045).
- +0x38: optional self-relative ptr (+offset arg8) — this is the "tail sentinel / next descriptor" link when the caller passes a non-zero flag byte at [rsp+0xa8]. Used by list-walkers.
- +0x40 page_count: derived (size / page_size); downstream iterators over page arrays use this.
- +0x48 page_size (dword), +0x4c / +0x50 caller dwords: permission / attribute fields passed from caller.
- +0x58..+0x68: zeroed (three qwords) — usage-counters / lock / spare fields cleared on fresh init.
- +0x70 flags, +0x74 = 1 (enabled), +0x78 context pointer: consumed by scheduler hooks when the descriptor is unlinked / torn down.

Cross-reference pointers for later waves to verify (search /tmp/sqlpal_full.txt for readers):
- Offset +0x28 / +0x30 pair — scan around 0x2056e0+ and 0x3756a3+ for `mov 0x28(%reg),...` / `mov 0x30(%reg),...` sequences that consume the va_base/size produced here.
- Offset +0x00 vtable at 0x412d70 — any `call *(%reg)` through a descriptor originating from this allocator hits that vtable.
- Offset +0x20 tag == 1 — used as a sentinel by FUN_0x37e1f0 itself (self-check at line 436107); other consumers likely compare against 1 before trusting the descriptor.
