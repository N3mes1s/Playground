# FUN_0x3814d4 — PE/COFF parser & section walker

All line refs point to `/tmp/sqlpal_full.txt`.

## Entry
- RVA: **0x3814d4**
- Line: **439503** (prolog `mov %rbx,0x8(%rsp)`)
- Epilog RVA 0x381710 at line 439658.
- Returns NTSTATUS in `%eax` (loaded from `%ebx` at line 439649).

## Argument register binding (from prolog, lines 439512-439517)
| Reg  | Role at entry                                      | Saved into |
|------|----------------------------------------------------|------------|
| rcx  | descriptor (module object)                         | rbp (439517) |
| rdx  | ptr to qword holding image-size (in caller's frame)| rdi (439516) |
| r8   | out-param: where DOS/NT header pointer is stored   | rsi (439515) |
| r9b  | flag byte (1 if called from 381d8c; see 440146)    | r12b (439514) |
| [rsp+0x80] | second flag byte (sete mode==2, line 440149)  | read at 439630 |

Caller (FUN_0x381d8c) details (line 440140-440150): rdx points to a
stack qword pre-loaded with desc[+0x30] (image size); r8 points to a
stack out-slot; r9b=1; stack+0x20 byte = (global_mode==2).

## PE validation checks
| Check                                   | RVA       | Line   | Failure action |
|-----------------------------------------|-----------|-------:|----------------|
| image size >= 0x40 (DOS header)         | 0x38153c  | 439531 | writes 0x40 into *rdi, ebx=0x80000005, bail via 0x3816ef (439535) |
| `*(u16*)MZ == 0x5a4d`                   | 0x381558  | 439537 | ebx=0xc000007b, bail (line 439538/439646) |
| e_lfanew (`MZ[0x3c]`) >= 0              | 0x381562  | 439539 | same bail                                 |
| size >= e_lfanew + 0x108 (NT headers)   | 0x38157d  | 439545 | writes required size into *rdi, 0x80000005 |
| `*(u32*)NT == 0x00004550` ("PE\0\0")    | 0x381593  | 439551 | ebx=0xc000007b (line 439554)              |
| sections fit within mapped size         | 0x3815d0  | 439566 | writes needed size into *rdi, 0x80000005  |

NumberOfSections is loaded from `COFF[+0x06]` -> r14d (line 439556);
SizeOfOptionalHeader from `COFF[+0x14]` -> esi (line 439558), and then
`section_table = NT + 0x18 + SizeOfOptionalHeader` (lines 439560-439561).
Each section entry is sized 0x28 (line 439642 `add $0x28,%rdi`), matching
IMAGE_SECTION_HEADER.

Success path: ebx stays 0 (initial via r13d=0 at line 439513 then written
into *rsi at 0x3816ef line 439647). Note: at 0x38159a the NT header
pointer is stored into the caller's out-slot `*rsi = r8` (line 439552)
so the caller gets the NT-headers address.

## Descriptor-field reads by 0x3814d4 itself
| Offset  | RVA     | Line   | Purpose                              |
|--------:|---------|-------:|--------------------------------------|
| +0x28   | 0x3814f0 via rbp | (via 0x3815ee below) |                         |
| +0x28   | 0x3816c3| 439636 | image base for per-section VA math   |
| +0x30   | 0x3814f0| 439512 | image-size sanity source             |
| +0x48   | 0x3815e8| 439573 | page-size (used with section VA)     |
| +0x48   | 0x38168e| 439619 | page-size for each section           |

## Descriptor-field WRITES by 0x3814d4 itself
**NONE.** FUN_0x3814d4 does not mutate `(%rbp)` (the descriptor) directly.
All descriptor mutation is performed by the callee **FUN_0x381714**
(per-section map helper, entry line 439662) which receives the
descriptor in %rcx.

What 0x3814d4 *does* write through pointers it received as arguments:
| Target  | Value                       | RVA        | Line   |
|---------|-----------------------------|-----------:|-------:|
| *(%rdi) | 0x40 (required hdr size)    | 0x381542   | 439533 |
| *(%rdi) | e_lfanew + 0x108            | 0x381582   | 439547 |
| *(%rdi) | needed size                 | 0x3815e0   | 439571 |
| *(%rsi) | 0 (success) or NT hdr ptr   | 0x381573 / 0x38159a / 0x3816ef | 439543 / 439552 / 439647 |

## Per-section loop (lines 439584-439644)
Registers entering the loop:
- r15d = NumberOfSections (copy of r14d, line 439559)
- rdi  = section_table + 0x8 (line 439586), i.e. pointer into first
  IMAGE_SECTION_HEADER such that `0(%rdi)` = VirtualSize,
  `4(%rdi)` = VirtualAddress, `1c(%rdi)` = Characteristics
  (the `+8` offset means %rdi is 8 bytes past Name[0], landing on
  VirtualSize since the 8-byte Name field precedes it).
- r14d = 1 (stride/const, line 439587)
- esi  = 0xe0000000 (mask for chars; line 439588)

Per-iteration logic:
```
phys_size   = *(u32*)(%rdi)        ; 439589  (VirtualSize)
if (phys_size == 0) skip section   ; 439590-439591
chars       = *(u32*)(%rdi+0x1c)   ; 439592  (Characteristics)
top3        = chars & 0xe0000000   ; 439593
switch(top3) {
  0x00000000: prot = 8           ; EXECUTE? no — RO with no IMAGE flags: PROT_READ-ish = 8
  0x20000000: prot = 5           ; EXECUTE only
  0x40000000: prot = 1           ; READ only (sets prot = r14d = 1)
  0x60000000: prot = 5           ; EXECUTE+READ
  0x80000000: prot = 0           ; (fall-through path at 0x38165c)
  0xc0000000: prot = 3           ; READ+WRITE
  0xe0000000: prot = 7           ; RWX
}
pagemask   = desc[+0x48] - 1       ; 439619-439622 (edx = -ecx, r10d = -ecx)
neg_mask   = ~(pagemask)           ; eax = -desc[+0x48]
raw_va     = *(u32*)(%rdi+0x54?)   ; actually r8d = *(%rdi-0x08+0x54)=section.VirtualAddress-related field
                                   ; precisely: at 439575 (first section before loop) r8d = *(r8+0x54)
                                   ; = OptionalHeader.SizeOfImage family; within loop the
                                   ; per-section VA source is computed at 439589-439626
size_pages = (phys_size + desc[+0x48] - 1) & ~(desc[+0x48]-1) ; 439623-439626
sec_rva    = *(u32*)(%rdi+0x04)    ; 439627  (VirtualAddress)
va_rounded = sec_rva & ~(desc[+0x48]-1)                       ; 439628

if ([rsp+0x80] != 0) {             ; global-mode byte (439630)
   if ((prot-3) & 0xfffffffb) prot = 1  ; demote to RO unless prot was 3 or 8
}                                  ; 439633-439635
base       = desc[+0x28]           ; 439636  (image base, written by FUN_0x37e1f0)
va         = base + va_rounded     ; 439638
stk[+0x20] = r12b (original r9b flag)          ; 439640
stk[+0x28] = prot byte                         ; 439637
FUN_0x381714(rcx=desc, rdx=va, r8=size_pages,  ; 439641  (call 381714)
             r9=prot, stk[+0x20]=flag, stk[+0x28]=prot);
rdi += 0x28                        ; 439642  (next IMAGE_SECTION_HEADER)
r15 -= 1                           ; 439643
if (r15 != 0) continue             ; 439644
```

The first section is handled by a pre-loop call at line 439583 (same
FUN_0x381714), using the optional-header `SizeOfHeaders` field at
`COFF+0x54` (line 439575) — i.e. it first maps the **headers region**,
then iterates actual sections.

## Internal callees
| RVA       | Line   | Role                                                       |
|-----------|-------:|------------------------------------------------------------|
| 0x381714  | 439583, 439641 | per-section mapper (rcx=desc, rdx=va, r8=size, r9=prot, stk[+0x20]/+0x28 flags); runs bounds asserts, computes `va / page_size` as PTE index, forwards to `0x3a9240` (page-table writer) at line 439758 |
| 0x3a0880  | 439521 | telemetry frame-capture (assert path)                      |
| 0x218494  | 439527 | assertion/fail-fast handler                                |
| 0x3a9240  | 439758 | page-table installer (callee of 0x381714, not 0x3814d4 directly) |

## Error codes returned via %eax
- `0x80000005` STATUS_BUFFER_OVERFLOW (size-needed error; three sites) — lines 439534, 439548, 439569
- `0xc000007b` STATUS_INVALID_IMAGE_FORMAT — lines 439554, 439646
- `0` success (fall-through, r13d=0 persists) — lines 439513, 439647

## Relationship to the descriptor
0x3814d4 is a **read-only consumer** of the descriptor w.r.t. the
module-object structure itself. It relies on FUN_0x37e1f0 having
already populated:
  - desc[+0x28] = image_base (verified in WAVE47_desc_28_writer.md, line 436039)
  - desc[+0x30] = page-aligned image size (line 436045)
  - desc[+0x48] = page_size (line 436047)
All section mapping is delegated to FUN_0x381714 which ultimately calls
0x3a9240 (page-table writer) — so any PTE/VA-range writes land in the
page-table hierarchy, not in the descriptor's own body.
