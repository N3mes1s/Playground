# FUN_0x37cf68 prologue + setup

Source: `/tmp/sqlpal_full.txt` lines 434669-434787.

## Entry RVA: 0x37cf68
Line: 434669

### Args in registers (Win64 ABI)
- `rcx` = arg0 = vms / process context (captured into `r13`)
- `rdx` = arg1 = PE_base (image base pointer; captured into `rbx` and `r14`)
- `r8`  = arg2 = size (raw byte count, rounded up)
- `r9`  = arg3 = flags / extra (spilled to 0x20(%rsp), later captured into `r15`)

## Prologue (home-slot spills, saves, stack frame)
| Line   | RVA     | Instruction                                | Semantic                                   |
|--------|---------|--------------------------------------------|--------------------------------------------|
| 434669 | 37cf68  | `mov  %r9,0x20(%rsp)`                      | spill arg3 (flags) to home slot            |
| 434670 | 37cf6d  | `mov  %rdx,0x10(%rsp)`                     | spill arg1 (PE_base) to home slot          |
| 434671 | 37cf72  | `push %rbp`                                | save                                       |
| 434672 | 37cf73  | `push %rbx`                                | save                                       |
| 434673 | 37cf74  | `push %rsi`                                | save                                       |
| 434674 | 37cf75  | `push %rdi`                                | save                                       |
| 434675 | 37cf76  | `push %r12`                                | save                                       |
| 434676 | 37cf78  | `push %r13`                                | save                                       |
| 434677 | 37cf7a  | `push %r14`                                | save                                       |
| 434678 | 37cf7c  | `push %r15`                                | save                                       |
| 434679 | 37cf7e  | `mov  %rsp,%rbp`                           | frame ptr                                  |
| 434680 | 37cf81  | `sub  $0x68,%rsp`                          | 0x68 local frame                           |

## Arg assignments (register captures)

| Line   | RVA     | Instruction                                 | Meaning                                                                 |
|--------|---------|---------------------------------------------|-------------------------------------------------------------------------|
| 434681 | 37cf85  | `lea  0xfff(%r8),%rsi`                      | `rsi = r8 + 0xfff`                                                      |
| 434682 | 37cf8c  | `mov  %r9,%r15`                             | `r15 = r9` (flags/size-dup)                                             |
| 434683 | 37cf8f  | `and  $0xfffffffffffff000,%rsi`             | `rsi = round_up(r8, 0x1000)` — page-aligned size                        |
| 434684 | 37cf96  | `mov  %rdx,%rbx`                            | `rbx = rdx` (PE_base)                                                   |
| 434685 | 37cf99  | `mov  %rcx,%r13`                            | `r13 = rcx` (vms)                                                       |
| 434686 | 37cf9c  | `mov  %rsi,0x58(%rbp)`                      | save aligned size at `-0x10(%rbp)` local slot                           |
| 434687 | 37cfa0  | `mov  %rdx,%r14`                            | **`r14 = rdx` (PE_base) — initial**                                     |
| 434688 | 37cfa3  | `mov  $0x1000,%r12d`                        | `r12 = 0x1000` (page size default)                                      |

### Final role summary at 0x37cfa3
- `r13` = vms / process ctx (arg0)
- `rbx` = PE_base (arg1)
- `r14` = PE_base (arg1) *(temporarily — reloaded at line 434780, see below)*
- `rsi` = page-aligned size `(size + 0xfff) & ~0xfff`
- `r15` = flags (arg3)
- `r12` = 0x1000 default page size
- `0x58(%rbp)` = spilled aligned size
- `rdi` = not yet assigned here; loaded below as `0x3c(%rbx)` (PE `e_lfanew`)

## Validation checks

### Overlap/bounds check (lines 434689-434692)
```
37cfa9  lea    (%rdx,%rsi,1),%rax        ; rax = PE_base + aligned_size
37cfad  xor    %rdx,%rax                 ; rax ^= PE_base
37cfb0  test   $0xffffffff80000000,%rax  ; top bits differ? => straddles high/low half
37cfb6  je     0x37cfe1                  ; ok if identical → skip bugcheck
37cfb8  call   0x3a0880                  ; bugcheck (KeBugCheck-style)
```
Ensures `[PE_base, PE_base+aligned_size)` lies within the same signed half (no canonical-address wrap).

### PE32+ optional-header magic check (lines 434700-434710) — **THE WAVE47-E CHECK**
```
434700  37cfe1  movslq 0x3c(%rbx),%rdi          ; rdi = e_lfanew (PE offset)
434701  37cfe5  mov    $0x20b,%eax              ; eax = 0x020B (IMAGE_NT_OPTIONAL_HDR64_MAGIC = PE32+)
434702  37cfea  cmp    0x18(%rdi,%rbx,1),%ax    ; cmp ax, WORD at PE_base + e_lfanew + 0x18
434703  37cfef  je     0x37d01a                 ; match → continue
434704  37cff1  call   0x3a0880                 ; bugcheck
...     (bugcheck args 0x903 / string @ 0x473920 / module @ 0x46f848)
```
Confirms the image is PE32+ (64-bit) via the OptionalHeader.Magic field at `e_lfanew + 0x18 + 0x0 = e_lfanew + 0x18` from PE base (this is OptionalHeader start because NT_HEADERS = DOS+Signature(4)+FileHeader(0x14) → OptionalHeader at PE_offset+0x18).

### Aligned-size > 0 check (lines 434711-434724)
```
37d01a  mov    %r15,%rcx
37d01d  call   0x20ee68                 ; check flags/size (returns bool in al)
37d024  je     0x37d05d                 ; skip if false
37d026  mov    0x38(%rdi,%rbx,1),%r12d  ; r12 = OptionalHeader.SectionAlignment
37d02b  cmp    $0x1000,%r12             ; must be >= 0x1000
37d032  jae    0x37d05d
37d034  call   0x3a0880                 ; bugcheck (0x90f)
```

## Post-validation body (lines 434725-434784)

| Line   | RVA     | Instruction                                 | Semantic                                                               |
|--------|---------|---------------------------------------------|------------------------------------------------------------------------|
| 434725 | 37d05d  | `mov 0xa8(%r13),%rcx`                       | rcx = vms->field_0xa8 (address-space root)                              |
| 434726 | 37d064  | `mov %r13,%rdx`                             | rdx = vms                                                               |
| 434727 | 37d067  | `call 0x37f128`                             | returns pointer to some descriptor; saved to `rdi` + `-0x28(%rbp)`      |
| 434730 | 37d073  | `cmpl $0x2,0x80(%rax)`                      | require `desc->0x80 == 2`                                               |
| 434732 | 37d07c  | `mov $0xc0000018,%r15d`                     | STATUS_CONFLICTING_ADDRESSES on mismatch                                |
| 434734 | 37d084  | `lea 0x58(%rbp),%r8` / `call 0x3804b8`      | reserve VA range; out-params at `0x50(%rbp)` (allocated base) / `0x58(%rbp)` (size) |
| 434738 | 37d094  | `mov 0x50(%rbp),%rbx`                       | **`rbx` reassigned** = returned VA base                                 |
| 434749 | 37d0c8  | `cmp %r14,%rbx`                             | new base must equal original PE_base                                    |
| 434760 | 37d0f9  | `xor %r14d,%r14d`                           | **`r14` cleared**                                                       |
| 434761 | 37d0fc  | `cmp 0x58(%rbp),%rsi`                       | aligned-size sanity (must be <= saved size)                             |
| 434770 | 37d12a  | `movl $0x206d6d56,0x38(%rsp)`               | tag `'Vmm '` (pool tag)                                                 |
| 434772 | 37d132  | `mov %rsi,%r9`                              | arg4 = aligned size                                                     |
| 434774 | 37d13a  | `mov %rbx,%r8`                              | arg3 = VA base (the reserved region)                                    |
| 434776 | 37d142  | `mov %r15d,%edx`                            | arg2 = flags                                                            |
| 434777 | 37d145  | `mov $0xc,%ecx`                             | arg1 = 0xc                                                               |
| 434779 | 37d14f  | `call 0x37fea8`                             | allocator call (returns an allocation/descriptor pointer at `0x60(%rbp)`) |
| 434780 | 37d154  | **`mov 0x60(%rbp),%r14`**                   | **`r14` ← newly allocated descriptor/header pointer**                    |
| 434781 | 37d158  | `mov $0x1000,%edx`                          | alignment                                                                |
| 434782 | 37d15d  | `mov %rsi,%rcx`                             | aligned size                                                             |
| 434783 | 37d160  | `mov (%r14),%r8d`                           | load header dword[0] into `r8d`                                          |
| 434784 | 37d163  | `add $0xf,%r8d`                             | +0xf                                                                     |

## What `r14` actually points at (the CRITICAL answer)

`r14` is **re-assigned at line 434780 (RVA 0x37d154)** from `0x60(%rbp)` which is the second out-parameter slot written by `call 0x37fea8` (FUN_0x37fea8 — pool/section allocator, tag `'Vmm '`).

So at `0x37d16e` (line 434786) and `0x37d1b4` (line 434801 `movaps (%r14),%xmm0`), **`r14` is NOT the original PE_base**; it is a freshly-allocated 16-byte image-header-descriptor whose first DWORD (`(%r14)`) is a count/size field used to compute extra storage needed (`(hdr[0] + 0xf) & ~0xf + 0xe8`).

### 16-byte struct at `[r14]` (passed via xmm0 to FUN_0x381d8c)
| Offset | Size | Meaning (inferred)                                                            |
|--------|------|-------------------------------------------------------------------------------|
| +0x00  | 4    | section/descriptor count — rounded up and used to size a descriptor table     |
| +0x04  | 4    | flags or reserved (observed only read via `mov (%r14),%r8d` → dword[0])       |
| +0x08  | 8    | pointer or secondary value (second qword of the xmm0 copy)                    |

Only the first DWORD is decoded here (at 0x37d160); the full 16 bytes are snapshotted onto the stack at `-0x18(%rbp)` (line 434810 `movdqa %xmm0,-0x18(%rbp)`) and the *stack address* `lea -0x18(%rbp),%rax` is then passed in arg5 home slot `0x28(%rsp)` at line 434805. FUN_0x381d8c therefore reads the struct from the caller's stack copy, not directly from `[r14]`.

The producer of this 16-byte struct is `FUN_0x37fea8` (called at line 434779) — that is the allocator writing the image-section descriptor header.

## Control flow to 0x37d167 descriptor-init entry

```
37d154  mov 0x60(%rbp),%r14      ; r14 = header ptr from FUN_0x37fea8
37d158  mov $0x1000,%edx         ; page size
37d15d  mov %rsi,%rcx            ; aligned image size
37d160  mov (%r14),%r8d          ; header.count
37d163  add $0xf,%r8d
37d167  and $0xfff0,%r8d         ; <-- LINE 434785 : round down to 16 (bit mask trick)
37d16e  add $0xe8,%r8            ; + 0xe8 header
37d175  call 0x37e518            ; compute descriptor-table size
37d17a  mov %rax,%rdx
37d17d  mov %r13,%rcx            ; vms
37d180  call 0x37b2f0            ; allocate descriptor table → r15
37d188  test %rax,%rax
37d18b  jne 0x37d1b4             ; success
...     bugcheck path if zero
37d1b4  movaps (%r14),%xmm0      ; load 16-byte header
37d1b8  lea -0x18(%rbp),%rax
37d1bc  movb $0x1,0x30(%rsp)
37d1c1  mov %rsi,%r9             ; arg4 = aligned size
37d1c4  mov %rax,0x28(%rsp)      ; arg5 = &stack_hdr
37d1c9  mov %rbx,%r8             ; arg3 = reserved VA base
37d1cc  mov %r13,%rdx            ; arg2 = vms
37d1cf  mov %r12,0x20(%rsp)      ; arg?? = 0x1000 (page size) spilled
37d1d4  mov %r15,%rcx            ; arg1 = descriptor table
37d1d7  movdqa %xmm0,-0x18(%rbp) ; stash hdr on stack
37d1dc  call 0x381d8c            ; descriptor-init sequence
```

## Key findings
1. **Initial `r14 = PE_base`** (arg1) at line 434687 — but that value is **overwritten at line 434780**.
2. **Operative `r14`** at the descriptor-init point (line 434801) is the return-slot pointer from `FUN_0x37fea8` (pool allocation tagged `'Vmm '`) — a 16-byte image-section-header descriptor, whose first DWORD is a count used to size the descriptor table.
3. PE32+ validation (magic `0x020B` at `e_lfanew+0x18`) is at lines **434700-434702**, matching wave-47-e's citation.
4. Args to `FUN_0x381d8c` (line 434811): `rcx=desc_table(r15)`, `rdx=vms(r13)`, `r8=VA_base(rbx)`, `r9=aligned_size(rsi)`, stack: `0x20=0x1000`, `0x28=&hdr_copy`, `0x30=byte 1`.
