# wave-48-f: FUN_0x3818e8 decode — UNICODE path copy helper

Source: `/tmp/sqlpal_full.txt`. Function body: lines 439788..439856
(RVA 0x3818e8..0x381a0a). Called from FUN_0x381d8c at line 440138
(`381de0: call 0x3818e8`) and once more at line 441739 (RVA 0x38347f).

## Register usage on entry
- `rcx` = descriptor pointer (desc). Copied to `rbx` at line 439796
  (`381905: mov %rcx,%rbx`). All later `*(%rbx...)` accesses are desc-relative.
- `rdi = [rcx+0x78]` at line 439794 (`3818ff: mov 0x78(%rcx),%rdi`).
  "header" pointer stored in desc+0x78 (interior pointer; the
  UNICODE_STRING it carries lives at rdi-0x1b8).

## Instruction flow table

| Line   | RVA     | Insn                                           | Note |
|--------|---------|------------------------------------------------|------|
| 439788 | 3818e8  | mov %rbx,0x10(%rsp)                            | save |
| 439789 | 3818ed  | mov %rsi,0x18(%rsp)                            | save |
| 439790 | 3818f2  | mov %rdi,0x20(%rsp)                            | save |
| 439791 | 3818f7  | push %rbp; mov %rsp,%rbp; sub $0x40,%rsp       | frame |
| 439794 | 3818ff  | mov 0x78(%rcx),%rdi                            | rdi = desc[+0x78] (hdr ptr) |
| 439795 | 381903  | xor %esi,%esi                                  | rsi = NULL const |
| 439796 | 381905  | mov %rcx,%rbx                                  | rbx = desc |
| 439797 | 381908  | cmp %rsi,0xa8(%rcx)                            | assert desc[+0xa8] != 0 |
| 439798 | 38190f  | je 0x381937                                    | skip assert if non-NULL |
| 439799 | 381911  | call 0x3a0880                                  | __debugbreak |
| 439800 | 381916  | mov $0x17e,%r9d (line=382)                     | assert arg |
| 439801-5| 38191c-2f | rdx=msg, r8=file, rcx=1; call 0x218494      | assertion print |
| 439806 | 381937  | lea 0x90(%rbx),%rdx                            | rdx = &desc[+0x90] (dst) |
| 439807 | 38193e  | lea -0x1b8(%rdi),%rcx                          | rcx = hdr-0x1b8   (src) |
| 439808 | 381945  | call 0x26bae8                                  | UNICODE copy |
| 439809 | 38194a  | cmp %si,0x27f6b7(%rip) # 0x601008              | global US.Length==0? |
| 439810 | 381951  | jbe 0x3819f1                                   | if empty -> epilogue |
| 439811 | 381957  | movups 0xd0(%rbx),%xmm0                        | read desc[+0xd0..+0xdf] |
| 439812 | 38195e  | lea 0x10(%rbp),%r9                             | r9 = &local_out |
| 439813 | 381962  | mov %si,0x10(%rbp)                             | local_out.Length = 0 |
| 439814 | 381966  | lea 0xb9333(%rip),%r8 # 0x43aca0               | separator string |
| 439815 | 38196d  | mov $0x1,%ecx                                  | flags = 1 |
| 439816 | 381972  | lea -0x10(%rbp),%rdx                           | rdx = &local_US |
| 439817 | 381976  | movdqu %xmm0,-0x10(%rbp)                       | local_US = desc[+0xd0] |
| 439818 | 38197b  | call 0x299ca8                                  | split helper #1 |
| 439819 | 381980  | test %eax,%eax; js 0x3819d1                    | on error jump |
| 439821 | 381984  | movzwl 0x10(%rbp),%eax                         | eax = local_out.Length |
| 439822-7| 381988-97 | r9=&local_out, r8=L"\\"(0x43ac90), shrink local_US by (eax+2) |
| 439828-33| 3819a3-b5 | Buffer = Buffer + ((eax+2)/2)*2; flags=1    |
| 439834 | 3819ba  | call 0x299ca8                                  | split helper #2 |
| 439835 | 3819bf  | test %eax,%eax; js 0x3819d1                    |  |
| 439837-9| 3819c3-cb | local_US.Length = local_US.MaxLen = local_out.Length |
| 439840 | 3819cf  | jmp 0x3819d5                                   |  |
| 439841 | 3819d1  | movzwl -0x10(%rbp),%eax                        | err path |
| 439842 | 3819d5  | test %ax,%ax; je 0x3819f1                      | empty -> skip |
| 439844-6| 3819da-e4 | r8b=1, rdx=global US@0x601008, rcx=&local_US |
| 439847 | 3819e8  | call 0x2995c0                                  | RtlEqualUnicodeString |
| 439848 | 3819ed  | test %al,%al; je 0x3819f6                      | match -> leave |
| 439850 | 3819f1  | call 0x3a0620                                  | LdrpLog/breakpoint |
| 439851-6| 3819f6-a| restore rbx,rsi,rdi; leave; ret              |  |

## Descriptor field writes

FUN_0x3818e8 itself performs **no direct stores** into desc (rbx).
All writes to desc+0x90 happen inside the callee `0x26bae8`, which
receives:
- `rdx = &desc[+0x90]` (line 439806) — destination
- `rcx = desc[+0x78] - 0x1b8`    (line 439807) — source UNICODE_STRING

The effective writes attributable to this call (0x26bae8's prologue at
line 123855 matches the locked UNICODE_STRING init/copy pattern shared
with 0x381b44) are:

| Offset    | Size | Meaning                                                |
|-----------|------|--------------------------------------------------------|
| desc+0x90 | 2 B  | UNICODE_STRING.Length  (from (hdr-0x1b8).Length)       |
| desc+0x92 | 2 B  | UNICODE_STRING.MaximumLength                           |
| desc+0x94 | 4 B  | padding                                                |
| desc+0x98 | 8 B  | UNICODE_STRING.Buffer (WCHAR*)                         |

**No writes** occur at desc+0xa0, +0xa8, +0xb0, +0xb8, +0xc0, +0xc8,
or +0xd0 within this function. desc+0xa8 is only *read* as a sanity
check (line 439797). desc+0xd0 is only *read* (line 439811) — it is a
second UNICODE_STRING populated by an earlier sibling helper.

## Source of UNICODE path data

The path string is **not a parameter**. It comes from the LDR/header
block pointed to by **desc[+0x78]**: specifically the UNICODE_STRING
at offset `-0x1b8` from that pointer (line 439807:
`lea -0x1b8(%rdi),%rcx`). In Drawbridge/Windows terms, desc+0x78 is
an interior LDR_DATA_TABLE_ENTRY pointer, and `-0x1b8` reaches the
module FullDllName/BaseDllName UNICODE_STRING.

The desc+0xd0 UNICODE_STRING (already present) is fed into the
0x299ca8 path-split helper twice — once with separator string at
0x43aca0, then on the shrunk prefix with separator at 0x43ac90 — to
extract the module leaf name. That leaf is then compared against the
global UNICODE_STRING at RVA `0x601008` via 0x2995c0; mismatch fires
`0x3a0620` (diagnostic breakpoint). This is an identity self-check
that the path just installed into desc+0x90 matches the expected module.

## Internal callees

| RVA       | Role                                                   |
|-----------|--------------------------------------------------------|
| 0x3a0880  | `__debugbreak` / int 0x2C thunk                        |
| 0x218494  | assertion print (rcx=1, rdx=msg, r8=file, r9=line#)    |
| 0x26bae8  | UNICODE_STRING copy (dst=rdx, src=rcx) — writes desc+0x90..0x9f |
| 0x299ca8  | path separator split helper                            |
| 0x2995c0  | `RtlEqualUnicodeString`-style compare                  |
| 0x3a0620  | LdrpLog / `__fastfail`-style breakpoint                |

## Summary

FUN_0x3818e8 installs the module's full path (taken from the LDR-like
header at `[desc+0x78]-0x1b8`) into the UNICODE_STRING slot at
`desc+0x90`, then self-verifies by extracting the leaf name from the
already-populated `desc+0xd0` UNICODE_STRING and matching it against
the global module name at `0x601008`. Wave-47-b's "+0x90..+0xd0"
range was an over-estimate: only +0x90..+0x9f is written, and
+0xd0..+0xdf is read-only.
