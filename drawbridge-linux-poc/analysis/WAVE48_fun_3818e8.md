# WAVE-48-f: FUN_0x3818e8 — UNICODE Path Copy Helper

Source: `/tmp/sqlpal_full.txt` lines 439788-439856.
Called from FUN_0x381d8c at line 440138 (`call 0x3818e8` from RVA 0x381de0).

## 1. Instruction Flow Table

| RVA      | Line   | Instruction                                   | Notes |
|----------|--------|-----------------------------------------------|-------|
| 0x3818e8 | 439788 | `mov %rbx,0x10(%rsp)`                         | home-save rbx |
| 0x3818ed | 439789 | `mov %rsi,0x18(%rsp)`                         | home-save rsi |
| 0x3818f2 | 439790 | `mov %rdi,0x20(%rsp)`                         | home-save rdi |
| 0x3818f7 | 439791 | `push %rbp`                                   | |
| 0x3818f8 | 439792 | `mov %rsp,%rbp`                               | frame |
| 0x3818fb | 439793 | `sub $0x40,%rsp`                              | 0x40 locals |
| 0x3818ff | 439794 | `mov 0x78(%rcx),%rdi`                         | **rdi = desc[+0x78]** (header ptr) |
| 0x381903 | 439795 | `xor %esi,%esi`                               | rsi = 0 |
| 0x381905 | 439796 | `mov %rcx,%rbx`                               | **rbx = desc** |
| 0x381908 | 439797 | `cmp %rsi,0xa8(%rcx)`                         | check desc[+0xa8] == 0 |
| 0x38190f | 439798 | `je 0x381937`                                 | skip assert if non-null |
| 0x381911 | 439799 | `call 0x3a0880`                               | assert/trace prologue |
| 0x381916 | 439800 | `mov $0x17e,%r9d`                             | line 0x17e |
| 0x38191c | 439801 | `mov %rsi,0x20(%rsp)`                         | |
| 0x381921 | 439802 | `lea 0xedf90(%rip),%r8  # 0x46f8b8`           | file name |
| 0x381928 | 439803 | `lea 0xf2c11(%rip),%rdx # 0x474540`           | msg string |
| 0x38192f | 439804 | `lea 0x1(%rsi),%ecx`                          | ecx = 1 |
| 0x381932 | 439805 | `call 0x218494`                               | trace/log (FAILFAST-style) |
| 0x381937 | 439806 | `lea 0x90(%rbx),%rdx`                         | **rdx = &desc[+0x90] (list head)** |
| 0x38193e | 439807 | `lea -0x1b8(%rdi),%rcx`                       | rcx = header - 0x1b8 (node base) |
| 0x381945 | 439808 | `call 0x26bae8`                               | **list insert: link node into desc+0x90 list** |
| 0x38194a | 439809 | `cmp %si,0x27f6b7(%rip) # 0x601008`           | check global g_PathLen (word) |
| 0x381951 | 439810 | `jbe 0x3819f1`                                | if 0 skip copy |
| 0x381957 | 439811 | `movups 0xd0(%rbx),%xmm0`                     | **load UNICODE_STRING from desc[+0xd0..+0xdf]** (Length, MaxLen, Buffer) |
| 0x38195e | 439812 | `lea 0x10(%rbp),%r9`                          | r9 = &localUS (output param) |
| 0x381962 | 439813 | `mov %si,0x10(%rbp)`                          | zero local US.Length |
| 0x381966 | 439814 | `lea 0xb9333(%rip),%r8 # 0x43aca0`            | separator / suffix string L"\\" or similar |
| 0x38196d | 439815 | `mov $0x1,%ecx`                               | flag=1 |
| 0x381972 | 439816 | `lea -0x10(%rbp),%rdx`                        | rdx = &localUS |
| 0x381976 | 439817 | `movdqu %xmm0,-0x10(%rbp)`                    | copy desc+0xd0 UNICODE_STRING -> local |
| 0x38197b | 439818 | `call 0x299ca8`                               | **RtlAppend-style op #1** |
| 0x381980 | 439819 | `test %eax,%eax` / `js 0x3819d1`              | on fail jump |
| 0x381984 | 439821 | `movzwl 0x10(%rbp),%eax`                      | ax = US2.Length |
| 0x381988 | 439822 | `lea 0x10(%rbp),%r9`                          | r9 = &US2 |
| 0x38198c | 439823 | `add $0x2,%ax`                                | +sizeof(WCHAR) |
| 0x381990 | 439824 | `lea 0xb92f9(%rip),%r8 # 0x43ac90`            | another literal |
| 0x381997 | 439825 | `sub %ax,-0x10(%rbp)`                         | localUS.Length -= (len+2) |
| 0x38199b | 439826 | `lea -0x10(%rbp),%rdx`                        | rdx = &localUS |
| 0x38199f | 439827 | `sub %ax,-0xe(%rbp)`                          | localUS.MaximumLength -= (len+2) |
| 0x3819a3 | 439828 | `movzwl %ax,%ecx`                             | |
| 0x3819a6 | 439829 | `mov -0x8(%rbp),%rax`                         | localUS.Buffer |
| 0x3819aa | 439830 | `shr $1,%rcx`                                 | chars |
| 0x3819ad | 439831 | `lea (%rax,%rcx,2),%rcx`                      | advance buffer |
| 0x3819b1 | 439832 | `mov %rcx,-0x8(%rbp)`                         | store adjusted Buffer ptr |
| 0x3819b5 | 439833 | `mov $0x1,%ecx`                               | |
| 0x3819ba | 439834 | `call 0x299ca8`                               | **RtlAppend-style op #2** |
| 0x3819bf | 439835 | `test %eax,%eax` / `js 0x3819d1`              | |
| 0x3819c3 | 439837 | `movzwl 0x10(%rbp),%eax`                      | |
| 0x3819c7 | 439838 | `mov %ax,-0xe(%rbp)`                          | |
| 0x3819cb | 439839 | `mov %ax,-0x10(%rbp)`                         | |
| 0x3819cf | 439840 | `jmp 0x3819d5`                                | |
| 0x3819d1 | 439841 | `movzwl -0x10(%rbp),%eax`                     | |
| 0x3819d5 | 439842 | `test %ax,%ax` / `je 0x3819f1`                | |
| 0x3819da | 439844 | `mov $0x1,%r8b`                               | |
| 0x3819dd | 439845 | `lea 0x27f624(%rip),%rdx # 0x601008`          | g_Path UNICODE_STRING |
| 0x3819e4 | 439846 | `lea -0x10(%rbp),%rcx`                        | rcx = &localUS |
| 0x3819e8 | 439847 | `call 0x2995c0`                               | **final UNICODE compare/merge** |
| 0x3819ed | 439848 | `test %al,%al` / `je 0x3819f6`                | |
| 0x3819f1 | 439850 | `call 0x3a0620`                               | error/telemetry |
| 0x3819f6 | 439851 | `mov 0x58(%rsp),%rbx`                         | restore |
| 0x3819fb | 439852 | `mov 0x60(%rsp),%rsi`                         | restore |
| 0x381a00 | 439853 | `mov 0x68(%rsp),%rdi`                         | restore |
| 0x381a05 | 439854 | `add $0x40,%rsp`                              | |
| 0x381a09 | 439855 | `pop %rbp`                                    | |
| 0x381a0a | 439856 | `ret`                                         | |

## 2. Descriptor-field Writes (exhaustive)

FUN_0x3818e8 performs **zero direct writes** to descriptor offsets through `%rbx` (the descriptor). Agent 47-b's report was misleading.

The only descriptor interaction through %rbx is:
- **Read** `0x78(%rcx)` (header ptr) at line 439794
- **Read** `0xa8(%rcx)` (assert non-null) at line 439797
- **LEA** `0x90(%rbx)` — address of list head, passed to FUN_0x26bae8 (line 439806)
- **Read** `0xd0(%rbx)` as UNICODE_STRING (16 bytes: Length/MaxLen/Buffer) at line 439811

### Indirect writes via callees
- `call 0x26bae8` at line 439808 performs an intrusive doubly-linked-list insert of node `desc_header-0x1b8` into the list head at `desc+0x90`. Concretely it writes the Flink/Blink of the list at `desc[+0x90]/[+0x98]` and the corresponding links inside the header node at `(desc[+0x78]-0x1b8)+0/+8` (see FUN_0x26bae8 at line 123855, body around 123912-123920 performs classic `InsertTailList` pointer fix-ups on `0x8(%rsi)` i.e. `desc+0x98`).
- **No writes to desc[+0xa0], [+0xa8], [+0xb0], [+0xb8], [+0xc0], [+0xc8], [+0xd0]** occur in this function or its callees on behalf of rbx. The UNICODE_STRING at desc[+0xd0] is only **read**.

### Net descriptor state delta
| Offset       | Access | Effect |
|--------------|--------|--------|
| desc[+0x78]  | R      | header pointer loaded |
| desc[+0x90]  | W (via 26bae8) | List.Flink set / updated to point to `header-0x1b8` |
| desc[+0x98]  | W (via 26bae8) | List.Blink updated |
| desc[+0xa8]  | R      | sanity asserted non-NULL |
| desc[+0xd0]  | R (movups) | UNICODE_STRING (Length, MaxLen, Buffer) copied to local |

## 3. Source of the UNICODE Path Data

The path UNICODE_STRING is **not a function argument**. It is read from **desc[+0xd0]** directly into a 16-byte local at `rbp-0x10` (line 439811). The local is then:

1. Appended with the literal at `0x43aca0` (suffix #1) via FUN_0x299ca8 (line 439818).
2. Had its Length/MaxLen/Buffer advanced by (appended-len + 2 bytes / 1 WCHAR terminator adjust) (lines 439825-439832).
3. Appended again with literal at `0x43ac90` (suffix #2) via FUN_0x299ca8 (line 439834).
4. Compared/merged into the global UNICODE_STRING at `0x601008` via FUN_0x2995c0 (line 439847).

So the "UNICODE path" originates from **desc[+0xd0]** (the descriptor's own module path field), is concatenated with two constant suffix strings, and the result drives the global at `0x601008` — **not** copied into desc[+0x90..+0xd0] as wave-47-b suggested.

The `desc[+0x90..+0x98]` writes are purely **list linkage**, not string payload.

## 4. Internal Callees

| Target RVA | Line in body | Role |
|------------|--------------|------|
| 0x3a0880   | 439799       | trace/assert prologue (non-taken path) |
| 0x218494   | 439805       | log/telemetry printf (non-taken path) |
| 0x26bae8   | 439808       | **InsertTailList**(desc+0x90, header-0x1b8) |
| 0x299ca8   | 439818, 439834 | UNICODE_STRING append/copy helper (Rtl-style) |
| 0x2995c0   | 439847       | UNICODE_STRING compare/merge against global g_Path (0x601008) |
| 0x3a0620   | 439850       | error/telemetry epilogue |

## 5. Summary

FUN_0x3818e8 is the **module-registration / path-publication** helper:

1. Inserts the owning header node (at `desc[+0x78] - 0x1b8`) into the descriptor's list head at **desc[+0x90]** (the only structural mutation on the descriptor).
2. Reads the descriptor's module-path UNICODE_STRING at **desc[+0xd0]** into a scratch local.
3. Builds `desc.Path + const1 + const2` in the scratch buffer.
4. Publishes/compares the result against global UNICODE_STRING at `0x601008`.

Wave-47-b's claim that the function "copies UNICODE path from desc[+0x90..+0xd0]" conflates a list-head write at desc[+0x90]/[+0x98] with a read of the UNICODE_STRING at desc[+0xd0]. These are independent; nothing in the 0xa0/0xa8/0xb0/0xb8/0xc0/0xc8 range is touched.
