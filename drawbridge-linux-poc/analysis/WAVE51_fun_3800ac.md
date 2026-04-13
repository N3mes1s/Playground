# Wave-51-c: FUN_0x3800ac — slot-descriptor sub-initializer (3rd level)

All line/RVA citations are from `/tmp/sqlpal_full.txt`. Function body RVA `0x3800ac .. 0x38010d`, lines 438120-438143.

## Signature & arguments

Called from FUN_0x380058 at line 438107 (RVA 0x38007e):

```
438105:  mov %rcx, %rbx             ; rbx = desc (in caller)
438107:  call FUN_0x3800ac           ; rcx still = desc
```

| Reg | Value  | Used as |
|-----|--------|---------|
| rcx | `desc` | saved to `rbx` at line 438123, survives through body |

No rdx / r8 / r9 inputs are read. Note the FUN_0x380058 caller preserves `rbx`, `rsi`, `rdi` across this call via its own stack frame (lines 438096-438099, 438114-438115).

## Prologue — `+0x78 == 0` assertion

```
438120:  push %rbx                      ; save caller's rbx
438121:  sub  $0x30, %rsp
438122:  cmpq $0x0, 0x78(%rcx)          ; ASSERT desc[+0x78] == 0
438123:  mov  %rcx, %rbx
438124:  je   0x3800e4                  ; pass -> continue
438125:  call 0x3a0880                  ; fail -> assertion breadcrumb
438126:  andq $0x0, 0x20(%rsp)
438127-438131: fail trampoline (sets r8=0x46f8a0, r9=0x80, rdx=0x4744a8, rcx=1)
            call 0x218494              ; assertion reporter
```

This confirms Wave-50a's claim: `+0x78` is pre-existing (either pool-construction zero-init or prior cleanup). **FUN_0x3800ac does NOT write `+0x78`** — it only asserts it is zero on entry. The external writer that Wave-50a flagged (line 154 of WAVE50_process_ctx_layout.md) is still unresolved by this chain.

## Descriptor field-writes

| Line   | RVA        | Instruction                          | Write                                           | Wave-50a row      |
|--------|------------|--------------------------------------|-------------------------------------------------|-------------------|
| 438132 | 0x3800e4   | `andq $0x0, 0x60(%rbx)`              | `desc[+0x60] = 0`                               | YES (+0x60) — subsequently overwritten by FUN_0x37f128 line 437213 |
| 438135 | 0x3800f0   | `mov %rax, 0x50(%rbx)`               | `desc[+0x50] = 0x80000000` (rax set line 438133) | YES (+0x50)       |
| 438137 | 0x3800f7   | `mov %rbx, 0x58(%rbx)`               | `desc[+0x58] = rbx` (self-link)                 | YES (+0x58)       |
| 438139 | 0x380100   | `movq $0x8000, 0x70(%rbx)`           | `desc[+0x70] = 0x8000`                          | YES (+0x70) — redundant with FUN_0x380058 line 438111 |

Register setup for these writes:

```
438133:  mov $0x80000000, %eax      ; rax = 0x80000000 (upper-32 zeroed via 32-bit mov)
438134:  xor %edx, %edx             ; edx = 0 (arg for FUN_0x380110 call below)
438136:  mov %rbx, %rcx             ; rcx = desc (arg for FUN_0x380110)
```

## Calls

| Line   | Target           | Args                            | Purpose                                           |
|--------|------------------|---------------------------------|---------------------------------------------------|
| 438125 | FUN_0x3a0880     | (none)                          | Assertion breadcrumb (only on +0x78 != 0 failure) |
| 438131 | FUN_0x218494     | rcx=1, rdx=0x4744a8, r8=0x46f8a0, r9=0x80 | Assertion reporter (fail path only) |
| 438138 | **FUN_0x380110** | rcx=desc, edx=0                  | **State transition +0x80: * -> 0**  (Wave-51-d)  |

**Wave-50b contradiction note**: Wave-50b says FUN_0x380110 is called "twice, for states 1 and 2" from FUN_0x3800ac — that is wrong. FUN_0x3800ac calls it **once** with `edx=0`. The edx=1 and edx=2 calls are both directly from FUN_0x37f128 (lines 437214, 437217), not from FUN_0x3800ac. This matches Wave-50a's table (first write is `0` inside FUN_0x3800ac) and Wave-50b's own line 438138 citation.

## Ordering inside FUN_0x3800ac

1. Assert `desc[+0x78] == 0`                   (line 438122)
2. `desc[+0x60] = 0`                           (line 438132)
3. `desc[+0x50] = 0x80000000`                  (line 438135)
4. `desc[+0x58] = desc`                        (line 438137)
5. `FUN_0x380110(desc, 0)`  =>  `desc[+0x80] = 0` (line 438138; writes +0x80 via helper)
6. `desc[+0x70] = 0x8000`                      (line 438139)

## Epilogue

Lines 438141-438143: `add $0x30,%rsp; pop %rbx; ret`. No return value consumed.

## Contradictions with Wave-50a

None — every write and assert matches the Wave-50a table (rows +0x50, +0x58, +0x60, +0x70, +0x78-assert).

## `+0x78` gap status

**NOT resolved by this chain.** FUN_0x3800ac only asserts pre-condition. The writer must sit between FUN_0x37f128 return (line 434728 in caller) and FUN_0x380708 consumption (line 434825). Wave-50a identified FUN_0x3804b8 and FUN_0x381d8c as candidates — this wave does not decode those, so the gap persists for a future wave.
