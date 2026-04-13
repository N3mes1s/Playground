# FUN_0x37e518 decode

Source: `/tmp/sqlpal_full.txt` lines 436231-436278. Function spans RVA 0x37e518..0x37e5ee, ends with `ret` at 436278; next byte is `int3` padding (436279). All claims below cite line numbers in `/tmp/sqlpal_full.txt`.

## Entry / Caller context

Caller `FUN_0x37cf68` at RVA 0x37d175 (line 434787) sets up:
- `rcx` = `rsi` — page-aligned request VA (line 434782)
- `rdx` = `0x1000` — page size (line 434781)
- `r8` = `((*r14) + 0xf) & 0xfff0) + 0xe8` — a header/struct size derived from `*0x60(rbp)` (lines 434780-434786)
- r9 not set for this call — function never reads it

Result is consumed at line 434788 (`mov %rax,%rdx`) then passed to `FUN_0x37b2f0` (line 434790) as the second argument — i.e. the returned value is used as a *size*.

## Instruction flow (full body)

| Line | RVA | Bytes/Mnem | Semantic |
|------|-----|------------|----------|
| 436231 | 37e518 | `mov %rbx,0x8(%rsp)` | save rbx (home slot) |
| 436232 | 37e51d | `mov %rbp,0x10(%rsp)` | save rbp |
| 436233 | 37e522 | `mov %rsi,0x18(%rsp)` | save rsi |
| 436234 | 37e527 | `push %rdi` | save rdi |
| 436235 | 37e528 | `sub $0x30,%rsp` | frame; +0x38 effective shift |
| 436236 | 37e52c | `lea -0x1(%rdx),%rsi` | rsi = pageSize - 1 |
| 436237 | 37e530 | `mov %r8,%rbp` | rbp = headerSize (arg3) |
| 436238 | 37e533 | `mov %rdx,%rbx` | rbx = pageSize (arg2) |
| 436239 | 37e536 | `mov %rcx,%rdi` | rdi = requestVA (arg1) |
| 436240 | 37e539 | `test %rsi,%rdx` | check (pageSize & (pageSize-1)) — power-of-two test |
| 436241 | 37e53c | `je 0x37e567` | skip assert if zero (POT) |
| 436242 | 37e53e | `call 0x3a0880` | assert helper #1 (line/file capture) |
| 436243-436248 | 37e543..37e562 | assert call w/ rdx=msg @0x474038 ("(pageSize & (pageSize - 1)) == 0", line 639725), r9d=0x3d4 (980), r8=file @0x46f860 ("vad.cpp"-ish, line 632110); calls `FUN_0x218494` (assert sink) | assertion #1 |
| 436249 | 37e567 | `cmp $0x1000,%rbx` | pageSize >= 0x1000 ? |
| 436250 | 37e56e | `jae 0x37e599` | skip assert if so |
| 436251-436257 | 37e570..37e594 | assert call: msg @0x473b00, r9d=0x3d5 (981) | assertion #2: pageSize >= 4K |
| 436258 | 37e599 | `test %rsi,%rdi` | check requestVA & (pageSize-1) — alignment of VA |
| 436259 | 37e59c | `je 0x37e5c7` | skip assert if aligned |
| 436260-436266 | 37e59e..37e5c2 | assert call: msg @0x473fc0, r9d=0x3d6 (982) | assertion #3: requestVA page-aligned |
| 436267 | 37e5c7 | `mov 0x50(%rsp),%rsi` | restore saved rsi (orig 0x18 + 0x38) — NOT a 4th arg load |
| 436268 | 37e5cc | `xor %edx,%edx` | clear rdx for div |
| 436269 | 37e5ce | `mov %rdi,%rax` | rax = requestVA |
| 436270 | 37e5d1 | `add $0xf,%rbp` | rbp = headerSize + 0xf |
| 436271 | 37e5d5 | `div %rbx` | rax = requestVA / pageSize, rdx = remainder |
| 436272 | 37e5d8 | `mov 0x40(%rsp),%rbx` | restore rbx |
| 436273 | 37e5dd | `add %rbp,%rax` | rax = (requestVA / pageSize) + headerSize + 0xf |
| 436274 | 37e5e0 | `mov 0x48(%rsp),%rbp` | restore rbp |
| 436275 | 37e5e5 | `and $0xfffffffffffffff0,%rax` | round result down to 16 |
| 436276 | 37e5e9 | `add $0x30,%rsp` | unwind |
| 436277 | 37e5ed | `pop %rdi` | restore rdi |
| 436278 | 37e5ee | `ret` | return rax |

## Arguments

Three positional args, x64 calling convention:
- `rcx` = requestVA (page-aligned, asserted line 436258)
- `rdx` = pageSize (POT, >= 0x1000, asserted lines 436240/436249)
- `r8`  = headerSize (e.g. `*r14 + 0xe8 + (rounded)` from caller)
- `r9` is unused. Stack restores at 0x40/0x48/0x50 are *callee-save reloads*, not extra params (offsets equal home-slot positions + push+sub adjustment of 0x38).

## Return value

`rax = ((requestVA / pageSize) + headerSize + 0xf) & ~0xf`

i.e. `align16(pageIndex + headerSize + 0xf)` — a 16-byte-aligned size combining a per-page index (page count from VA 0) with a header size. Used by caller as the size argument to `FUN_0x37b2f0` (line 434789-434790), which is an allocator wrapper.

NOTE: This contradicts the wave-37 hint that claimed "returns 0x80 header size". The function is in fact a size *computation* dependent on the input VA — it returns a value proportional to `requestVA / pageSize` plus a 16-byte-aligned header. For requestVA=0x180000000 and pageSize=0x1000, the page index alone is 0x180000, dwarfing any constant header. The hint was wrong.

## Global/struct writes (if any)

None. The only memory writes are stack home-slot saves (lines 436231-436234) restored before return. No `.data` or struct field is written. Reads only touch immediates (assertion strings/file/line constants at lines 436244, 436246, 436253, 436255, 436262, 436264) used to populate assertion-helper arguments.

## Internal callees

- `FUN_0x3a0880` — assertion frame setup (lines 436242, 436251, 436260). Pure assertion plumbing.
- `FUN_0x218494` — assertion sink / log-and-trap (lines 436248, 436257, 436266). Same.

No allocator, no lock, no state-mutating callee on the success path (all three asserts are skipped when inputs are valid).

## Callers

From grep on RVA 0x37e518:
- 0x37b058 (line 432596)
- 0x37b11b (line 432640)
- 0x37b1e4 (line 432686)
- 0x37b3f6 (line 432838)
- 0x37beff (line 433552)
- 0x37c6e8 (line 434045)
- 0x37d175 (line 434787) — the wave-47 site
- 0x385389 (line 443961)

Eight call sites total — consistent with a generic per-page sizing helper used wherever a VA range is being mapped/sized.

## Purpose summary

Pure arithmetic / validation helper. No allocation, no global mutation, no state tied to the request VA. Asserts (pageSize POT, pageSize >= 4K, requestVA page-aligned) then computes `align16((requestVA / pageSize) + headerSize + 0xf)` and returns it in `rax`. The caller uses the result as an allocation size for `FUN_0x37b2f0`. The wave-37 "returns 0x80 header size" characterization is incorrect; the value scales with `requestVA / pageSize`.
