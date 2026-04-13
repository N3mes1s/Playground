# FUN_0x37b2f0 decode

Source: `/tmp/sqlpal_full.txt` lines 432758-432816 (function body, ends `ret` at 432816 / RVA 0x37b3c0). Inner helper `FUN_0x37b3c4` (line 432820 onward) is a separate slow-path callee, not part of this function. All claims cite `/tmp/sqlpal_full.txt` line numbers.

## Entry / Caller context

Mission's framing of `(vms, alloc'd object)` is **inverted**. At the call site (line 434790) `rdx` is the *requested size*, not an object pointer:
- line 434787: `call 0x37e518` returns size in rax
- line 434788: `mov %rax,%rdx` — size becomes arg2
- line 434789: `mov %r13,%rcx` — vms (or vms-derived heap) becomes arg1
- line 434790: `call 0x37b2f0`
- line 434791: `mov %rax,%r15` — return value is the **newly allocated chunk**
- line 434792-434793: `test %rax,%rax / jne` — assertion guards on null result, confirming this is an allocator

So FUN_0x37b2f0 is `void* alloc(heap_ctx, size)`, returning a 32-byte-offset chunk pointer.

## Instruction flow

| Line | RVA | Mnemonic | Semantic |
|------|-----|----------|----------|
| 432758 | 37b2f0 | `mov %rsp,%rax` | frame anchor |
| 432759-432762 | 37b2f3..37b2ff | save rbx,rbp,rsi,rdi to home slots | prologue |
| 432763 | 37b303 | `push %r14` | save r14 |
| 432764 | 37b305 | `sub $0x20,%rsp` | shadow space |
| 432765 | 37b309 | `mov %rdx,%rbp` | rbp = size |
| 432766 | 37b30c | `mov %rcx,%rsi` | rsi = heap_ctx |
| 432767 | 37b30f | `call 0x24c2d0` | get + clear "first-chance" flag from TLS heap diag block (returns al=1 if 0x232 was 1 then clears it; see lines 87571-87582) |
| 432768 | 37b314 | `mov %al,%r14b` | r14b = saved first-chance flag |
| 432769 | 37b317 | `call 0x244cd0` | get TLS thread-local heap diag block (returns rax = `*(gs:[0x30]+0x1838)->[0x70]+0xf0` or 0; lines 79133-79145) |
| 432770 | 37b31c | `lea -0xf0(%rax),%r8` | r8 = base of diag struct (undo +0xf0) |
| 432771-432773 | 37b323..37b329 | `neg/sbb/and` | rdi = (rax!=0) ? r8 : 0 — null-safe ptr |
| 432774 | 37b32c | `je 0x37b334` | skip if no TLS block |
| 432775 | 37b32e | `incl 0xbc8(%rdi)` | **inc per-thread heap-recursion / in-allocator counter** (same field used by allocator paths at lines 18428, 18459, 20f6bd, 218823, etc.) |
| 432776-432777 | 37b334..37b337 | `test %rsi,%rsi / je` | skip lock if heap_ctx null |
| 432778-432779 | 37b339..37b33c | `mov %rsi,%rcx; call 0x21ad20` | **acquire heap rwlock** (rcx = heap_ctx; calls into bitlock at 0x8(rcx) — see line 30704 `lock btrl $0x0,0x8(%rbx)`) |
| 432780 | 37b341 | `lea 0x28(%rsi),%rcx` | rcx = heap_ctx + 0x28 (free-list/tree root) |
| 432781 | 37b345 | `mov %rbp,%rdx` | rdx = size |
| 432782 | 37b348 | `call 0x385e44` | **fast-path allocator**: walks free-tree at +0x28, splits a 0x20-header chunk; returns chunk+0x20 in rax (lines 444726-444802) |
| 432783 | 37b34d | `mov %rax,%rbx` | rbx = chunk (or 0 on miss) |
| 432784-432785 | 37b350..37b353 | `test %rsi,%rsi / je` | skip unlock if heap_ctx null |
| 432786-432787 | 37b355..37b358 | `mov %rsi,%rcx; call 0x21ae70` | **release heap rwlock** (rcx = heap_ctx; performs `lock xadd / lock cmpxchg` on 0x8(rcx) — lines 30787-30797) |
| 432788-432789 | 37b35d..37b360 | `test %rdi,%rdi / je` | skip if no TLS block |
| 432790 | 37b362 | `decl 0xbc8(%rdi)` | **dec per-thread heap-recursion counter** (paired with 432775) |
| 432791 | 37b368 | `call 0x244cd0` | re-fetch TLS diag block (rax may differ if context-switched) |
| 432792-432793 | 37b36d..37b370 | `test %rax,%rax / je` | skip if null |
| 432794 | 37b372 | `test %r14b,%r14b` | check saved first-chance flag |
| 432795 | 37b375 | `setne %cl` | cl = (flag!=0) |
| 432796 | 37b378 | `mov %cl,0x232(%rax)` | **restore first-chance flag** at TLS+0x232 (the byte cleared by 0x24c2d0 call at line 432767) |
| 432797-432798 | 37b37e..37b381 | `test %rbx,%rbx / jne 37b396` | if fast-path got chunk, skip slow path |
| 432799-432801 | 37b383..37b389 | `mov %rbp,%rdx; mov %rsi,%rcx; call 0x37b3c4` | **slow-path allocator** (FUN_0x37b3c4 — VAD-aware, calls 0x37e518 then 0x37acdc, populates a fresh VM region; see lines 432820-432910+) |
| 432802-432804 | 37b38e..37b394 | `mov %rax,%rbx; test %rax,%rax; je 37b3a3` | use slow-path result; skip memset on null |
| 432805-432808 | 37b396..37b39e | `mov %rbp,%r8; xor %edx,%edx; mov %rbx,%rcx; call 0x3a9240` | **memset(chunk, 0, size)** (FUN_0x3a9240 is the optimized memset, lines 486496-486515) |
| 432809-432815 | 37b3a3..37b3be | restore rbp/rbx/rsi/rdi/r14, `add $0x20,%rsp; pop %r14` | epilogue |
| 432816 | 37b3c0 | `ret` | return rax = chunk (zeroed) or NULL |

## Arguments

- `rcx` = heap context (the "vms"-side allocator handle, *not* a descriptor). Its +0x8 is a bitlock; +0x28 is the free-list/tree root.
- `rdx` = allocation size in bytes (computed by 0x37e518).
- `r8`, `r9`, stack args: **none read**. Function takes exactly 2 args.

## Field writes on descriptor

There is **no descriptor argument**. The only "field writes" are:
- The new chunk's bytes 0..size are zeroed by memset (line 432808). The *caller* (FUN_0x37cf68) then writes the descriptor's contents at lines 434801-434822.
- TLS diag block field +0xbc8 is incremented (line 432775) and decremented (line 432790) — recursion guard.
- TLS diag block field +0x232 is restored (line 432796) — first-chance-allocation flag.

## Field reads on vms (rcx)

- `+0x8` (heap_ctx): rwlock — read+modified by 0x21ad20 (acquire) at line 432778-432779 and 0x21ae70 (release) at line 432786-432787.
- `+0x28` (heap_ctx): free-tree root — read by 0x385e44 at line 432782 (the function performs `mov 0x18(%rdx),%rax` etc. walking the tree, lines 444744-444746).

## Lock/atomic operations

- **Acquire**: 0x21ad20 — `lock btrl $0x0, 0x8(%rcx)` (line 30704). Bitlock on heap_ctx+8.
- **Release**: 0x21ae70 — `lock xadd %eax, 0x8(%rcx)` (line 30790) followed by conditional `lock cmpxchg` (line 30797). Reader/writer-counted release.
- No `cmpxchg`, no atomics inside FUN_0x37b2f0 itself; all atomic ops are inside the lock helpers it calls.

## Internal callees

| RVA | Purpose | Line |
|-----|---------|------|
| 0x24c2d0 | TLS first-chance-flag fetch+clear | 432767 (def 87571) |
| 0x244cd0 | TLS heap diag block getter | 432769, 432791 (def 79133) |
| 0x21ad20 | heap_ctx bitlock acquire | 432779 (def 30690) |
| 0x385e44 | free-tree fast-path alloc | 432782 (def 444726) |
| 0x21ae70 | heap_ctx rwlock release | 432787 (def 30784) |
| 0x37b3c4 | VAD-backed slow-path alloc (incl. call to 0x37e518 then 0x37acdc, plus memory commit + zero) | 432801 (def 432820) |
| 0x3a9240 | memset | 432808 (def 486496) |

## Downstream consumers

The returned chunk is consumed by FUN_0x37cf68 starting at line 434791:
- line 434801: `movaps (%r14),%xmm0` then later writes to the chunk via `0x381d8c` (line 434811) — the descriptor initializer
- line 434817-434822: `lea 0x48(%r13),%rcx; call 0x37d23c` then `call 0x37e4c0` with edx=2 — state transitions on the **vms**, not on this chunk
- line 434825: `call 0x380708` — caller-side bookkeeping

The chunk's fields are written by 0x381d8c (the per-VA-range descriptor populator), not by 0x37b2f0.

## What state does the PE scheduler require this to set?

**None directly.** FUN_0x37b2f0 is a generic 2-arg heap allocator wrapper:
1. Save+clear TLS first-chance flag, bump TLS recursion guard.
2. Take heap rwlock.
3. Try fast-path free-tree alloc (0x385e44).
4. Drop rwlock, dec recursion guard, restore first-chance flag.
5. On miss, fall through to slow-path VAD allocator (0x37b3c4) which itself takes locks/maps fresh pages.
6. memset(chunk, 0, size) on success.

The VA-range bookkeeping (state codes, counters, region trees) lives in the **callees** — `0x385e44` for fast-path tree manipulation, and `0x37b3c4` (which calls `0x37e518` and `0x37acdc`) for the slow-path VAD construction — and in the **caller** FUN_0x37cf68 via 0x381d8c, 0x37d23c, and 0x37e4c0. Agent D's hypothesis is therefore partially wrong for 0x37b2f0 itself: this function only allocates and zeroes; the actual VA bookkeeping is in the chain it dispatches to (0x37b3c4 -> 0x37e518/0x37acdc) and in 0x381d8c at the caller.
