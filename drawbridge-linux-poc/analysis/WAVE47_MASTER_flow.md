# FUN_0x37cf68 (`VmModuleState::ReservePeImageRange`) — assembled flow

Synthesizes wave-45 (ELF DK sequence), wave-46 (scope allocator), wave-47-c (FUN_0x37b2f0), wave-47-d (FUN_0x37e518), wave-47-b (FUN_0x381d8c), and direct disasm of the 0x37cf68 body interior.

All claims below cite `/tmp/sqlpal_full.txt` lines.

## Call-site context

Caller: `FUN_0x2055dc "RegisterInitialModule"` invokes `FUN_0x37cf68(vms, request_va, size)` with r13=vms, somewhere in 0x2055dc…0x2056e0. The returned value is a fully-initialised PE-image descriptor.

## Interior flow (lines 434770–434830)

| RVA     | Line  | Insn                               | Purpose                                           |
|---------|-------|------------------------------------|---------------------------------------------------|
| 0x37d167| 434785| `and $0xfff0, %r8d`                | align header size                                 |
| 0x37d16e| 434786| `add $0xe8, %r8`                   | add 0xe8 = descriptor header slab size            |
| 0x37d175| 434787| `call 0x37e518`                    | compute chunk size (arithmetic helper)            |
| 0x37d17a| 434788| `mov %rax, %rdx`                   | rdx = chunk size                                  |
| 0x37d17d| 434789| `mov %r13, %rcx`                   | rcx = vms (heap context)                          |
| 0x37d180| 434790| `call 0x37b2f0`                    | allocate zeroed chunk                             |
| 0x37d185| 434791| `mov %rax, %r15`                   | r15 = chunk (= descriptor pointer)                |
| 0x37d188| 434792| `test %rax, %rax`                  | null check                                        |
| 0x37d18b| 434793| `jne 0x37d1b4`                     | skip fastfail on success                          |
| 0x37d18d| 434794| `call 0x3a0880`                    | fastfail if null                                  |
| 0x37d1b4| 434801| `movaps (%r14), %xmm0`             | read 16 bytes from r14 (header ptr)               |
| 0x37d1b8| 434802| `lea -0x18(%rbp), %rax`            | local scratch                                     |
| 0x37d1bc| 434803| `movb $0x1, 0x30(%rsp)`            | stack flag = 1                                    |
| 0x37d1c1| 434804| `mov %rsi, %r9`                    | r9 arg  (image_base / request_va)                 |
| 0x37d1c4| 434805| `mov %rax, 0x28(%rsp)`             | arg6 = &[rbp-0x18]                                |
| 0x37d1c9| 434806| `mov %rbx, %r8`                    | r8 arg                                            |
| 0x37d1cc| 434807| `mov %r13, %rdx`                   | rdx = vms                                         |
| 0x37d1cf| 434808| `mov %r12, 0x20(%rsp)`             | arg5 = r12                                        |
| 0x37d1d4| 434809| `mov %r15, %rcx`                   | rcx = chunk (descriptor)                          |
| 0x37d1d7| 434810| `movdqa %xmm0, -0x18(%rbp)`        | store xmm0 at local                               |
| 0x37d1dc| 434811| **`call 0x381d8c`**                | **descriptor populator (vtable + PE parse)**      |
| 0x37d1e1| 434812| `mov %rsi, %rdx`                   |                                                   |
| 0x37d1e4| 434813| `mov %rax, 0x50(%rbp)`             | save 381d8c's return                              |
| 0x37d1e8| 434814| `mov %rsi, %rcx`                   |                                                   |
| 0x37d1eb| 434815| `mov %rax, %rbx`                   |                                                   |
| 0x37d1ee| 434816| `call 0x208b0c`                    | helper (log/telemetry)                            |
| 0x37d1f3| 434817| `lea 0x48(%r13), %rcx`             | rcx = vms + 0x48                                  |
| 0x37d1f7| 434818| `mov %rbx, %rdx`                   | rdx = 381d8c return                               |
| 0x37d1fa| 434819| `call 0x37d23c`                    | vms-state helper                                  |
| 0x37d1ff| 434820| `mov $0x2, %edx`                   | state = 2                                         |
| 0x37d204| 434821| `mov %rbx, %rcx`                   |                                                   |
| 0x37d207| 434822| **`call 0x37e4c0`**                | **state transition → 2 (REGISTERED)**             |
| 0x37d20c| 434823| `lea 0x50(%rbp), %rdx`             |                                                   |
| 0x37d210| 434824| `mov %rdi, %rcx`                   |                                                   |
| 0x37d213| 434825| `call 0x380708`                    | final bookkeeping                                 |
| 0x37d218| 434826| `lea 0x50(%rbp), %rcx`             |                                                   |
| 0x37d21c| 434827| `call 0x379788`                    | cleanup                                           |
| 0x37d221| 434828| `lea -0x28(%rbp), %rcx`            |                                                   |
| 0x37d225| 434829| `call 0x3797fc`                    | cleanup                                           |

## Callees decoded

### FUN_0x37e518 (wave-47-d, `analysis/WAVE47_fun_37e518.md`)
- Pure arithmetic helper, no state mutation
- Signature: `uint64_t compute_chunk_size(requestVA, pageSize, headerSize)`
- Returns: `((requestVA/pageSize) + headerSize + 0xf) & ~0xf`
- 3 asserts (power-of-2 pageSize, pageSize ≥ 0x1000, requestVA page-aligned)

### FUN_0x37b2f0 (wave-47-c, `analysis/WAVE47_fun_37b2f0.md`)
- Generic 2-arg heap allocator: `void* alloc(heap_ctx=rcx, size=rdx)`
- Returns zeroed chunk (memset via 0x3a9240)
- Locks heap_ctx+8 bitlock, walks free-tree at heap_ctx+0x28
- Slow path: FUN_0x37b3c4 (VAD-aware, still uncharted)
- **Does NOT write any descriptor fields**

### FUN_0x381d8c (wave-47-b, `analysis/WAVE47_fun_381d8c.md`)
- 40-instruction vtable installer + PE loader trampoline
- Args: (rcx=descriptor, rdx=header_ptr, r8=image_base, **r9=page_aligned_size** — corrected by wave-47-e, stack[0x20]=arg5, stack[0x28]=&out)
- Writes: `descriptor[+0x00] = vtable_ptr` (0x412e18)
- Internal callees:
  - **FUN_0x3812cc — threads descriptor through to FUN_0x3853e4 → FUN_0x37e1f0 which writes +0x28 and +0x30** (correction from wave-47-e)
  - FUN_0x3818e8 — UNICODE path copy (reads desc[+0x90..+0xd0])
  - FUN_0x3814d4 — PE/COFF parser (validates MZ/PE signatures, walks sections)

### FUN_0x37e1f0 (wave-47-e, `analysis/WAVE47_desc_28_writer.md`)
**The authoritative writer of va_base and size fields.** Called deep in the chain:
`FUN_0x37cf68 → FUN_0x381d8c → FUN_0x3812cc → FUN_0x3853e4 → FUN_0x37e1f0`.

Writes:
- `desc[+0x28] = image_base` at RVA `0x37e25f`, line **436039**: `mov %r9, 0x28(%rcx)`
- `desc[+0x30] = page_aligned_size` at RVA `0x37e27b`, line **436045**: `mov %rbp, 0x30(%rcx)`

Source-of-value chain:
- r9 → 0x37e1f0's r9 → 0x3853e4's ... → 0x3812cc's r9 (from `mov %r8,%r9` at line 439400) → FUN_0x381d8c's r8 → FUN_0x37cf68's rbx → caller's arg2 (PE base, validated PE32+ at line 434700-434702)
- rbp (size) → loaded from `0x80(%rsp)` at line 436021 → propagated from FUN_0x3812cc's `mov %r9, -0x48(%r11)` at line 439399 → FUN_0x381d8c's r9 → FUN_0x37cf68's rsi (page-aligned-up size, computed at 434681-434683)

## Post-0x381d8c operations in FUN_0x37cf68 (lines 434812–434829)

| RVA     | Line  | Operation                                   |
|---------|-------|---------------------------------------------|
| 0x37d1e4| 434813| `mov %rax, 0x50(%rbp)` — save 381d8c ret    |
| 0x37d1ee| 434816| `call 0x208b0c` — logging/telemetry helper  |
| 0x37d1fa| 434819| `call 0x37d23c(rcx=vms+0x48, rdx=desc_ret)` |
| 0x37d207| 434822| `call 0x37e4c0(rcx=desc_ret, edx=2)` — **state → 2** |
| 0x37d213| 434825| `call 0x380708(rcx=rdi, rdx=&local)` — final bookkeeping |
| 0x37d21c| 434827| `call 0x379788(rcx=&local)` — cleanup       |
| 0x37d225| 434829| `call 0x3797fc(rcx=local)` — cleanup        |

## FUN_0x37f128 (wave-46, `analysis/WAVE46_scope_layout.md`) — NOT called from this path
- Pure bitmap slot allocator over fixed descriptor pool
- Earlier waves incorrectly thought this was a scope-list walker
- Not relevant to the RegisterInitialModule flow for PE image

## Downstream descriptor consumers (not yet decoded)

After FUN_0x37cf68 returns, callers read:
- `desc[+0x28]` — va_base (confirmed in wave-47-b, used by 0x381e75, 0x381745, 0x38179d, 0x38208d)
- `desc[+0x30]` — size (computed as limit = base + size)
- `desc[+0x80]` — state (set to 2 by FUN_0x37e4c0 at the end)
- `desc[+0x00]` — vtable ptr (set by FUN_0x381d8c)

## ELF-host pre-load sequence (wave-45, `analysis/WAVE45_elf_dk_sequence.md`)

The ELF `sqlservr` host calls 3 DK functions BEFORE PE entry:
1. `DkStreamOpen (0x1001000)` on the PE file
2. `DkVirtualMemoryAllocate (0x2001000, kind=1, mode=3)` — **this is the call that populates VmModuleState+0xa8's descriptor chain**
3. `DkStreamMapPeBinary (0x1007000)` per PE section

Our port does raw `mmap()` via `pe_loader_parse_and_map` in `main.cpp`, skipping all three DK calls. This is why the descriptor state the PE expects post-`FUN_0x37f700` is missing.

## Open questions (wave-48 and beyond)

1. ~~**Where is `desc[+0x28]` actually written?**~~ ✅ Resolved by wave-47-e: FUN_0x37e1f0.
2. **What other descriptor fields (+0x38, +0x40, +0x58, +0x60, +0x68, +0x70, +0x90..+0xd0) need to be populated?**
   - `desc[+0x90..+0xd0]` — UNICODE path (read by FUN_0x3818e8 per wave-47-b)
   - FUN_0x37e1f0 may write more fields beyond +0x28/+0x30 — check rest of its body
   - FUN_0x3814d4 (PE parser) may write section-related fields
3. **What does FUN_0x37e4c0(rcx=desc, edx=2) do?** The state=2 transition but may also set counters/links.
4. **What does FUN_0x380708 do?** Final bookkeeping — may register descriptor in a broader vms index.
5. **What does FUN_0x37d23c(rcx=vms+0x48, rdx=desc_return) do?** State op on vms itself.
6. **What does FUN_0x208b0c do?** Helper call at line 434816 — likely logging/telemetry.
7. **What's at `r14` (line 434801 `movaps (%r14),%xmm0`)?** A 16-byte header struct passed to 0x381d8c; need to trace r14's origin in FUN_0x37cf68's prologue.

## Implementation path (deferred until open questions resolved)

When we have full understanding:

1. In our host's boot sequence (probably end of `ntum_bootstrap_launch` or in `pal_boot.cpp`), after `VmModuleState` is established by PE's own init:
2. Allocate a 0xe8-byte chunk via a host-side allocator (could reuse pool_allocator_real for simplicity)
3. Initialize the descriptor fields per the decoded layout:
   - `desc[+0x00] = vtable_ptr` (value 0x412e18 from `FUN_0x381d8c`)
   - `desc[+0x28] = 0x180000000` (PE base VA)
   - `desc[+0x30] = 0x01000000` (PE image size 16 MB)
   - `desc[+0x80] = 2` (state REGISTERED)
   - (other fields as discovered)
4. Link the descriptor into `VmModuleState+0xa8`'s chain
5. Remove wave-40's fake-descriptor SIGILL intercept at 0x37d067

This mirrors what the ELF host does in `FUN_002b6d90` at `sqlservr_FULL.c:193886` — a natural fix, not a bypass.

## Verification protocol (before touching code)

For each decoded field:
- Does a wave-47-X report cite the specific /tmp/sqlpal_full.txt line where the write happens?
- Do we have the source-of-value (what register/memory the value comes from)?
- Do we have AT LEAST ONE downstream consumer that validates the field (so we know what value is expected)?

Only when ALL of the above are satisfied for each required field do we proceed with implementation.
