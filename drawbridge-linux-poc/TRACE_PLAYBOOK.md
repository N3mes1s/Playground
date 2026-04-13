# Drawbridge Linux POC — Trace Playbook

Distilled methodology from waves 1–44. **Read this before diagnosing any new boot crash.**

The PE under analysis lives at VA `0x180000000`+, with .text covering roughly
`0x180200000 .. 0x1803a9aa8`. Disassembly is at `/tmp/sqlpal_full.txt`; raw
bytes at `/tmp/sqlpal_mapped.bin`. Boot stack is at `0x500000000`. The host's
SIGILL/SIGSEGV handler lives in `drawbridge-host/ntum_signals.cpp`.

---

## 1. Triage Decision Tree

When boot crashes, gather: **signal name, RIP, faulting address (if SEGV),
stack trace from `[CRASH-STACK]`, and registers**. Then:

```
crash
 ├─ signal == SIGILL
 │   ├─ RIP at known ud2 trap site?  → READ the corresponding handler
 │   │                                  clause in ntum_signals.cpp; the
 │   │                                  scenario is already documented.
 │   └─ Unknown ud2 → likely PE patched bytes mismatch; check whether
 │                    a recent wave overwrote PE bytes, dump 16 bytes
 │                    around RIP from /tmp/sqlpal_mapped.bin.
 │
 ├─ signal == SIGSEGV
 │   ├─ fault addr ≈ 0x10..0x100 with low base register (rsi=0x10, r15=0)
 │   │   → NULL/uninitialized struct field deref. Almost always a
 │   │     fake-descriptor incompleteness (see §4). Map RIP via grep
 │   │     /tmp/sqlpal_full.txt and identify the missing field by
 │   │     offset.
 │   ├─ fault addr starts 0xfffff78000000xxx
 │   │   → KUSER_SHARED_DATA kernel-canonical alias. Wave-42 patched
 │   │     `movabs $0xfffff78000000XXX, %rax` PE-wide; if a NEW site
 │   │     fires, extend the scan in pal_boot.cpp.
 │   ├─ fault addr in PE .text range (0x180200000–0x1803a9aa8)
 │   │   → executing patched/unmapped code; check pe_loader and
 │   │     mprotect calls.
 │   ├─ fault addr in 0x300000xxxxxx
 │   │   → VmModuleState region. Check whether DK_VmIdentityEcho was
 │   │     called for that arena (grep [VA-IN] in stderr.log).
 │   └─ Other → likely real PE-side bug exposed by a fake state.
 │
 ├─ signal == SIGSEGV at RIP == 0x1803a0880 (int $0x2c)
 │   → __fastfail. RAX is the NTSTATUS (commonly 0xc000000d
 │     INVALID_PARAMETER or 0xc0000018 CONFLICTING_ADDRESSES).
 │     Walk back the stack frames in [CRASH-STACK]; the first PE
 │     frame is the validator that produced the status. Trace
 │     upstream from there (see §3).
 │
 ├─ signal == SIGTRAP
 │   → int3. Either an explicit MS __debugbreak() or a wrong
 │     ud2/int3 patch. Check the byte at RIP in sqlpal_mapped.bin.
 │
 └─ stack overflow (RSP near 0x500000000)
     → Boot stack guard hit. Likely raise/dispatch recursion
       (see waves 9, 12, 18). Add a counter to the recursive
       function and abort after N entries to capture cycle.
```

**Rule of thumb:** if a crash signature matches one already addressed in
recent commits (`git log --oneline | head -30`), read that commit body
first — odds are the same root cause has surfaced again with a new RIP.

---

## 2. Diagnostic Harness Recipes

### 2.1 ud2 trap at a specific RVA

In `drawbridge-host/ntum_bootstrap.cpp`, after the PE is mapped:

```cpp
{
    constexpr uintptr_t TARGET = 0x18037d073ULL;   // example RVA
    volatile uint8_t *p = (uint8_t*)TARGET;
    /* Save the original 5 bytes if you need to restore later. */
    p[0] = 0x0f; p[1] = 0x0b;          // ud2
    p[2] = 0x90; p[3] = 0x90; p[4] = 0x90;
    fprintf(stderr, "[TRAP] ud2 installed at 0x%lx\n", (unsigned long)TARGET);
}
```

If the page isn't writable yet, `mprotect(page_align(TARGET), 0x1000,
PROT_READ|PROT_WRITE|PROT_EXEC)` first.

### 2.2 SIGILL handler clause (register + memory dump + clean continuation)

In `drawbridge-host/ntum_signals.cpp`, inside `if (sig == SIGILL) { ... }`:

```cpp
if (rip == 0x18037d073ULL) {
    auto *gr = uc->uc_mcontext.gregs;
    uint64_t rax = gr[REG_RAX], rcx = gr[REG_RCX], rdx = gr[REG_RDX];
    uint64_t rbp = gr[REG_RBP], rsp = gr[REG_RSP], rdi = gr[REG_RDI];
    uint64_t rsi = gr[REG_RSI], r8 = gr[REG_R8], r15 = gr[REG_R15];

    fprintf(stderr,
        "[TRAP-37d073] rax=%lx rcx=%lx rdx=%lx rdi=%lx rsi=%lx "
        "r8=%lx r15=%lx rbp=%lx rsp=%lx\n",
        rax, rcx, rdx, rdi, rsi, r8, r15, rbp, rsp);

    /* Dump up to 0xa0 bytes from a struct pointer. Always range-check. */
    if (rdi >= 0x300000000000ULL && rdi < 0x500000000000ULL) {
        const uint64_t *p = (const uint64_t*)rdi;
        for (int i = 0; i < 20; i++)
            fprintf(stderr, "  [rdi+0x%02x]=0x%lx\n", i*8, p[i]);
    }

    /* Dump caller frame so we know who called us. */
    if (rsp >= 0x500000000ULL && rsp < 0x501000000ULL) {
        uint64_t caller = *(volatile uint64_t*)rsp;
        fprintf(stderr, "[TRAP-37d073] caller=0x%lx\n", caller);
    }

    /* Choose ONE continuation strategy: */

    /* (a) Skip past the ud2: continue at next instruction. */
    uc->uc_mcontext.gregs[REG_RIP] = rip + 5;     /* size of ud2+3nops */
    return;

    /* (b) Emulate a return: pop caller addr from rsp. */
    // uint64_t caller = *(uint64_t*)rsp;
    // uc->uc_mcontext.gregs[REG_RIP] = caller;
    // uc->uc_mcontext.gregs[REG_RSP] = rsp + 8;
    // uc->uc_mcontext.gregs[REG_RAX] = 0;        /* status SUCCESS */
    // return;

    /* (c) Diagnostic only: clean exit so logs flush. */
    // _exit(210);
}
```

Always `return` from the handler to resume; never `siglongjmp` mid-PE
without unwinding the PE's locks.

### 2.3 SIGSEGV skip clause (tactical NULL-deref bypass)

```cpp
if (sig == SIGSEGV && rip == 0x180374800ULL) {
    /* mov (%rsi),%eax with rsi=0x10 → fake-descriptor lock field is null.
     * Skip to the post-acquire instruction. */
    fprintf(stderr, "[SKIP-374800] rsi=0x%lx → skip to 0x37485c\n",
            (unsigned long)uc->uc_mcontext.gregs[REG_RSI]);
    uc->uc_mcontext.gregs[REG_RIP] = 0x18037485cULL;
    return;
}
```

Tactical skips compound: if you find yourself adding the third skip in
the same routine, STOP and seed the missing struct field properly
(see §4).

### 2.4 Resolver-slot to DK-id mapping (PE disasm scan)

DK function pointers live in PE .data slots `[0x63fXXX]`. The resolver
loop writes them with this idiom:

```
mov  [0x63fXXX], rax        ; rax = host fn ptr from DK_AbiDispatcher
mov  r8d, 0xNNNNNNNN        ; r8d = DK id (e.g. 0x5001000)
```

Find every binding for a category:

```bash
grep -nE 'mov +\[0x63f[0-9a-f]+\], *rax' /tmp/sqlpal_full.txt > /tmp/slots.txt
grep -nE 'mov +r8d, *0x[0-9a-f]+' /tmp/sqlpal_full.txt > /tmp/dkids.txt
# Pair line-N slot write with the closest preceding/following dkid mov.
```

Once you have `slot_addr ↔ DK id`, runtime instrumentation (§3.1)
confirms which host stub services that id.

---

## 3. DK-ID Mapping Workflow

When boot calls a DK function whose meaning is unclear:

1. **Identify the dispatcher.** `DK_AbiDispatcher` in `dk_pal.cpp` is the
   single entry point. The DK id arrives in a known register (commonly
   the dispatcher itself reads it from a slot or arg). Add a one-shot
   logger that prints `(dk_id, caller_rip, args)` on first call.

2. **Find the slot.** `grep '0xXXXXXXX' /tmp/sqlpal_full.txt` for the
   DK id reveals the resolver block; the immediately-preceding
   `mov [0x63fYYY], rax` is the slot the PE will jump through.

3. **Find consumers.** `grep '\[0x63fYYY\]' /tmp/sqlpal_full.txt`
   gives every callsite. Each callsite is a candidate "wrapper"
   that knows the real signature.

4. **Find the enter-tag string.** Wrappers usually look like:
   ```
   lea rdx, [STRING_ADDR]
   call 0x201bb0          ; the trace-entry helper
   ```
   Decode `STRING_ADDR` (it's an absolute VA in the PE) by reading
   the bytes at that offset in `/tmp/sqlpal_mapped.bin`. The string
   is typically `"FunctionName:enter <fmt args>"` — that's the real
   DK function name.

5. **Confirm at runtime.** Add `[XXX-IN]/[XXX-OUT]` printfs to your
   stub (pattern from wave-32). Re-run; the args printed must match
   the wrapper's `cmp rsi,[rbp-0x18]` identity-echo expectations
   (see waves 32–34 for the 7-arg `VmRegisterRange` discovery).

**Spawn an agent for step 4** if there are >5 consumers (template
in §5.2).

---

## 4. Fake-Descriptor Gotchas

Lessons from waves 38, 40, 44:

- **Partial seeding compounds failures.** Wave-38 stamped a 7-field
  aux descriptor at `[vms+0xa8]`; the PE's lookup uses an entirely
  different descriptor at `0x300000441068`. Wave-40 then intercepted
  at the allocator call site — but the returned descriptor is missing
  fields `[+0x40]` (timing counters), which exposed wave-44's SEGVs at
  `0x374800` and `0x37485c`. Each tactical skip unblocks one frame and
  reveals the next missing field.

- **Iterating SEGV-skips has diminishing returns.** When you've added
  3+ skips in adjacent code, STOP. The descriptor is fundamentally
  incomplete; you're playing whack-a-mole with the consumers of fields
  that were never initialized.

- **Seed only when ALL of:**
  1. The struct is small (<0x100 bytes) and reachable via one slot.
  2. You have a complete field-by-field map (from Ghidra/disasm).
  3. No PE init routine OWNS the struct's lifetime (else you'll race
     with the PE's own writes — wave-38 banner showed our stamp got
     overwritten).

- **Port the ELF init when:**
  1. The struct is large or has nested heap-allocated children
     (descriptor arrays, AVL trees, lock chains).
  2. The PE's own `FUN_0x...` initializer is short and self-contained
     (translate it to C++ in `pe_init_replicas.cpp` — see how
     `pal_boot_write_module_globals` was wired in wave-5b).
  3. Multiple downstream callers consume mutually-dependent fields
     (e.g. bitmap + cap + scope-base must agree).

- **Heuristic:** if `git diff` shows >10 lines of seed values for one
  struct, you're about to commit a wave-38-class mistake. Refactor
  into a translated init function instead.

---

## 5. Sub-Agent Prompt Templates

### 5.1 Decode PE function

```
Decode FUN_0xNNNNNN in /tmp/sqlpal_full.txt.
- Read 200 lines starting at the function entry.
- Identify: arg signature (rcx/rdx/r8/r9 + stack), prologue stack frame
  size, return value register usage, all internal calls, all memory
  writes, and the function's exit conditions.
- Cross-reference any global addresses (0x180c00xxx, 0x63fxxx) with
  /tmp/sqlpal_full.txt grep to find producers/consumers.
- Output: 1-paragraph summary of semantics + a numbered list of
  non-obvious behaviors. Do NOT propose host-side changes.
- Write report to /tmp/waveNN_funNNNNNN.md.
```

### 5.2 Map DK id category

```
Map DK id category 0xNNN in /tmp/sqlpal_full.txt.
- Find every `mov r8d, 0xNNNxxxx` in the resolver region (0x213xxx).
- For each, identify the paired `mov [0x63fXXX], rax` slot.
- For each slot, find consumers via grep '[0x63fXXX]' and locate the
  enter-tag string via the `lea rdx,[STR]; call 0x201bb0` idiom.
- Decode each STR from /tmp/sqlpal_mapped.bin (UTF-8 / ASCII).
- Output table: dk_id | slot_addr | function_name | likely signature.
- Write to /tmp/waveNN_NNN_map.md.
```

### 5.3 Trace upstream stack frames

```
Given crash stack [CRASH-STACK] with RIP=0xN and PE return addresses
A, B, C, D, identify the boot phase.
- For each return addr, grep /tmp/sqlpal_full.txt to find the
  containing function (look for the nearest preceding label/entry).
- Identify the call site within each function (the instruction
  immediately preceding the return addr).
- Determine which arguments were passed at each level (track rcx/rdx
  through the chain).
- Output: 1 line per frame `0xN: FUN_xxx + 0xoff (calls FUN_yyy with
  rcx=..., rdx=...)`, plus a summary of which boot phase this is
  (VM init / scheduler init / scope register / etc).
- Write to /tmp/waveNN_upstream.md.
```

Dispatch in parallel (3 agents at once) when the work is independent.

---

## 6. Automation Opportunities

These would compress the manual steps above. None exist yet — adding
any of them will pay back in the next 5 waves.

1. **`scripts/crash_triage.sh <RIP> <stderr.log>`**
   - Reads the last `[CRASH-STACK]` and `[REGS]` blocks from stderr.log.
   - Prints the matching commit-message reference if RIP is in any
     `git log --grep` body.
   - Greps `/tmp/sqlpal_full.txt` for the containing function entry.
   - Lists nearby PE writes to global slots in the function body.

2. **`scripts/resolve_slot.sh 0x63fXXX`**
   - Greps slot consumers from `/tmp/sqlpal_full.txt`.
   - Scans backwards from each consumer for the nearest `lea rdx,
     [STRING_ADDR]; call 0x201bb0` pair and decodes STRING_ADDR.
   - Output: `slot 0x63fXXX → DK id 0xNNN → "FunctionName"`.

3. **`scripts/fn_decode.sh FUN_0xNNNNNN`**
   - Awks 200 lines starting at the entry from `/tmp/sqlpal_full.txt`.
   - Runs `grep -nE 'mov +\[0x[0-9a-f]+\]'` to extract all globals
     written.
   - Runs `grep -nE 'call +0x[0-9a-f]+'` to extract all internal calls.
   - Pre-formats output ready for an agent prompt.

4. **`scripts/install_trap.py <RVA> <handler-snippet>`**
   - Edits `ntum_bootstrap.cpp` to add a ud2 patch block.
   - Edits `ntum_signals.cpp` to add a SIGILL clause for that RIP.
   - Provides templated register-dump skeleton.

5. **`scripts/grep_log.sh <stderr-tag>`**
   - Standardized view of `[VA-IN]/[VA-OUT]/[EVT-IN]/[EVT-OUT]/[TRAP-…]`
     events in chronological order, with optional filter by RIP range.

6. **DK-id ground-truth table (`docs/dk_id_map.md`)**
   - Generated once from the resolver region; kept in version control.
   - Eliminates re-discovery of the same `slot ↔ id ↔ name` mapping
     that has already been done in waves 26, 32, 34, 35, 37.

---

## Quick Reference

| Memory range            | Owner                                     |
|-------------------------|-------------------------------------------|
| `0x180200000–0x1803a9aa8` | PE .text                                  |
| `0x180c00xxx`           | PE .data globals (LIBOS_PARAMETERS etc.)  |
| `0x18063fxxx`           | DK fn-ptr resolver slots                  |
| `0x300000000000+`       | VmModuleState region                      |
| `0x321000000`           | LIBOS_PARAMETERS buffer (PE-managed)      |
| `0x500000000`           | Host boot stack                           |
| `0x7ffe0000`            | KUSER_SHARED_DATA (user)                  |
| `0xfffff78000000000`    | KUSER_SHARED_DATA (kernel alias — patched) |

| Special RIP             | Meaning                                   |
|-------------------------|-------------------------------------------|
| `0x1803a0880`           | `int $0x2c` __fastfail                    |
| `0x1802a855a`           | RtlRaiseStatus retry — patched to ud2     |
| `0x180213dc0`           | panic_unsupported_abi entry               |
| `0x180201bb0`           | trace-entry helper (enter-tag emitter)    |

| File                              | Purpose                       |
|-----------------------------------|-------------------------------|
| `drawbridge-host/ntum_signals.cpp`| All SIGILL/SIGSEGV handlers   |
| `drawbridge-host/ntum_bootstrap.cpp` | PE patches + boot init     |
| `drawbridge-host/dk_pal.cpp`      | DK_AbiDispatcher + DK stubs   |
| `drawbridge-host/pal_vm.cpp`      | VM-related DK stubs           |
| `drawbridge-host/pe_init_replicas.cpp` | Translated PE init bodies |
| `/tmp/sqlpal_full.txt`            | PE disassembly                |
| `/tmp/sqlpal_mapped.bin`          | PE raw bytes (for strings)    |
| `stderr.log`                      | Last run's diagnostic output  |
