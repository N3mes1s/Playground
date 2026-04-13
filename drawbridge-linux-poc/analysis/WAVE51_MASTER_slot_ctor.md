# WAVE-51 MASTER — Slot-descriptor constructor chain (FUN_0x37f128)

Synthesis of waves 51-a, 51-b, 51-c, 51-d. All citations are `/tmp/sqlpal_full.txt` line numbers.

## Entry

- Caller: `FUN_0x37cf68` at line 434727 (RVA 0x37d067)
- Signature: `FUN_0x37f128(rcx = [vms+0xa8] /*pool*/, rdx = vms)`
- Return: `rax = pool_base + 0x88 * slot_idx` (slot descriptor, a.k.a. `process_ctx`)

```
caller FUN_0x37cf68 (line 434727)
  -> FUN_0x37f128                    (line 437101, Wave-51-a)
       FUN_0x244cd0                  (line 437115, thread/owner)
       FUN_0x21ad20                  (line 437126, ACQUIRE pool+0x40)
       FUN_0x384fbc                  (line 437132, bitmap_find_and_set -> slot_idx)
       FUN_0x37a218                  (line 437161, region prepare)
       FUN_0x380058                  (line 437209, Wave-51-b)
         FUN_0x3800ac                (line 438107, Wave-51-c)
           FUN_0x380110(desc, 0)     (line 438138, Wave-51-d) -> +0x80 = 0
       +0x18 = 1                     (line 437211)
       +0x60 = vms                   (line 437213)
       FUN_0x380110(desc, 1)         (line 437214) -> +0x80 = 1
       FUN_0x380110(desc, 2)         (line 437217) -> +0x80 = 2
       FUN_0x37a1c8                  (line 437220, register with vms)
       FUN_0x21ae70                  (line 437226, RELEASE pool+0x40)
       FUN_0x244cd0                  (line 437230)
  <- rax = desc                      (line 437238)
```

## Pool layout (fields of `rcx = [vms+0xa8]`)

| Offset (pool) | Semantic                                 | Consumed at       |
|--------------:|------------------------------------------|-------------------|
| +0x10         | **pool slot-array base**                 | line 437207       |
| +0x18         | `va_offset_base` (added into +0x48)      | line 437205       |
| +0x28         | generation counter (u64)                 | lines 437127, 437222 |
| +0x38         | stride/meta (added into +0x68)           | lines 437136, 437203 |
| +0x40         | pool lock                                | line 437122 (acq), 437226 (rel) |

- **Pool base address symbolic form: `[[vms+0xa8]+0x10]`**. Actual numeric address is runtime-allocated — not a `.data` global. `[vms+0xa8]` itself points to a pool object whose construction we have not decoded; it is likely allocated early in the vms init path. For host-side reproduction this is a BSS-style region of `0x88 * N_slots` bytes.
- `N_slots` upper bound: the bitmap search at 437131 uses `r8 = [pool+0x28] - 1` as cap, so it is dynamic.

## Slot stride

**0x88 bytes** (line 437206 `imul $0x88,%r15,%rdi`). Confirmed by all three sub-functions operating within that window (highest offset written: +0x80 by FUN_0x380110, 4 bytes — so fields used span +0x08..+0x83, fitting within 0x88).

## Per-function field-write counts

| Function       | # direct desc writes | Offsets written                      |
|----------------|----------------------|--------------------------------------|
| FUN_0x37f128   | **2**                | +0x18, +0x60                         |
| FUN_0x380058   | **4**                | +0x48, +0x40, +0x70, +0x68           |
| FUN_0x3800ac   | **4**                | +0x60, +0x50, +0x58, +0x70           |
| FUN_0x380110   | **1** (executed 3x)  | +0x80                                |

Note: +0x60 is written by FUN_0x3800ac (zero, line 438132) then overwritten by FUN_0x37f128 (vms, line 437213) — two writes, final value is `vms`. +0x70 is written twice (FUN_0x380058 line 438111 and FUN_0x3800ac line 438139) — same value `0x8000`, idempotent.

## Final descriptor layout after FUN_0x37f128 returns

| Offset | Final value                                    | Writer (line)                    | Wave-50a? |
|-------:|------------------------------------------------|----------------------------------|:---------:|
| +0x00  | (unchanged from pool construction)             | --                               | match     |
| +0x08  | (unchanged; later set by FUN_0x37d23c list-insert) | --                           | match     |
| +0x10  | (unchanged)                                    | --                               | match     |
| +0x18  | `1`                                            | FUN_0x37f128 (437211)            | match     |
| +0x20  | (unchanged — pool-construction lock)           | --                               | match     |
| +0x28  | (unchanged — caller FUN_0x381d8c will set later) | --                             | match     |
| +0x38  | (pool-construction, read-only from here)       | --                               | match     |
| +0x40  | `0`                                            | FUN_0x380058 (438108)            | match     |
| +0x48  | `[pool+0x18] + (slot_idx << 31)`               | FUN_0x380058 (438106)            | match     |
| +0x50  | `0x80000000`                                   | FUN_0x3800ac (438135)            | match     |
| +0x58  | `&desc` (self-link)                            | FUN_0x3800ac (438137)            | match     |
| +0x60  | `vms`                                          | FUN_0x37f128 (437213)            | match     |
| +0x68  | `(slot_idx << 12) + [pool+0x38]`               | FUN_0x380058 (438113)            | match     |
| +0x70  | `0x8000`                                       | FUN_0x380058 (438111) / FUN_0x3800ac (438139) | match |
| +0x78  | **UNWRITTEN by this chain** (asserted == 0 at 438122) | --                         | match — gap |
| +0x80  | `2` (after 0 -> 1 -> 2)                        | FUN_0x380110 x3 (438138, 437214, 437217) | match |

## State machine on +0x80 (per Wave-51-d)

| Transition       | Caller          | Line   | Pre-condition (assertion)           |
|------------------|-----------------|--------|--------------------------------------|
| `* -> 0`         | FUN_0x3800ac    | 438138 | cur in {0, 4, 5}                     |
| `0 -> 1`         | FUN_0x37f128    | 437214 | cur == 0                             |
| `1 -> 2`         | FUN_0x37f128    | 437217 | cur == 1                             |

Dispatch table supports additional transitions (2->3, 0->4, {2,3}->5) not exercised in alloc path.

## Asserts summary

- FUN_0x3800ac line 438122: **`desc[+0x78] == 0`** on pool-slot reuse. Caller must zero +0x78 during slot cleanup (not during construction by this chain).
- FUN_0x380110: predecessor-state assertions per state table above.
- FUN_0x37f128 post-`FUN_0x37a218` block (lines 437173-437202): three checks on the out-buffer (`[rsp+0x90] == [pool+0x38] + slot*0x1000`, `[rsp+0xa0] == 0`, `[rsp+0xa8] == 0x1000`).

## +0x78 gap — NOT resolved by this chain

Wave-50a identified `+0x78` (owner-tag mirror) as the "external caller population" gap because FUN_0x380708 asserts `[desc+0x78] == [desc+0x60]` (== vms) at line 438535. This wave confirms:

1. FUN_0x3800ac only **asserts** `+0x78 == 0` on entry — it does NOT write it.
2. No other function in the constructor chain (FUN_0x37f128 body, FUN_0x380058, FUN_0x380110) touches `+0x78`.
3. Therefore the write must occur between FUN_0x37f128 return (line 434728) and FUN_0x380708 entry (line 434825).
4. Per Wave-50a candidate list, the writer is inside either `FUN_0x3804b8` (line 434737) or `FUN_0x381d8c` (line 434811). **Decoding one of those is the next wave's target.**

## Implementation recipe for host-side reproduction

### What the host needs

- **Pool storage**: a BSS-style array of `0x88 * N_slots` bytes, zero-initialised. Mapping to our `drawbridge-host` world: this is the `process_ctx` pool that sits logically at `[vms+0xa8]+0x10`.
- **Pool header** holding:
  - `pool+0x10` = pointer to the slot array above.
  - `pool+0x18` = `va_offset_base` (constant across slots; treated as an offset that ends up in `+0x48` of each descriptor).
  - `pool+0x28` = `generation_counter` (u64, `cap`).
  - `pool+0x38` = per-slot stride/meta (added into `+0x68`).
  - `pool+0x40` = a lock object compatible with our FUN_0x21ad20 / 0x21ae70 pair (or a noop stub for single-threaded boot).
- **Bitmap** for slot allocation — we control the allocation, so for a single-slot boot a monotonic counter suffices.
- Slot descriptor type: 0x88-byte struct with the offsets above.

### Init order for one slot

Given host `drawbridge_slot_ctor(pool, vms) -> desc*`:

```c
1. lock_acquire(&pool->lock);                              // FUN_0x21ad20 equiv
2. uint64_t slot = bitmap_alloc(pool);                     // FUN_0x384fbc equiv
3. desc = pool->base + slot * 0x88;
4. assert(desc->f78 == 0);                                 // FUN_0x3800ac prologue
5. // FUN_0x380058 body prefix
   desc->f48 = pool->va_offset_base + (slot << 31);        // +0x48
6. // FUN_0x3800ac body
   desc->f60 = 0;                                           // +0x60 (cleared)
   desc->f50 = 0x80000000ULL;                               // +0x50
   desc->f58 = (uintptr_t)desc;                             // +0x58 self-link
   desc->f80 = 0;                                           // +0x80 via FUN_0x380110(0)
   desc->f70 = 0x8000ULL;                                   // +0x70
7. // FUN_0x380058 body suffix
   desc->f40 = 0;                                           // +0x40 (AVL root)
   desc->f70 = 0x8000ULL;                                   // +0x70 (redundant)
   desc->f68 = (slot << 12) + pool->f38_meta;               // +0x68
8. // FUN_0x37f128 body
   desc->f18 = 1;                                           // +0x18
   desc->f60 = (uintptr_t)vms;                              // +0x60 (owner)
   assert(desc->f80 == 0);
   desc->f80 = 1;                                           // via FUN_0x380110(1)
   assert(desc->f80 == 1);
   desc->f80 = 2;                                           // via FUN_0x380110(2)
9. // (Optional) FUN_0x37a1c8-equivalent registration with vms
10. lock_release(&pool->lock);
11. return desc;
```

### Fields still requiring external population AFTER this ctor chain

| Field  | Who should write                                | Required by           |
|--------|-------------------------------------------------|-----------------------|
| +0x28  | FUN_0x381d8c (AVL key / va_base) — Wave-47     | FUN_0x380708 line 438556 (AVL key cmp) |
| +0x78  | **UNKNOWN** — FUN_0x3804b8 or FUN_0x381d8c (Wave-52 target) | FUN_0x380708 line 438535 (owner-mirror assert) |
| +0x08, +0x10, +0x18(back-ptr) | FUN_0x37d23c (vms-list insert) | List traversal from vms+0x48 |

Everything else is pool-construction-time state (not re-initialised per alloc) and must only be set up once when the pool itself is created.

### Asserts the host must respect

1. Pool slot on free: write `desc->f78 = 0` so the next alloc's FUN_0x3800ac prologue passes (line 438122).
2. `desc->f80` monotonic 0 -> 1 -> 2 during alloc (FUN_0x380110 checks previous state each step).
3. After the ctor: `desc->f80 == 2` (the caller at 434730 enforces this).
4. Before FUN_0x380708 insert: `desc->f78 == desc->f60` (must equal vms) — NOT satisfied by this chain, needs downstream wave.
5. `desc->f70 == 0x8000` always after ctor (used as bitmap_max by downstream bitmap probe).

### Numeric constants encountered

| Constant       | Meaning                          |
|----------------|----------------------------------|
| `0x88`         | slot stride                      |
| `0x80000000`   | per-slot `+0x50` region size     |
| `0x8000`       | per-slot `+0x70` bitmap/page cap |
| `0x1000`       | base page size (FUN_0x37a218 arg, asserted in `[rsp+0xa8]`) |
| `'Vmm '`(0x206d6d56) | pool tag passed to FUN_0x37a218 at 437155 |
| `0x3`          | arg-5 constant passed to FUN_0x37a218 |

## Provenance / cross-checks

- Wave-50a layout table: every row is consistent with Wave-51 decode (see per-row "match" column above).
- Wave-50b state-machine: confirmed, but with the correction that the 0-write comes from FUN_0x3800ac, not from FUN_0x380058 directly. FUN_0x37f128 issues only the 1 and 2 transitions.
- Wave-48-c's FUN_0x37e4c0 `+0x74` writer is structurally parallel but operates on a different descriptor type (PE-image), confirmed distinct by Wave-50b.

## Open items carried to Wave-52

- `+0x78` writer (FUN_0x3804b8 vs FUN_0x381d8c).
- Pool-construction code for `[vms+0xa8]` — if the host is to allocate and hand-initialise this pool, the construction path (likely in `PalVmInit` / `vms_construct`) needs a separate wave.
- `FUN_0x37a218` body (region prep) — called but not decoded here; not a descriptor writer per this analysis but its out-buffer side effects (asserted at 437173-437202) suggest it manages another table.

## File manifest

- `analysis/WAVE51_fun_37f128.md`
- `analysis/WAVE51_fun_380058.md`
- `analysis/WAVE51_fun_3800ac.md`
- `analysis/WAVE51_fun_380110.md`
- `analysis/WAVE51_MASTER_slot_ctor.md`  (this file)

All decoded instruction-by-instruction with line/RVA citations. No instructions remain un-explained in the four subject functions.
