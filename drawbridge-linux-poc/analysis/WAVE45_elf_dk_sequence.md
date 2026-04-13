# Wave-45: Baseline DK Call Sequence (ELF host vs. drawbridge-host)

## Executive summary

The ELF `sqlservr` host **loads `sqlpal.dll` via the DK ABI**:
`DkStreamOpen → DkVirtualMemoryAllocate(reserve PE region) →
DkStreamMapPeBinary(per section)`. Our drawbridge-host bypasses DK
entirely: `pe_loader_parse_and_map()` raw-mmaps the PE
(`drawbridge-host/main.cpp:88`) then jumps into sqlpal's
`FUN_0x37f700` with the PE image **never registered with the NTUM's
`VmModuleState`** — exactly the gap before `FUN_0x37cf68`.

The missing call: `DkVirtualMemoryAllocate` (call_type `0x2001000`,
kind=1, mode=3) populates `VmModuleState+0xa8` on the ELF host. Today
we paper over this in `DK_VmIdentityEcho`
(`drawbridge-host/dk_pal.cpp:1602-1625`) with a synthetic descriptor.

## 1. Expected DK sequence during boot

PE-load orchestrator: `FUN_00251e30` ("Load guest", `palcalls.cpp`,
sqlservr_FULL.c:122794), called from `FUN_002051e0` (:69779). It
stores entry/base/size in `pal_instance+0x170/180/188` BEFORE
`FUN_002053e0` (:69862) builds `WINDOWS_LIBOS_PARAMETERS` and BEFORE
the PE entry runs.

Marshallers: `FUN_002b6b40 / 6c00 / 6d90 / 71d0`
(`sqlpal/UtilLibs/AbiHost/PalMemoryMapPeBinary.cpp`,
sqlservr_FULL.c:193740-194450). DK trampoline is `FUN_001ae6e0` (:647),
varargs.

| # | call_type | Function | Args (ELF source) | We call? |
|---|-----------|----------|-------------------|----------|
| 1 | `0x7001000` v0 | DkAbiGetVersion → flag=1 | (resolution-time stub) | y (dk_pal.cpp:1158) |
| 2 | `0x7002000` v0 | DkAbiGetFunction → flag=2 | (resolution-time stub) | y (dk_pal.cpp:1161) |
| 3 | `0x1001000` | DkStreamOpen (FUN_0024e1f0) | (path "sqlpal.dll", flags, share, attr, &handle) | n (we mmap directly) |
| 4 | `0x1003000` | DkStreamRead — read PE header | (handle, off=0, len=4096, &buf) | n |
| 5 | `0x2001000` | **DkVirtualMemoryAllocate (RESERVE PE)** | (`addr=PE_base, len=size&~0xFFF, kind=1, mode=3, &out_base, &out_size`) — sqlservr_FULL.c:193886 | **n (CRITICAL GAP)** |
| 6 | `0x1007000` | DkStreamMapPeBinary (per section) | (stream, base, length, kind=5, offset, prot, &out_base, &out_size) — sqlservr_FULL.c:194060 | n (we mmap raw) |
| 7 | `0x1003000` | DkStreamRead — for non-mapped sections | (stream, file_off, len, &buf) — sqlservr_FULL.c:194040 | n |
| 8 | `0x8002000` | DkRandomBitsRead — for security cookie | (&buf, 2) — sqlservr_FULL.c:122849 | n (PE does this internally) |
| 9 | `0x6001000` | DkConsoleCreate (logging path) | — | n |
|10 | (PE entry FUN_0x37f700 invoked) | VM-module-state init | reads `[0xc00820]+0x38/+0x40` for VM window | partially (ntum_bootstrap.cpp:124-138 stamps it) |
|11 | `0x5001000`/`0x5002000` | "VmIdentityEcho" callbacks during PE init | (ctx, va_start, va_end, kind, idx, *out_start, *out_end) | y (dk_pal.cpp:1572) |
|12 | `0x2001000` | DkVirtualMemoryAllocate (kernel heap pages) | from PE allocator FUN_0x384fbc | y (dk_pal.cpp:1113) |

Steps 3-7 are the missing host-side PE-loader DK chain.

---

## 2. Gap analysis

ELF host does, we don't:

- **DK_StreamOpen on guest** (FUN_0024e1f0 :120398). We call
  `pe_loader_load_sfp + pe_loader_map_pe_from_sfp` (main.cpp:62-72).
- **DkVirtualMemoryAllocate to reserve PE image VA**. In
  FUN_002b6d90 the ELF issues
  `FUN_001ae6e0(PE_base, size, 1, 3, &out_base, &out_size)`, with
  `out_base==PE_base, out_size==size` asserted (:193886, :193907).
  6-arg DK_VirtualMemoryAllocate, kind=1, mode=3. **This is the
  call that populates `VmModuleState+0xa8`'s module-descriptor
  list with the PE image.**
- **DkStreamMapPeBinary per section** (:194060):
  `FUN_001ae6e0(stream, section_va, size, 5, file_off, prot,
  &out_base, &out_size)`.
- **FUN_0021a770(stream, entry, length)** dynlink-list registration
  after load (:122877). Host bookkeeping, not DK.
- **Build LIBOS_PARAMETERS from load result**. FUN_002053e0
  (:69862-69870) reads `instance+0x180/0x188` (set by FUN_002051e0
  from the load) — we hardcode in ntum_bootstrap_init()
  (main.cpp:119-122, ntum_bootstrap.cpp:67-69).

Our host does, ELF host doesn't:

- Stamp `[0x18063f8c0]=1` and `[0x18063f8c8]=DK_AbiDispatcher`
  directly (ntum_bootstrap.cpp:178-179). ELF resolves via
  `0x7001000`/`0x7002000` v0 dispatch.
- Pre-allocate KTHREAD/sched/TEB into BOOT_STRUCTS_ADDR
  (ntum_bootstrap.cpp:270+). ELF lets PE call DkThreadCreate
  (0x4001000) after VM init.
- Synthesize the module descriptor at `vms+0xa8` inside
  DK_VmIdentityEcho (dk_pal.cpp:1607-1625) — workaround for the
  missing PE-image registration.

---

## 3. The PE image registration specifically

**ELF host pre-registers the PE image BEFORE handing control to PE
entry.** Order:

  1. PAL boot (FUN_00204680) brings up logging/threads/I-O.
  2. **FUN_002051e0 → 251e30 → 251c30 → 2b6d90 calls
     DkVirtualMemoryAllocate(PE_base, size, 1, 3) → registers PE
     image with NTUM VmModuleState (`vms+0xa8`).**
  3. FUN_002b6c00 → 2b71d0 calls DkStreamMapPeBinary per section.
  4. FUN_002053e0 builds WINDOWS_LIBOS_PARAMETERS from loaded
     PE's base/length.
  5. PE entry (FUN_0x3a04d0 → FUN_0x37f700) runs; `vms+0xa8`
     already has the PE-image descriptor that FUN_0x37cf68
     ReservePeImageRange walks via FUN_0x3804b8.

Exact DK call (decoded from sqlservr_FULL.c:193886):

```
DkVirtualMemoryAllocate(
    inout addr   = PE_image_base,    // 0x180000000
    inout length = size_aligned,     // (raw_size + 0xFFF) & ~0xFFF
    kind         = 1,                // MEM_RESERVE
    mode         = 3                 // PAGE_READWRITE / page-attribute=3
);
// Post: *addr == PE_image_base, *length == size_aligned (asserted)
```

call_type for `DK_VirtualMemoryAllocate` = `0x2001000`
(drawbridge-host/dk_pal.cpp:1113). The 6-arg variant matches the
ELF's `FUN_001ae6e0(addr, len, kind, mode, &out_base, &out_size)`.

**Why our `FUN_0x37f700` doesn't register the PE image internally:**
it never tried to. `FUN_0x37f700` only builds the *managed* VM
descriptor slabs for the LibOS heap region (vm_base, size_shift,
LO/HI slabs at `self+0xE8`, see drawbridge-host/pal_vm.cpp:528-567).
The PE image lives OUTSIDE that range (PE_base = 0x180000000;
LibOS heap = 0x300000000+). Per ELF design, the PE image is
registered by the *loader* code path, not by the VM-module
constructor. Our host's loader path
(`pe_loader_parse_and_map`) doesn't make any DK calls at all, so
nothing populates `vms+0xa8` for the PE image.

---

## 4. Specific action items

All citations are line numbers in `analysis/sqlservr_FULL.c`.

A. **Add a host-side "load PE via DK" stage** modeled on
   `FUN_00251e30` (sqlservr_FULL.c:122794-122898) and
   `FUN_00251c30` (122699-122790). It should run AFTER
   `dk_pal_init()` (drawbridge-host/main.cpp:106) but BEFORE
   `ntum_bootstrap_init()`. The minimum content per-PE:

     a. Open SFP entry as a DK stream (DK_StreamOpen 0x1001000;
        for now we can register a synthetic stream backed by our
        SFP buffer).
     b. Issue **DK_VirtualMemoryAllocate(addr=PE_base, len=size,
        kind=1, mode=3, out_base, out_size)** — call_type
        `0x2001000` — to reserve the PE image VA range. This is
        the call that populates `VmModuleState+0xa8` in the real
        host (sqlservr_FULL.c:193886).
     c. For each PE section issue
        **DK_StreamMapPeBinary(stream, va=section_base, len=size,
        kind=5, offset=file_off, prot, out_base, out_size)** —
        call_type `0x1007000` (sqlservr_FULL.c:194060).

B. **Move the synthetic descriptor stamp out of
   `DK_VmIdentityEcho`** (drawbridge-host/dk_pal.cpp:1602-1625).
   Once (A) is in place, the descriptor will be created by the
   real DK_VirtualMemoryAllocate path and the workaround becomes
   harmful: it can race with the real registration. Replace the
   stamp with a sanity-assert that `vms+0xa8 != 0` by the time
   the first echo arrives.

C. **Defer setting `[0x18063f8c0]=1` and `[0x18063f8c8]=disp`**
   (drawbridge-host/ntum_bootstrap.cpp:178-179) until AFTER the
   PE has issued its `0x7001000`/`0x7002000` v0 first-pass
   resolutions — match the ELF's two-phase ABI handshake at
   sqlservr_FULL.c:69722 (`FUN_001be270` ABI-resolve loop).
   Stamping them up front works today but masks the timing of
   resolution; if the PE ever switches to v1 second-pass it will
   misbehave.

D. **Pull image_base / image_length from the load step** (not
   from `pe_loader_parse_and_map` return values) when filling
   `WINDOWS_LIBOS_PARAMETERS`. The ELF wires this through
   `g_pal_instance+0x180/0x188` (sqlservr_FULL.c:69845-69846)
   then reads it back at sqlservr_FULL.c:69867. Mirror that
   storage in drawbridge-host/pal_boot.cpp:158-176 so the values
   used by `FUN_0x37f700`'s VMBase/VMSize derivation are the
   ones the DK loader actually mapped.

E. **Add `FUN_0021a770`-equivalent dynlink-list registration**
   (sqlservr_FULL.c:122877) once (A) lands. It's not a DK call
   but it is what binds the module's IAT to subsequent stream
   reads. Without it, secondary DLL loads (DkDll.dll, etc.) that
   the PE attempts during boot will skip the loaded-module list
   and re-issue StreamOpen.

Order of operations recommended for the next wave: **A first** (this
is the wave's headline fix), then B (cleanup once A works), then C/D
(timing/correctness), then E (follow-on DLL loads).

---

## Files referenced

- `analysis/sqlservr_FULL.c` (RVAs cited inline)
- `analysis/REAL_BOOT_SEQUENCE.c`, `analysis/ANNOTATED_BOOT_FUNCTIONS.c`
- `drawbridge-host/{main,ntum_bootstrap,pal_boot,pal_vm,dk_pal}.cpp`
