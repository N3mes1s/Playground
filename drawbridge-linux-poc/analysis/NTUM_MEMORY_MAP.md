# NTUM Memory Map (from strace analysis)

## Boot Sequence (observed syscalls)

1. ELF host starts, loads shared libs (libc, libpthread, libssl, etc.)
2. Opens SFP archives: secforwarder, sqlagent, sqlconnector, system.wmi,
   system, system.common, system.certificates, system.security, system.tzdb, system.netfx
3. Maps sqlpal.dll from system.sfp (fd 8) at 0x3FFF87400000
4. Sets up control pages at 0x400000000000
5. Creates LibOS VM ranges
6. Spawns threads for NTUM kernel
7. NTUM boots, loads ntdll.dll, kernel32, etc.
8. Loads target application
9. Transfers control to app entry point

## LibOS Address Space

```
Address              Size       Flags                    Purpose
──────────────────────────────────────────────────────────────────
0x100000000          4KB        RW                       Control page (PEB?)
0x200000000          4KB        RW (initial)             NTUM image base
0x200040000          4KB        R                        PE header
0x200041000          ~1MB       RX                       .text (code)
0x200142000          256KB      R                        .rdata
0x20018d000          40KB       R                        .pdata
0x20019b000          ~456KB     R                        other sections
0x200210000+         varies     varies                   Additional DLL mappings
0x300000000          1GB        RW NORESERVE             LibOS kernel heap
0x300000000000       ~4.5MB     RW                       Thread environment
0x300000442000       8KB        RW                       Thread data
0x3FFF80000000       64KB       RW                       Kernel control
0x3FFF87400000       16MB       RW (from fd 8)           sqlpal.dll raw mapping
0x3FFF89000000+      varies     RW                       Registry hives, config
0x400000000000       4KB        RW                       High control page
0x500000000          1GB        RW NORESERVE             Application heap
0x600000000          4KB        RW                       Control
0x700000000          4KB        RW                       Control
0x800000000          64KB       RW NORESERVE             Config/registry
0x900000000          64KB       RW NORESERVE             Additional control
```

## Key Observations

1. **2GB reserved** for heaps (0x300000000 + 0x500000000, both 1GB MAP_NORESERVE)
2. **sqlpal.dll** mapped from SFP file at high address (0x3FFF87400000)
   then sections copied to 0x200000000 with correct permissions
3. **PE sections** get mprotect: .text → RX, .rdata → R, .data → RW
4. **Thread env** at 0x300000000000 (separate from LibOS heap)
5. **36,191 syscalls** during boot (mostly mmap/mprotect)
6. **No clone()** in trace - threads managed inside NTUM via pthreads

## Boot Timeline (thread IDs)

- TID 26505: Main thread - opens SFPs, maps sqlpal.dll
- TID 26942: First NTUM thread - sets up LibOS VM, loads PE sections
- TID 27256-27267: Kernel initialization threads
- TID 29607-29820: Application heap setup
- TID 30563: Application thread (writes to stdout)
