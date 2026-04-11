# Drawbridge Linux PoC

A proof-of-concept implementation of Microsoft's Drawbridge architecture for
running Windows PE executables on Linux.

## Background

Microsoft's Drawbridge (ASPLOS 2011) introduced a **library OS** architecture
that refactors Windows into three layers:

1. **Picoprocess** - A minimal isolation container with ~45 syscall surface
2. **Library OS** - Windows APIs implemented as a user-mode library (~16MB)
3. **PAL (Platform Abstraction Layer)** - ~45 primitive operations bridging to the host

This is how **SQL Server on Linux** works: Microsoft uses SQLPAL (derived from
Drawbridge) to run the full SQL Server engine on Linux without rewriting it.

```
+---------------------------------------------+
|        Windows Application (.exe)           |
|        (unmodified PE binary)               |
+---------------------------------------------+
|        Win32 API / NT API                   |
|        (library OS - user mode stubs)       |
+---------------------------------------------+
|        Platform Abstraction Layer           |
|        (~45 primitive operations)           |
+---------------------------------------------+
|        Linux Kernel                         |
|        (host OS)                            |
+---------------------------------------------+
```

## Architecture of this PoC

### Components

| Component | Directory | Description |
|-----------|-----------|-------------|
| PE Loader | `loader/` | Parses PE/COFF headers, maps sections into memory |
| PAL | `pal/` | Platform Abstraction Layer - maps ~45 operations to Linux syscalls |
| Library OS | `libos/` | Minimal Win32 API stubs (kernel32, ntdll) |
| Test Programs | `test/` | Simple Windows programs cross-compiled with MinGW |
| Runner | `main.c` | Orchestrator that ties all components together |

### PAL Operations (Linux Implementation)

| Category | PAL Function | Linux Mapping |
|----------|-------------|---------------|
| Memory | `pal_mem_alloc` | `mmap()` |
| Memory | `pal_mem_free` | `munmap()` |
| Memory | `pal_mem_protect` | `mprotect()` |
| Threading | `pal_thread_create` | `clone()` / `pthread_create()` |
| Threading | `pal_thread_exit` | `pthread_exit()` |
| I/O | `pal_stream_open` | `open()` |
| I/O | `pal_stream_read` | `read()` |
| I/O | `pal_stream_write` | `write()` |
| I/O | `pal_stream_close` | `close()` |
| Process | `pal_process_exit` | `exit()` |
| Sync | `pal_mutex_create` | `pthread_mutex_init()` |
| Sync | `pal_event_create` | `eventfd()` |
| Time | `pal_time_query` | `clock_gettime()` |
| Crypto | `pal_random_read` | `getrandom()` |
| Console | `pal_console_write` | `write(STDOUT)` |

### PE Loading Process

1. Read PE/COFF headers from the .exe file
2. Validate PE signature and architecture (x86-64)
3. Map each section (.text, .data, .rdata, .bss) into memory with correct permissions
4. Process the Import Address Table (IAT) - resolve Win32 API imports to our libos stubs
5. Apply relocations if the image cannot be loaded at its preferred base address
6. Transfer control to the PE entry point

## Building

```bash
# Requires: gcc, MinGW-w64 (for cross-compiling test programs)
make all

# Build only the loader (no test programs)
make loader

# Cross-compile test programs
make test-programs
```

## Running

```bash
# Run a simple Windows executable on Linux
./drawbridge-run test/hello.exe
```

## References

- [Rethinking the Library OS from the Top Down (ASPLOS 2011)](https://www.microsoft.com/en-us/research/publication/rethinking-the-library-os-from-the-top-down/)
- [Haven: Shielding Applications from an Untrusted Cloud (OSDI 2014)](https://www.microsoft.com/en-us/research/publication/shielding-applications-from-an-untrusted-cloud-with-haven/)
- [Gramine (open-source library OS)](https://github.com/gramineproject/gramine)
- [SQL Server on Linux architecture](https://cloudblogs.microsoft.com/sqlserver/2016/03/07/sql-server-on-linux/)
- [Microsoft Research Drawbridge project](https://www.microsoft.com/en-us/research/project/drawbridge/)
