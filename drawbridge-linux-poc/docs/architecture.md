# Drawbridge Architecture Deep Dive

## Microsoft's Original Drawbridge

### The Problem

Traditional OS architecture couples applications to a specific kernel:
- Windows apps call ~400+ NT kernel syscalls
- Apps depend on kernel version, installed DLLs, registry state
- Porting means reimplementing the entire API surface (Wine approach)
- VMs carry a full OS kernel (heavyweight)

### The Drawbridge Solution

**Key insight**: Most of the Windows API can run in user mode. Only ~45
primitive operations truly require kernel support.

```
Traditional:
  App -> Win32 DLL -> NT Kernel (400+ syscalls) -> Hardware

Drawbridge:
  App -> Win32 DLL -> Library OS (user mode) -> PAL (45 calls) -> Host Kernel
```

### Picoprocess

A picoprocess is an empty address space with special trap handling:

1. Host kernel creates an empty address space
2. Marks it as "pico" - syscalls get redirected to the library OS, not the host
3. Library OS binary is loaded into this space
4. Only PAL calls can exit the picoprocess to the host

Security properties:
- Cannot access host file system, registry, network directly
- All external access mediated by PAL (policy-controllable)
- Attack surface: ~45 operations vs ~400+ traditional syscalls

### Library OS

The library OS contains:
- **ntdll.dll** (NT system call layer - reimplemented in user mode)
- **kernel32.dll** (Win32 API)
- **user32.dll / gdi32.dll** (graphics - software rendered)
- **ws2_32.dll** (Winsock networking)
- **msvcrt.dll** (C runtime)
- Registry emulation (serialized hive file)
- File system virtualization (mapped to PAL I/O streams)

Total size: ~16MB (vs ~20GB full Windows installation)

### PAL Interface

~45 operations in these categories:

**Memory (5)**
- Allocate virtual memory
- Free virtual memory
- Protect memory (RWX permissions)
- Query memory info
- Map file to memory

**Threading (7)**
- Create thread
- Exit thread
- Suspend/Resume thread
- Get thread ID
- Thread-local storage
- Set thread context

**I/O Streams (8)**
- Open stream (file, pipe, network)
- Read/Write stream
- Close stream
- Map stream to memory
- Flush stream
- Query stream attributes
- Set stream length

**Process (3)**
- Create picoprocess
- Exit process
- Get process ID

**Synchronization (5)**
- Create mutex
- Create event
- Wait for object(s)
- Signal event
- Release mutex

**Time (3)**
- Query system time
- Create timer
- Sleep

**System (4)**
- Query system info (CPU count, memory)
- CPUID
- Get random bytes
- Debug output

## SQL Server on Linux (SQLPAL)

### Why It Works

SQL Server already had an internal abstraction: **SQLOS** (SQL Server Operating
System). SQLOS handles:
- Cooperative thread scheduling (fibers)
- Memory management (buffer pool, memory grants)
- I/O completion (asynchronous I/O)
- Lock management

SQLOS was designed for performance, not portability, but its abstraction
made porting feasible.

### SQLPAL Architecture

```
+------------------------------------------+
|          SQL Server Engine               |
|   (Query processor, Storage engine,      |
|    Replication, Full-text search, ...)   |
+------------------------------------------+
|          SQLOS (SQL Operating System)    |
|   (Scheduler, Memory, I/O, Locks)       |
+------------------------------------------+
|          Library OS Layer                |
|   (Win32 stubs from Drawbridge lineage)  |
+------------------------------------------+
|          SQLPAL                          |
|   (PAL implementation for Linux)         |
+------------------------------------------+
|          Linux Kernel                    |
|   (epoll, io_uring, mmap, pthreads)     |
+------------------------------------------+
```

### Key SQLPAL Mappings

| Windows API | SQLPAL Linux Implementation |
|------------|---------------------------|
| `CreateThread` | `pthread_create` |
| `VirtualAlloc` | `mmap(MAP_ANONYMOUS)` |
| `CreateFile` | `open()` |
| `ReadFile` / `WriteFile` | `pread()` / `pwrite()` |
| `WaitForSingleObject` | `futex()` or `pthread_cond_wait` |
| `CreateEvent` | `eventfd()` |
| `GetSystemTimeAsFileTime` | `clock_gettime(CLOCK_REALTIME)` |
| `QueryPerformanceCounter` | `clock_gettime(CLOCK_MONOTONIC)` |
| `IOCP (I/O Completion Ports)` | `epoll` / `io_uring` |
| `InitializeCriticalSection` | `pthread_mutex_init` |
| `TlsAlloc` / `TlsGetValue` | `pthread_key_create` / `pthread_getspecific` |
| Windows Registry | Configuration files |
| Windows Event Log | `syslog` |

### Performance

SQLPAL adds minimal overhead because:
1. PAL calls are infrequent relative to SQL Server's internal work
2. Memory-intensive operations (buffer pool) use `mmap` directly
3. I/O uses Linux's native async I/O (`io_uring`)
4. SQL Server's cooperative scheduler maps well to `pthreads`

## Our PoC Approach

We implement a minimal version of this stack:

1. **PE Loader**: Parse PE/COFF, map sections, resolve imports
2. **PAL**: Implement ~20 essential operations on Linux
3. **LibOS**: Provide Win32 stubs for common APIs
4. **Runner**: Orchestrate loading and execution

This is sufficient to run a simple Windows console application that:
- Calls `GetStdHandle` + `WriteConsoleA` (or `WriteFile`)
- Calls `ExitProcess`
- Uses basic memory allocation (`VirtualAlloc` / `HeapAlloc`)

The goal is not a production runtime but a **demonstration of the architectural
principle** that makes SQL Server on Linux possible.
