# Drawbridge Linux PoC - Real Component Extraction

Extracting and integrating **real components** from open-source projects to
replicate Microsoft's Drawbridge architecture for running Windows PE
executables on Linux.

**We don't rebuild Windows - we extract real pieces and wire them together.**

## The Drawbridge Principle

```
+---------------------------------------------+
|      Windows Application (.exe)             |
|      (unmodified PE binary)                 |
+---------------------------------------------+
|      Real Windows DLLs (ReactOS)            |
|      kernel32.dll, ntdll.dll, msvcrt.dll    |
+---------------------------------------------+
|      PE Loader (from Wine)                  |
|      Loads PE, resolves imports, relocates  |
+---------------------------------------------+
|      PAL - Platform Abstraction Layer       |
|      (from Gramine - ~50 operations)        |
+---------------------------------------------+
|      Linux Kernel                           |
+---------------------------------------------+
```

## Real Components We Extract

| Component | Source Project | What We Get | License |
|-----------|--------------|-------------|---------|
| **PAL** | [Gramine](https://github.com/gramineproject/gramine) | Real Linux PAL (~50 ops mapped to syscalls) | LGPL-3.0 |
| **PE Loader** | [Wine](https://gitlab.winehq.org/wine/wine) | Real PE/COFF loader, import resolver, relocator | LGPL-2.1 |
| **Windows DLLs** | [ReactOS](https://github.com/nicedreams/reactos) | Real kernel32.dll, ntdll.dll, msvcrt.dll | GPL-2.0 |
| **Reference** | SQL Server on Linux | SQLPAL analysis (proprietary, study only) | Proprietary |

## How SQL Server on Linux Does It (SQLPAL)

Microsoft's production implementation (`mssql-server` package):
- Ships real Windows DLLs bundled with the SQL Server engine
- SQLPAL implements the PAL on Linux (pthreads, mmap, epoll, io_uring)
- SQL Server runs as a normal Linux process, calling Win32 APIs internally
- The library OS layer translates Win32 -> PAL -> Linux syscalls

## Project Structure

```
drawbridge-linux-poc/
├── README.md                    # This file
├── docs/
│   └── architecture.md          # Deep architecture analysis
├── analysis/
│   ├── sqlpal_analysis.py       # Analyze SQLPAL from mssql-server packages
│   ├── gramine_pal_map.md       # Gramine PAL operation mapping
│   └── component_matrix.md      # Component compatibility matrix
├── extraction/
│   ├── extract_gramine_pal.sh   # Extract PAL from Gramine source
│   ├── extract_wine_loader.sh   # Extract PE loader from Wine
│   └── extract_reactos_dlls.sh  # Extract DLLs from ReactOS
├── integration/
│   ├── drawbridge_runner.c      # Orchestrator: load PE via Wine loader,
│   │                            # resolve imports via ReactOS DLLs,
│   │                            # execute via Gramine PAL
│   ├── pal_bridge.h             # Bridge between Wine PE loader and Gramine PAL
│   └── win32_to_pal.c           # Win32 API -> PAL call translation layer
├── scripts/
│   └── setup_environment.sh     # Download and build all dependencies
└── test/
    └── hello_win.c              # Simple Windows test program
```

## Quick Start

```bash
# 1. Set up the environment (downloads real components)
./scripts/setup_environment.sh

# 2. Build the integration layer
make

# 3. Run a Windows executable on Linux
./drawbridge-run test/hello_win.exe
```

## References

- [Drawbridge: Rethinking the Library OS (ASPLOS 2011)](https://www.microsoft.com/en-us/research/publication/rethinking-the-library-os-from-the-top-down/)
- [Gramine Library OS](https://github.com/gramineproject/gramine)
- [Wine PE Loader](https://gitlab.winehq.org/wine/wine)
- [ReactOS](https://reactos.org/)
- [SQL Server on Linux announcement](https://cloudblogs.microsoft.com/sqlserver/2016/03/07/sql-server-on-linux/)
