# Chrome Sandbox Agent

Run any command inside Chrome's production seccomp-BPF sandbox. This project extracts Chromium's multi-layer Linux sandbox and exposes it as a standalone tool for sandboxing arbitrary processes — AI agents, shells, scripts, build tools, etc.

## Security Model

Eight defense-in-depth layers, identical to what Chrome uses for renderer processes:

| Layer | Mechanism | What it does |
|-------|-----------|--------------|
| 1 | User namespace | Maps root inside sandbox to unprivileged UID outside |
| 2 | PID namespace | Processes can only see each other, not the host |
| 3 | IPC namespace | Isolates System V IPC and POSIX message queues |
| 4 | Network namespace | No network access by default (opt-in with `--network`) |
| 5 | Mount namespace + chroot | Only workspace + system dirs visible; host filesystem hidden |
| 6 | Capability dropping | All Linux capabilities removed (no `CAP_SYS_ADMIN`, etc.) |
| 7 | seccomp-BPF | Syscall filter blocks dangerous calls (`kexec_load`, `mount`, `ptrace`, `bpf`, etc.) |
| 8 | Ptrace filesystem broker | Every `open`/`openat`/`access`/`stat` validated against path allowlist |

The sandboxed process **cannot**:
- Access files outside its workspace and system directories
- Create network connections (unless `--network` is enabled)
- Load kernel modules, mount filesystems, or escalate privileges
- Send signals to PID 1 (namespace init protection)
- Create raw sockets, BPF programs, or perf events
- Escape via TOCTOU races (chroot contains only broker-allowed paths)

## Quick Start

### Build

```bash
cd extracted/build
cmake ..
make chrome_sandbox_harness
```

This produces `libchrome_sandbox_harness.so`, the shared library used by both the CLI and Python API.

**Requirements**: CMake 3.10+, GCC/Clang with C++20, libcap-dev, Linux kernel 3.5+ with seccomp-BPF.

### Run a command

```bash
# Interactive shell in sandbox
./sandbox-run bash

# Run Claude Code sandboxed
./sandbox-run claude

# Python REPL
./sandbox-run python3

# With network access
./sandbox-run --network curl https://example.com

# Specific workspace directory
./sandbox-run --workspace ./my-project python3 app.py

# No workspace (ephemeral /tmp only)
./sandbox-run --no-workspace bash
```

### Install as a command

```bash
ln -s "$(pwd)/sandbox_claude.py" /usr/local/bin/sandbox-run
chmod +x sandbox_claude.py
```

## CLI Reference

```
sandbox-run [options] <command> [args...]
```

| Flag | Description |
|------|-------------|
| `--workspace DIR`, `-w DIR` | Host directory to mount as workspace (default: current directory) |
| `--no-workspace` | Don't mount any workspace; ephemeral /tmp only |
| `--network` | Enable network access inside the sandbox |
| `--policy {STRICT,PERMISSIVE,TRACE_ALL}` | seccomp-BPF policy level (default: STRICT) |
| `--config FILE` | Path to `sandbox.config.json` |
| `--verbose`, `-v` | Print sandbox configuration before launching |

### Policy Levels

- **STRICT** (default): Block dangerous syscalls, broker all filesystem access. Production use.
- **PERMISSIVE**: Allow most syscalls, block truly dangerous ones. Development/debugging.
- **TRACE_ALL**: Allow all syscalls but trace every one. Profiling and analysis.

## Configuration

Configuration is loaded from three sources (highest priority first):

1. **CLI flags** (`--workspace`, `--network`, `--policy`, etc.)
2. **Environment variables** (`SANDBOX_WORKSPACE`, `SANDBOX_NETWORK`, etc.)
3. **Config file** (`sandbox.config.json` in current directory, or `--config`)

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SANDBOX_WORKSPACE` | Host workspace directory | `/home/user/project` |
| `SANDBOX_WORKSPACE_PATH` | Path inside sandbox | `/workspace` |
| `SANDBOX_POLICY` | seccomp-BPF policy | `STRICT` |
| `SANDBOX_NETWORK` | Enable network | `true` / `false` |
| `SANDBOX_READONLY_PATHS` | Colon-separated read-only mounts | `/opt/node22:/opt/python3` |
| `SANDBOX_ALLOWED_PATHS` | Colon-separated read-write mounts | `/opt/tools` |
| `SANDBOX_EXEC_POLICY` | Exec policy | `BROKERED` |
| `SANDBOX_VERBOSE` | Print config on launch | `1` |

### Config File

```json
{
    "workspace": "./my-project",
    "policy": "STRICT",
    "network": false,
    "readonly_paths": ["/usr/local/lib", "/usr/local/bin"],
    "allowed_paths": ["/opt/tools"],
    "sandbox_workspace_path": "/workspace",
    "exec_policy": "BROKERED"
}
```

### Exec Policies

| Policy | Behavior |
|--------|----------|
| `CHROME` | Allow first exec only (Chrome's renderer behavior) |
| `BROKERED` (default) | Validate every exec path against broker allowlist |
| `BLOCKED` | Block all execs after initial setup |

## Python API

```python
from chrome_sandbox import ChromeSandbox, PolicyLevel, ExecPolicy

# Basic usage — capture output
with ChromeSandbox(policy=PolicyLevel.STRICT) as sb:
    result = sb.run("echo hello world")
    print(result.stdout)        # "hello world\n"
    print(result.exit_code)     # 0
    print(result.syscall_log)   # [{nr: 1, name: "write", ...}, ...]

# With workspace — files persist on host
sandbox = ChromeSandbox(
    workspace_dir="/home/user/my-project",
    workspace_symlink="/workspace",
    network_enabled=False,
)
result = sandbox.run("ls /workspace")
sandbox.close()

# Interactive mode — stdio passthrough, no capture
sandbox = ChromeSandbox(policy=PolicyLevel.STRICT)
exit_code = sandbox.run_interactive(["bash"])
sandbox.close()

# Explicit argv (no shell interpretation)
result = sandbox.run_argv(["python3", "-c", "print('hi')"])

# Query capabilities
print(ChromeSandbox.kernel_version())
print(ChromeSandbox.has_seccomp_bpf())
print(ChromeSandbox.has_user_namespaces())
```

### SandboxResult Fields

| Field | Type | Description |
|-------|------|-------------|
| `exit_code` | int | Process exit code |
| `stdout` | str | Captured stdout |
| `stderr` | str | Captured stderr |
| `syscall_log` | list[dict] | JSON array of traced syscalls |
| `num_syscalls_total` | int | Total syscalls made |
| `num_syscalls_blocked` | int | Syscalls blocked by policy |
| `duration_seconds` | float | Wall-clock execution time |

## C API

The sandbox is implemented as `libchrome_sandbox_harness.so` with a C API defined in `extracted/harness/sandbox_harness.h`:

```c
#include "sandbox_harness.h"

// Initialize (call once)
sandbox_set_policy(SANDBOX_POLICY_STRICT);
sandbox_set_allowed_paths("/home/user/work:/tmp");
sandbox_set_network_enabled(0);
sandbox_init();

// Execute commands
SandboxResult result = sandbox_exec_shell("whoami");
printf("stdout: %.*s\n", (int)result.stdout_len, result.stdout_buf);
sandbox_result_free(&result);

// Interactive mode
const char* argv[] = {"bash", NULL};
int exit_code = sandbox_exec_interactive(argv);

// Cleanup
sandbox_shutdown();
```

## What's Visible Inside the Sandbox

| Path | Access | Source |
|------|--------|--------|
| `/workspace` (or configured path) | read-write | Bind-mounted from host workspace |
| `/tmp` | read-write | Ephemeral tmpfs |
| `/bin`, `/usr/bin` | read-only | System binaries |
| `/lib`, `/usr/lib`, `/lib64` | read-only | System libraries |
| `/etc` (select files) | read-only | hostname, resolv.conf, passwd, etc. |
| `/dev/null`, `/dev/zero`, `/dev/urandom` | read-only | Standard devices |
| Everything else | **blocked** | Not present in chroot |

## Running the Security Tests

An 82-test breakout suite verifies all sandbox layers:

```bash
# Compile the test (static binary — no library deps inside sandbox)
gcc -O2 -static -o tests/test_sandbox_escape tests/test_sandbox_escape.c

# Run inside sandbox
./sandbox-run ./tests/test_sandbox_escape
```

Test categories:
- **Filesystem escape**: path traversal, symlink escape, hardlink, write to /bin, /etc, /usr
- **/proc attacks**: PID namespace isolation, /proc/1/mem, /proc/kcore, kallsyms
- **Privilege escalation**: mount, chroot, unshare, ptrace, mknod, SUID, capabilities
- **Network escape**: TCP/UDP/raw sockets, bind+listen, Unix socket to docker.sock, netlink
- **Dangerous syscalls**: kexec, kernel modules, BPF, io_uring, perf, keyctl, reboot
- **Process/signal attacks**: kill PID 1, fork bombs (RLIMIT_NPROC), TIOCSTI injection
- **Broker bypass**: direct SYS_open, O_PATH escape, memfd_create, TOCTOU race
- **Namespace escape**: unshare, setns, sysfs, cgroup, uid_map
- **Information disclosure**: /proc/cmdline, SSH keys, env vars, dmesg

## Project Structure

```
chrome-sandbox-agent/
  sandbox_claude.py          # CLI launcher (sandbox-run)
  sandbox_config.py          # Config system (file + env + args)
  chrome_sandbox.py          # Python ctypes bindings
  agent.py                   # Agent orchestration
  tests/
    test_sandbox_escape.c    # 82-test breakout suite
  extracted/
    CMakeLists.txt           # Build system
    harness/
      sandbox_harness.h      # C API header
      sandbox_harness.cc     # Core implementation (all 8 layers)
    sandbox/linux/            # Extracted Chromium sandbox source
      seccomp-bpf/           # SandboxBPF class, BPF compiler
      seccomp-bpf-helpers/   # Baseline policy, syscall sets
      syscall_broker/        # Broker process, permission list
      services/              # Credentials, namespaces, proc utils
      bpf_dsl/               # BPF domain-specific language
```

## Known Mitigations and Hardening

- **TOCTOU defense**: Ptrace broker rewrites validated paths back to child memory, and the chroot filesystem only contains broker-allowed paths (defense in depth neutralizes the race)
- **Kill broker**: kill/tgkill/tkill routed through ptrace broker to protect PID 1 from SIGKILL (fixes Chrome's RestrictKillTarget PID-hardcoding issue in PID namespaces)
- **Empty-path denial**: TRACE_BROKER syscalls with no extractable path are explicitly denied (prevents fchdir-style bypasses)
- **Core dumps disabled**: RLIMIT_CORE=0 prevents memory disclosure
- **Fork bomb defense**: RLIMIT_NPROC limits process creation
- **no_new_privs**: Prevents SUID escalation
- **TIOCSTI blocked**: Terminal injection via ioctl blocked by seccomp
