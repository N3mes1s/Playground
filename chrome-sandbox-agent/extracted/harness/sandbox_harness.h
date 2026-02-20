// sandbox_harness.h - C API for the Chrome sandbox harness.
// This is the interface used by Python ctypes to drive the sandbox.
//
// Architecture (mirrors Chrome's multi-layer sandbox model):
//
//   Python Agent (broker/tracer)             Sandboxed Worker (target)
//   ┌─────────────────────────┐            ┌─────────────────────────┐
//   │  LLM tool calls         │  fork+IPC  │  Layer 1: User NS       │
//   │  Policy decisions       │ ─────────> │  Layer 2: PID NS + init │
//   │  Syscall analysis       │ <───────── │  Layer 3: IPC NS        │
//   │                         │ results +  │  Layer 4: Net NS        │
//   │  ptrace-based broker:   │ syscall log│  Layer 5: Mount NS      │
//   │  ┌───────────────────┐  │            │  Layer 6: Chroot/pivot  │
//   │  │BrokerPermissionList│  │   ptrace   │  Layer 7: Drop caps     │
//   │  │ validates paths    │<─┼───────────┤  Layer 8: seccomp-BPF   │
//   │  │ against allowlist  │──┼───────────>│   TRACE_BROKER →        │
//   │  └───────────────────┘  │  allow/deny│   validates path →      │
//   │                         │            │   allow or -EACCES      │
//   └─────────────────────────┘            └─────────────────────────┘

#ifndef SANDBOX_HARNESS_H_
#define SANDBOX_HARNESS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Sandbox lifecycle ---

// Initialize the sandbox subsystem. Call once at startup.
// Returns 0 on success, -1 on failure.
int sandbox_init(void);

// Shutdown and clean up.
void sandbox_shutdown(void);

// --- Policy configuration ---

// Policy levels (maps to Chrome's baseline_policy.cc)
typedef enum {
  SANDBOX_POLICY_STRICT = 0,      // Block dangerous syscalls, broker FS access
  SANDBOX_POLICY_PERMISSIVE = 1,  // Allow most, log dangerous
  SANDBOX_POLICY_TRACE_ALL = 2,   // Allow all but trace every syscall
} SandboxPolicyLevel;

// Configure writable paths for the broker to open on behalf of sandboxed process.
// These paths get read-write-create access (bind-mounted read-write in the
// mount namespace, ReadWriteCreateRecursive in the broker permission list).
// paths: colon-separated list of allowed paths (e.g., "/tmp:/home/user/work")
// MUST be called before sandbox_init() — mount namespace is set up during init.
int sandbox_set_allowed_paths(const char* paths);

// Configure read-only paths for runtimes, tools, and libraries.
// These paths get read-only access (bind-mounted read-only in the mount
// namespace, ReadOnlyRecursive in the broker permission list).
// Use for: language runtimes (/opt/node22), extra tool dirs, SDK paths.
// paths: colon-separated list of read-only paths (e.g., "/opt/node22:/opt/python3")
// MUST be called before sandbox_init() — mount namespace is set up during init.
int sandbox_set_readonly_paths(const char* paths);

// Set the policy level for subsequent sandbox_exec calls.
void sandbox_set_policy(SandboxPolicyLevel level);

// Exec policy: controls how execve/execveat are handled in the sandbox.
//
// Chrome blocks execve entirely (zygote model: fork, never exec).
// Since we run commands via exec, we offer configurable exec policies:
typedef enum {
  // CHROME mode: block ALL exec after the initial command launch.
  // The first execve (launching the sandboxed command) is allowed;
  // all subsequent execs from within the sandbox are blocked with -EACCES.
  // This matches Chrome's renderer sandbox behavior.
  // Use for: single-binary sandboxing where the command shouldn't spawn others.
  SANDBOX_EXEC_CHROME = 0,

  // BROKERED mode (default): every execve is validated by the broker.
  // The ptrace tracer checks the executable path against BrokerPermissionList.
  // Only executables in allowed paths (/bin, /usr/bin, etc.) can run.
  // Use for: shell commands and pipelines that need to exec sub-processes.
  SANDBOX_EXEC_BROKERED = 1,

  // BLOCKED mode: block ALL execs including the initial one.
  // The command must already be running (e.g., via fork from zygote).
  // Use for: Chrome-identical behavior when exec is truly unnecessary.
  SANDBOX_EXEC_BLOCKED = 2,
} SandboxExecPolicy;

// Set the exec policy for subsequent sandbox_exec calls.
// Default: SANDBOX_EXEC_BROKERED
void sandbox_set_exec_policy(SandboxExecPolicy policy);

// --- Seccomp filter extensions ---
//
// The default seccomp-BPF filter is identical to Chrome's renderer sandbox.
// These functions allow extending the filter at runtime WITHOUT modifying the
// base policy. Extensions are additive — they can only allow operations that
// Chrome blocks, never restrict operations Chrome allows.
//
// MUST be called before sandbox_init() — seccomp filters are installed during init.

// Allow additional ioctl commands inside the sandbox.
// By default only TCGETS and FIONREAD are allowed (Chrome's RestrictIoctl).
// Use for runtimes that need: FIONBIO (non-blocking), TIOCGPGRP (TTY detect),
// TIOCGWINSZ (terminal size), TCSETS (terminal config), etc.
// cmds: array of ioctl request codes to allow.
// count: number of entries in the array.
int sandbox_allow_ioctls(const unsigned long* cmds, int count);

// Allow additional getsockopt/setsockopt options inside the sandbox.
// By default only SOL_SOCKET+SO_PEEK_OFF is allowed (Chrome's policy).
// Use for runtimes that need: SO_TYPE (socket detection), SO_ERROR,
// SO_RCVBUF/SO_SNDBUF, SO_KEEPALIVE, SO_REUSEADDR, etc.
// optnames: array of SOL_SOCKET option names to allow.
// count: number of entries in the array.
int sandbox_allow_sockopts(const int* optnames, int count);

// --- Execution ---

// Result of a sandboxed execution.
typedef struct {
  int exit_code;             // Process exit code
  char* stdout_buf;          // Captured stdout (caller must free)
  size_t stdout_len;
  char* stderr_buf;          // Captured stderr (caller must free)
  size_t stderr_len;
  char* syscall_log;         // JSON array of intercepted syscalls (caller must free)
  size_t syscall_log_len;
  int num_syscalls_total;    // Total syscalls made
  int num_syscalls_blocked;  // Syscalls that were blocked by policy
  double duration_seconds;   // Wall-clock execution time
} SandboxResult;

// Execute a command inside the Chrome sandbox.
// argv: null-terminated array of command arguments (argv[0] = program)
// Returns a SandboxResult. Caller must call sandbox_result_free().
SandboxResult sandbox_exec(const char* const* argv);

// Execute a shell command inside the sandbox.
// cmd: shell command string (run via /bin/sh -c)
SandboxResult sandbox_exec_shell(const char* cmd);

// Free a SandboxResult's allocated buffers.
void sandbox_result_free(SandboxResult* result);

// --- Syscall broker ---

// Start a broker process that can handle file operations on behalf
// of sandboxed processes. The broker runs in the parent (privileged)
// process and the sandboxed child sends requests via IPC.
// Returns broker PID, or -1 on failure.
int sandbox_start_broker(void);

// Stop the broker process.
void sandbox_stop_broker(void);

// --- Namespace isolation ---

// Enable or disable namespace isolation (user, PID, network, mount).
// When enabled (default), the sandbox applies Chrome's full defense-in-depth:
//   Layer 1: User namespace (isolate UIDs, drop privilege)
//   Layer 2: PID namespace (isolate process tree)
//   Layer 3: Network namespace (isolate network stack)
//   Layer 4: Mount namespace (isolate filesystem view)
//   Layer 5: Drop all capabilities
//   Layer 6: seccomp-BPF filter (syscall allowlist)
// When disabled, only seccomp-BPF is used.
// Must be called before sandbox_exec(). Default: enabled.
void sandbox_set_namespaces_enabled(int enabled);
int sandbox_get_namespaces_enabled(void);

// --- Query capabilities ---

// Check if seccomp-BPF is available on this kernel.
int sandbox_has_seccomp_bpf(void);

// Check if user namespaces are available.
int sandbox_has_user_namespaces(void);

// Get the kernel version string.
const char* sandbox_kernel_version(void);

#ifdef __cplusplus
}
#endif

#endif  // SANDBOX_HARNESS_H_
