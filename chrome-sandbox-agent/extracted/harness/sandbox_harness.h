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
//
// Security model:
//   The BASE sandbox is identical to Chrome's renderer sandbox.
//   All extensions are ADDITIVE and RUNTIME-CONFIGURED — they can only
//   relax specific restrictions, never weaken the structural isolation.
//   Seccomp extensions are PER-EXECUTION — they apply only to the
//   single command they're configured for, then auto-reset.

#ifndef SANDBOX_HARNESS_H_
#define SANDBOX_HARNESS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Sandbox lifecycle ---

// Initialize the sandbox subsystem. Call once at startup.
// All init-time configuration (paths, network) must be set BEFORE this call.
// Returns 0 on success, -1 on failure.
int sandbox_init(void);

// Shutdown and clean up.
void sandbox_shutdown(void);

// ==========================================================================
// Init-time configuration (MUST be called before sandbox_init)
// ==========================================================================
// These settings affect the sandbox infrastructure and cannot be changed
// after initialization because they're baked into the zygote's namespaces.

// Configure writable paths for the broker to open on behalf of sandboxed process.
// These paths get read-write-create access (bind-mounted read-write in the
// mount namespace, ReadWriteCreateRecursive in the broker permission list).
// paths: colon-separated list of allowed paths (e.g., "/tmp:/home/user/work")
int sandbox_set_allowed_paths(const char* paths);

// Configure read-only paths for runtimes, tools, and libraries.
// These paths get read-only access (bind-mounted read-only in the mount
// namespace, ReadOnlyRecursive in the broker permission list).
// Use for: language runtimes (/opt/node22), extra tool dirs, SDK paths.
// paths: colon-separated list of read-only paths (e.g., "/opt/node22:/opt/python3")
int sandbox_set_readonly_paths(const char* paths);

// Enable or disable network namespace isolation.
// When enabled (default), sandboxed processes have no network access.
// When disabled, sandboxed processes inherit the host network stack.
// Use disabled for: API calls (Claude Code), package managers, curl, etc.
// Default: enabled (Chrome's behavior).
void sandbox_set_network_enabled(int enabled);

// Enable or disable ALL namespace isolation (user, PID, network, mount).
// When disabled, only seccomp-BPF is used.
// Default: enabled.
void sandbox_set_namespaces_enabled(int enabled);
int sandbox_get_namespaces_enabled(void);

// ==========================================================================
// Per-execution runtime policy (can be changed between sandbox_exec calls)
// ==========================================================================
// These settings are sent to the zygote with EACH command via IPC.
// Seccomp extensions are PER-EXECUTION: they apply only to the next
// sandbox_exec() call, then auto-reset to Chrome's defaults.
// This ensures each command gets the minimum privileges it needs.

// Policy levels (maps to Chrome's baseline_policy.cc)
typedef enum {
  SANDBOX_POLICY_STRICT = 0,      // Block dangerous syscalls, broker FS access
  SANDBOX_POLICY_PERMISSIVE = 1,  // Allow most, log dangerous
  SANDBOX_POLICY_TRACE_ALL = 2,   // Allow all but trace every syscall
} SandboxPolicyLevel;

// Set the policy level for subsequent sandbox_exec calls.
void sandbox_set_policy(SandboxPolicyLevel level);

// Exec policy: controls how execve/execveat are handled in the sandbox.
typedef enum {
  SANDBOX_EXEC_CHROME = 0,    // Allow first exec only (Chrome's behavior)
  SANDBOX_EXEC_BROKERED = 1,  // Validate every exec path against broker
  SANDBOX_EXEC_BLOCKED = 2,   // Block ALL execs
} SandboxExecPolicy;

// Set the exec policy for subsequent sandbox_exec calls.
// Default: SANDBOX_EXEC_BROKERED
void sandbox_set_exec_policy(SandboxExecPolicy policy);

// --- Seccomp filter extensions (per-execution, auto-reset) ---
//
// The default seccomp-BPF filter is identical to Chrome's renderer sandbox.
// These functions EXTEND the filter for the NEXT sandbox_exec() call ONLY.
// After each execution, extensions auto-reset to Chrome's defaults.
//
// Security properties:
//   - Extensions are PER-EXECUTION (scoped to one command, then cleared)
//   - Extensions are ADDITIVE (can only allow, never restrict beyond Chrome)
//   - Extensions are AUDITED (logged to stderr when active)
//   - The base Chrome policy is ALWAYS enforced as the minimum
//
// Example usage:
//   sandbox_allow_ioctls(node_ioctls, 7);  // extend for next exec
//   sandbox_exec_shell("node -e 'console.log(1)'");  // uses extensions
//   sandbox_exec_shell("echo safe");  // back to Chrome defaults

// Allow additional ioctl commands for the NEXT sandbox_exec() call.
// By default only TCGETS and FIONREAD are allowed (Chrome's RestrictIoctl).
// Auto-resets after each sandbox_exec().
int sandbox_allow_ioctls(const unsigned long* cmds, int count);

// Allow additional getsockopt/setsockopt options for the NEXT sandbox_exec() call.
// By default only SOL_SOCKET+SO_PEEK_OFF is allowed (Chrome's policy).
// Auto-resets after each sandbox_exec().
int sandbox_allow_sockopts(const int* optnames, int count);

// Clear all seccomp extensions (return to Chrome defaults).
// This is called automatically after each sandbox_exec().
void sandbox_clear_extensions(void);

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
// Seccomp extensions are applied to this execution only, then auto-reset.
SandboxResult sandbox_exec(const char* const* argv);

// Execute a shell command inside the sandbox.
// cmd: shell command string (run via /bin/sh -c)
// Seccomp extensions are applied to this execution only, then auto-reset.
SandboxResult sandbox_exec_shell(const char* cmd);

// Execute a command interactively inside the sandbox (passthrough mode).
// stdin/stdout/stderr stay connected to the terminal (not captured).
// Returns the process exit code directly.
//
// Security: IDENTICAL to sandbox_exec() — all 8 Chrome sandbox layers active:
//   1. User NS  2. PID NS  3. IPC NS  4. Network NS  5. Mount NS + chroot
//   6. Capability drop  7. seccomp-BPF  8. ptrace filesystem broker
//
// Only difference from sandbox_exec(): stdio is not redirected (stays on
// terminal for interactive use) and syscall logs are not collected.
//
// Use for: running interactive commands like `claude`, `python3`, `bash`, etc.
int sandbox_exec_interactive(const char* const* argv);

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
