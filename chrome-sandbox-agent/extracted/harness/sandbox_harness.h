// sandbox_harness.h - C API for the Chrome sandbox harness.
// This is the interface used by Python ctypes to drive the sandbox.
//
// Architecture (mirrors Chrome's multi-layer sandbox model):
//
//   Python Agent (broker)                   Sandboxed Worker (target)
//   ┌─────────────────────┐                ┌─────────────────────────┐
//   │  LLM tool calls     │   fork + IPC   │  Layer 1: User NS       │
//   │  Policy decisions   │ ──────────────> │  Layer 2: PID NS        │
//   │  Syscall analysis   │ <────────────── │  Layer 3: Net NS        │
//   │                     │   results +     │  Layer 4: Mount NS      │
//   │                     │   syscall log   │  Layer 5: Drop caps     │
//   │                     │                 │  Layer 6: seccomp-BPF   │
//   └─────────────────────┘                └─────────────────────────┘

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

// Configure allowed paths for the broker to open on behalf of sandboxed process.
// paths: colon-separated list of allowed paths (e.g., "/tmp:/home/user/work")
int sandbox_set_allowed_paths(const char* paths);

// Set the policy level for subsequent sandbox_exec calls.
void sandbox_set_policy(SandboxPolicyLevel level);

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
