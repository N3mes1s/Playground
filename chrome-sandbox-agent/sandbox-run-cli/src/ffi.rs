//! FFI bindings to libchrome_sandbox_harness.so
//!
//! These map directly to the C API in sandbox_harness.h.
//! All 8 Chrome security layers are activated through these functions.

use std::os::raw::{c_char, c_int};

/// seccomp-BPF policy levels
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum SandboxPolicyLevel {
    Strict = 0,
    Permissive = 1,
    TraceAll = 2,
}

/// Exec policy: controls how execve is handled inside the sandbox
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum SandboxExecPolicy {
    Chrome = 0,
    Brokered = 1,
    Blocked = 2,
}

extern "C" {
    // Lifecycle
    pub fn sandbox_init() -> c_int;
    pub fn sandbox_shutdown();

    // Init-time configuration (must be called BEFORE sandbox_init)
    pub fn sandbox_set_policy(level: SandboxPolicyLevel);
    pub fn sandbox_set_exec_policy(policy: SandboxExecPolicy);
    pub fn sandbox_set_allowed_paths(paths: *const c_char) -> c_int;
    pub fn sandbox_set_readonly_paths(paths: *const c_char) -> c_int;
    pub fn sandbox_set_network_enabled(enabled: c_int);
    pub fn sandbox_set_namespaces_enabled(enabled: c_int);

    // Per-execution extensions (called BEFORE sandbox_exec/sandbox_exec_interactive)
    pub fn sandbox_allow_ioctls(cmds: *const std::os::raw::c_ulong, count: c_int) -> c_int;
    pub fn sandbox_allow_sockopts(optnames: *const c_int, count: c_int) -> c_int;

    // Execution
    pub fn sandbox_exec_interactive(argv: *const *const c_char) -> c_int;

    // Audit mode
    pub fn sandbox_set_audit_mode(enabled: c_int, log_path: *const c_char) -> c_int;

    // Query
    pub fn sandbox_has_seccomp_bpf() -> c_int;
    pub fn sandbox_has_user_namespaces() -> c_int;
    pub fn sandbox_kernel_version() -> *const c_char;
}
