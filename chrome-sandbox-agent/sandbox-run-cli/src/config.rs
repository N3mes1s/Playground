//! TOML config file support for sandbox-run.
//!
//! Config files let you define reusable sandbox profiles for different agents
//! and workloads. CLI flags override config file values.
//!
//! Example config (aider.toml):
//!
//! ```toml
//! [sandbox]
//! policy = "STRICT"
//! network = true
//!
//! [paths]
//! readonly = ["/usr/local/lib/python3.11", "/usr/local/bin", "/usr/lib/python3"]
//! deny = ["/etc/shadow", "/etc/passwd"]
//!
//! [filters]
//! ioctls = ["tty"]
//! sockopts = ["tcp_nodelay", "so_keepalive"]
//! ```

use serde::Deserialize;
use std::path::Path;

/// Top-level config file structure.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    pub sandbox: SandboxSection,
    pub paths: PathsSection,
    pub filters: FiltersSection,
    pub env: std::collections::HashMap<String, String>,
}

/// Core sandbox settings.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SandboxSection {
    /// Policy level: "STRICT", "PERMISSIVE", or "TRACE_ALL"
    pub policy: Option<String>,
    /// Enable network access
    pub network: Option<bool>,
    /// Workspace directory
    pub workspace: Option<String>,
    /// Enable audit mode
    pub audit: Option<bool>,
    /// Audit log file path
    pub audit_log: Option<String>,
    /// Verbose output
    pub verbose: Option<bool>,
}

/// Path filtering configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PathsSection {
    /// Read-only paths (runtimes, libraries)
    pub readonly: Vec<String>,
    /// Extra read-write paths
    pub allowed: Vec<String>,
    /// Denied paths (blocklist — always blocked even if inside allowed dirs)
    pub deny: Vec<String>,
}

/// Syscall/ioctl/sockopt filtering.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FiltersSection {
    /// Extra ioctl commands to allow. Supports "tty" shorthand and hex values.
    pub ioctls: Vec<String>,
    /// Extra socket options to allow. Supports named options.
    pub sockopts: Vec<String>,
    /// Extra syscalls to allow. Named syscalls like "flock", "getxattr", etc.
    pub syscalls: Vec<String>,
}

impl SandboxConfig {
    /// Load a config file from disk.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file {}: {}", path.display(), e))?;
        let config: SandboxConfig = toml::from_str(&content)
            .map_err(|e| format!("failed to parse config file {}: {}", path.display(), e))?;
        Ok(config)
    }

    /// Load a preset by name from the config directory.
    /// Looks for `<name>.toml` in: $SANDBOX_CONFIG_DIR, ./configs/, /etc/sandbox-run/
    pub fn preset(name: &str) -> Result<Self, String> {
        // Sanitize name: only alphanumeric, hyphens, underscores
        if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("invalid preset name: {}", name));
        }
        let filename = format!("{}.toml", name);

        // Search order: env var > local configs/ > system /etc/sandbox-run/
        let search_dirs: Vec<std::path::PathBuf> = vec![
            std::env::var("SANDBOX_CONFIG_DIR")
                .ok()
                .map(std::path::PathBuf::from)
                .unwrap_or_default(),
            std::path::PathBuf::from("configs"),
            std::path::PathBuf::from("/etc/sandbox-run"),
        ];

        for dir in &search_dirs {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let path = dir.join(&filename);
            if path.exists() {
                return Self::load(&path);
            }
        }

        Err(format!(
            "preset '{}' not found (searched for {} in: $SANDBOX_CONFIG_DIR, ./configs/, /etc/sandbox-run/)",
            name, filename
        ))
    }

    /// Merge CLI overrides into this config. CLI values take precedence.
    pub fn merge_cli(
        &mut self,
        cli_policy: Option<&str>,
        cli_network: bool,
        cli_workspace: Option<&str>,
        cli_no_workspace: bool,
        cli_readonly: Option<&str>,
        cli_allowed: Option<&str>,
        cli_deny: Option<&str>,
        cli_ioctls: Option<&str>,
        cli_sockopts: Option<&str>,
        cli_audit: Option<Option<&str>>,
        cli_verbose: bool,
    ) {
        // CLI policy overrides config (only if explicitly set, not default)
        if let Some(p) = cli_policy {
            self.sandbox.policy = Some(p.to_string());
        }

        // CLI --network flag overrides
        if cli_network {
            self.sandbox.network = Some(true);
        }

        // CLI workspace
        if cli_no_workspace {
            self.sandbox.workspace = None;
        } else if let Some(ws) = cli_workspace {
            self.sandbox.workspace = Some(ws.to_string());
        }

        // CLI paths extend config paths (not replace)
        if let Some(ro) = cli_readonly {
            for p in ro.split(':') {
                if !p.is_empty() && !self.paths.readonly.contains(&p.to_string()) {
                    self.paths.readonly.push(p.to_string());
                }
            }
        }
        if let Some(allowed) = cli_allowed {
            for p in allowed.split(':') {
                if !p.is_empty() && !self.paths.allowed.contains(&p.to_string()) {
                    self.paths.allowed.push(p.to_string());
                }
            }
        }
        if let Some(deny) = cli_deny {
            for p in deny.split(':') {
                if !p.is_empty() && !self.paths.deny.contains(&p.to_string()) {
                    self.paths.deny.push(p.to_string());
                }
            }
        }

        // CLI ioctls extend config
        if let Some(io) = cli_ioctls {
            for part in io.split(',') {
                let part = part.trim().to_string();
                if !part.is_empty() && !self.filters.ioctls.contains(&part) {
                    self.filters.ioctls.push(part);
                }
            }
        }

        // CLI sockopts extend config
        if let Some(so) = cli_sockopts {
            for part in so.split(',') {
                let part = part.trim().to_string();
                if !part.is_empty() && !self.filters.sockopts.contains(&part) {
                    self.filters.sockopts.push(part);
                }
            }
        }

        // CLI audit
        if let Some(audit_opt) = cli_audit {
            self.sandbox.audit = Some(true);
            if let Some(path) = audit_opt {
                self.sandbox.audit_log = Some(path.to_string());
            }
        }

        // CLI verbose
        if cli_verbose {
            self.sandbox.verbose = Some(true);
        }
    }
}

/// Parse ioctl strings into numeric values.
/// Supports: "tty" (shorthand), "0x5413" (hex), "21523" (decimal)
pub fn parse_ioctls(specs: &[String]) -> Vec<std::os::raw::c_ulong> {
    let mut result = Vec::new();
    for spec in specs {
        let s = spec.trim();
        if s.eq_ignore_ascii_case("tty") {
            result.push(0x5413); // TIOCGWINSZ
            result.push(0x5414); // TIOCSWINSZ
            result.push(0x540e); // TIOCSCTTY
        } else if let Some(hex) = s.strip_prefix("0x") {
            if let Ok(val) = u64::from_str_radix(hex, 16) {
                result.push(val as std::os::raw::c_ulong);
            }
        } else if let Ok(val) = s.parse::<u64>() {
            result.push(val as std::os::raw::c_ulong);
        }
    }
    result
}

/// Parse syscall extension strings into numeric syscall numbers.
///
/// All names map to real Linux x86_64 syscall numbers. The BPF policy
/// checks `extra_syscalls_.count(sysno)` at the very top of evaluation,
/// so ANY syscall listed here bypasses Chrome's default category handlers.
/// No sentinel values, no special-case handling — just real numbers.
pub fn parse_syscalls(specs: &[String]) -> Vec<std::os::raw::c_int> {
    let mut result = Vec::new();
    for spec in specs {
        let s = spec.trim();
        match s.to_ascii_lowercase().as_str() {
            // Sub-sandbox support (agents that create their own seccomp sandbox).
            // SECURITY: Even when allowed here, the C harness applies argument-
            // level filtering: prctl only permits PR_SET_NO_NEW_PRIVS,
            // PR_SET_NAME, PR_GET_NAME, PR_GET_DUMPABLE. seccomp only permits
            // SECCOMP_SET_MODE_FILTER (install additive filters).
            "prctl" | "prctl_no_new_privs" => result.push(157), // __NR_prctl
            "seccomp" => result.push(317),                       // __NR_seccomp
            // Process group/session management (needed by agents running commands)
            "setsid" => result.push(112),
            "setpgid" => result.push(109),
            "getpgid" => result.push(121),
            "getpgrp" => result.push(111),
            // File locking (advisory, FD-only)
            "flock" => result.push(73),
            // Extended attributes (metadata queries)
            "getxattr" => result.push(191),
            "lgetxattr" => result.push(192),
            "listxattr" => result.push(193),
            "llistxattr" => result.push(194),
            "xattr" => {
                result.push(191); // getxattr
                result.push(192); // lgetxattr
                result.push(193); // listxattr
                result.push(194); // llistxattr
            }
            // File advisory (posix_fadvise — performance hint only)
            "fadvise64" => result.push(221),
            // Process personality (ADDR_NO_RANDOMIZE etc.)
            "personality" => result.push(135),
            // Anything else: try numeric
            _ => {
                if let Some(hex) = s.strip_prefix("0x") {
                    if let Ok(val) = i32::from_str_radix(hex, 16) {
                        result.push(val);
                    }
                } else if let Ok(val) = s.parse::<i32>() {
                    result.push(val);
                }
            }
        }
    }
    result
}

/// Parse sockopt strings into numeric values.
/// Supports named options and numeric values.
pub fn parse_sockopts(specs: &[String]) -> Vec<std::os::raw::c_int> {
    let mut result = Vec::new();
    for spec in specs {
        let s = spec.trim();
        match s.to_ascii_lowercase().as_str() {
            "tcp_nodelay" => result.push(1),
            "tcp_keepidle" => result.push(4),
            "tcp_keepintvl" => result.push(5),
            "tcp_keepcnt" => result.push(6),
            "so_keepalive" => result.push(9),
            "so_sndbuf" => result.push(7),
            "so_rcvbuf" => result.push(8),
            "so_reuseaddr" => result.push(2),
            "so_reuseport" => result.push(15),
            "so_type" => result.push(3),
            "so_error" => result.push(4),
            _ => {
                // Try numeric
                if let Some(hex) = s.strip_prefix("0x") {
                    if let Ok(val) = i32::from_str_radix(hex, 16) {
                        result.push(val);
                    }
                } else if let Ok(val) = s.parse::<i32>() {
                    result.push(val);
                }
            }
        }
    }
    result
}
