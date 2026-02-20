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

    /// Load a built-in preset by name.
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "aider" => Some(Self::preset_aider()),
            "opencode" => Some(Self::preset_opencode()),
            "claude-code" | "claude" => Some(Self::preset_claude_code()),
            _ => None,
        }
    }

    fn preset_aider() -> Self {
        SandboxConfig {
            sandbox: SandboxSection {
                policy: Some("STRICT".into()),
                network: Some(true),
                ..Default::default()
            },
            paths: PathsSection {
                readonly: vec![
                    "/usr/local/lib/python3.11".into(),
                    "/usr/local/bin".into(),
                    "/usr/lib/python3.11".into(),
                    "/usr/lib/python3".into(),
                    "/usr/share/zoneinfo".into(),
                    "/etc/ssl".into(),
                    "/lib/x86_64-linux-gnu".into(),
                ],
                deny: vec![
                    "/etc/shadow".into(),
                    "/etc/gshadow".into(),
                ],
                ..Default::default()
            },
            filters: FiltersSection {
                ioctls: vec!["tty".into()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn preset_opencode() -> Self {
        SandboxConfig {
            sandbox: SandboxSection {
                policy: Some("STRICT".into()),
                network: Some(true),
                ..Default::default()
            },
            paths: PathsSection {
                readonly: vec![
                    "/opt/node22".into(),
                    "/usr/local/bin".into(),
                    "/etc/ssl".into(),
                    "/lib/x86_64-linux-gnu".into(),
                ],
                deny: vec![
                    "/etc/shadow".into(),
                    "/etc/gshadow".into(),
                ],
                ..Default::default()
            },
            filters: FiltersSection {
                ioctls: vec!["tty".into()],
                ..Default::default()
            },
            env: [
                // Redirect HOME so opencode writes data/log/config to workspace
                ("HOME".into(), "/tmp".into()),
                // Redirect TMPDIR so Bun's JIT .so extraction goes to writable dir
                ("TMPDIR".into(), "/tmp".into()),
            ]
            .into_iter()
            .collect(),
        }
    }

    fn preset_claude_code() -> Self {
        SandboxConfig {
            sandbox: SandboxSection {
                policy: Some("STRICT".into()),
                network: Some(true),
                ..Default::default()
            },
            paths: PathsSection {
                readonly: vec![
                    "/opt/node22".into(),
                    "/usr/local/bin".into(),
                    "/usr/share/zoneinfo".into(),
                    "/etc/ssl".into(),
                    "/lib/x86_64-linux-gnu".into(),
                ],
                deny: vec![
                    "/etc/shadow".into(),
                    "/etc/gshadow".into(),
                ],
                ..Default::default()
            },
            filters: FiltersSection {
                ioctls: vec!["tty".into()],
                ..Default::default()
            },
            ..Default::default()
        }
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
