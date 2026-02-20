//! sandbox-run: Portable Rust CLI for Chrome's seccomp-BPF sandbox.
//!
//! Single static binary. Wraps Chrome's extracted sandbox C++ code via FFI.
//! All 8 security layers active: User NS, PID NS, IPC NS, Net NS,
//! Mount NS + chroot, cap drop, seccomp-BPF, ptrace filesystem broker.
//!
//! Security workflow:
//!   1. Audit:  sandbox-run --audit /tmp/audit.jsonl -- tool --version
//!   2. Config: sandbox-run --generate-config /tmp/audit.jsonl > tool.toml
//!   3. Run:    sandbox-run --config tool.toml -- tool args...

mod config;
mod ffi;

use clap::Parser;
use std::ffi::CString;
use std::os::raw::c_char;
use std::process::ExitCode;

use config::SandboxConfig;
use ffi::{SandboxExecPolicy, SandboxPolicyLevel};

/// Run any command inside Chrome's seccomp-BPF sandbox.
///
/// Always runs with STRICT seccomp-BPF policy. Use --config or --preset
/// to provide tool-specific filtering rules. Use --audit + --generate-config
/// for the security-first workflow: audit first, then generate minimal config.
#[derive(Parser, Debug)]
#[command(name = "sandbox-run", version, about, long_about = None)]
#[command(after_help = "\
WORKFLOW (security-first):
    1. Audit:  sandbox-run --audit /tmp/audit.jsonl -- tool --version
    2. Config: sandbox-run --generate-config /tmp/audit.jsonl > tool.toml
    3. Run:    sandbox-run --config tool.toml -- tool args...

EXAMPLES:
    sandbox-run bash                                    # Shell in sandbox
    sandbox-run --network -- claude                     # Claude with network
    sandbox-run --config aider.toml -- aider --message 'fix it'
    sandbox-run --preset aider -- python3 -m aider --version
    sandbox-run --audit /tmp/audit.jsonl --network -- python3 -m aider --version

PRESETS:
    aider        Python-based AI coding agent
    opencode     Node.js-based AI coding agent
    claude-code  Claude Code (Node.js)

SECURITY:
    8 isolation layers (user/PID/IPC/net NS, chroot, caps, seccomp-BPF,
    ptrace broker). Policy is always STRICT. Config only relaxes specific
    filters (paths, ioctls, sockopts) — never weakens structural isolation.")]
struct Cli {
    /// Load tool config from TOML file (see --generate-config)
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Use a built-in preset: aider, opencode, claude-code
    #[arg(long)]
    preset: Option<String>,

    /// Generate a minimal TOML config from an audit log file, then exit.
    /// Pipe output to a .toml file: --generate-config audit.jsonl > tool.toml
    #[arg(long, value_name = "AUDIT_LOG")]
    generate_config: Option<String>,

    /// Host directory to mount as workspace (default: current directory)
    #[arg(short, long)]
    workspace: Option<String>,

    /// Don't mount any workspace (ephemeral /tmp only)
    #[arg(long)]
    no_workspace: bool,

    /// Enable network access inside the sandbox (default: blocked)
    #[arg(long)]
    network: bool,

    /// Additional colon-separated read-only mount paths (runtimes, tools)
    #[arg(long)]
    readonly: Option<String>,

    /// Additional colon-separated read-write mount paths
    #[arg(long)]
    allowed: Option<String>,

    /// Colon-separated paths to always deny (blocklist, overrides allow)
    #[arg(long)]
    deny: Option<String>,

    /// Print sandbox configuration before launching
    #[arg(short, long)]
    verbose: bool,

    /// Enable audit mode: log every broker decision to file (or stderr if no path)
    #[arg(long, value_name = "LOG_PATH")]
    audit: Option<Option<String>>,

    /// Allow extra ioctl commands (comma-separated hex values, or "tty" shorthand)
    #[arg(long)]
    ioctls: Option<String>,

    /// Allow extra socket options (comma-separated: tcp_nodelay, so_keepalive, etc.)
    #[arg(long)]
    sockopts: Option<String>,

    /// Command to run inside the sandbox
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // --generate-config: parse audit log and emit minimal TOML config
    if let Some(ref audit_log_path) = cli.generate_config {
        return generate_config_from_audit(audit_log_path);
    }

    // Strip leading "--" from command if present
    let command: Vec<&str> = if cli.command.first().map(|s| s.as_str()) == Some("--") {
        cli.command[1..].iter().map(|s| s.as_str()).collect()
    } else {
        cli.command.iter().map(|s| s.as_str()).collect()
    };

    if command.is_empty() {
        eprintln!("sandbox-run: no command specified");
        eprintln!("Usage: sandbox-run [OPTIONS] -- COMMAND [ARGS...]");
        return ExitCode::from(1);
    }

    // Load config: --config file > --preset > defaults
    let mut cfg = if let Some(ref path) = cli.config {
        match SandboxConfig::load(std::path::Path::new(path)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sandbox-run: {}", e);
                return ExitCode::from(1);
            }
        }
    } else if let Some(ref preset_name) = cli.preset {
        match SandboxConfig::preset(preset_name) {
            Some(c) => c,
            None => {
                eprintln!(
                    "sandbox-run: unknown preset '{}' (available: aider, opencode, claude-code)",
                    preset_name
                );
                return ExitCode::from(1);
            }
        }
    } else {
        SandboxConfig::default()
    };

    // Merge CLI flags into config (CLI takes precedence)
    cfg.merge_cli(
        None, // policy is always STRICT
        cli.network,
        cli.workspace.as_deref(),
        cli.no_workspace,
        cli.readonly.as_deref(),
        cli.allowed.as_deref(),
        cli.deny.as_deref(),
        cli.ioctls.as_deref(),
        cli.sockopts.as_deref(),
        cli.audit
            .as_ref()
            .map(|opt| opt.as_deref()),
        cli.verbose,
    );

    // Resolve workspace: config > env var > CWD
    let workspace = if cli.no_workspace {
        None
    } else if let Some(ref ws) = cfg.sandbox.workspace {
        Some(ws.clone())
    } else if let Ok(ws) = std::env::var("SANDBOX_WORKSPACE") {
        if ws.is_empty() {
            None
        } else {
            Some(ws)
        }
    } else {
        std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    };

    // Network: config > env var
    let network = cfg.sandbox.network.unwrap_or(false)
        || std::env::var("SANDBOX_NETWORK")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

    // Build combined path lists
    let mut all_allowed_parts: Vec<String> = Vec::new();
    if let Some(ref ws) = workspace {
        all_allowed_parts.push(ws.clone());
    }
    for p in &cfg.paths.allowed {
        if !p.is_empty() {
            all_allowed_parts.push(p.clone());
        }
    }
    let all_allowed = all_allowed_parts.join(":");
    let all_readonly = cfg.paths.readonly.join(":");
    let all_denied = cfg.paths.deny.join(":");

    // Parse filter lists
    let ioctl_cmds = config::parse_ioctls(&cfg.filters.ioctls);
    let sockopt_vals = config::parse_sockopts(&cfg.filters.sockopts);

    // Verbose output
    let verbose = cfg.sandbox.verbose.unwrap_or(false) || std::env::var("SANDBOX_VERBOSE").is_ok();
    if verbose {
        eprint!("\x1b[2m");
        eprintln!("sandbox-run: Chrome seccomp-BPF sandbox");
        eprintln!("  Command:   {}", command.join(" "));
        eprintln!(
            "  Workspace: {}",
            workspace
                .as_deref()
                .unwrap_or("(none - ephemeral /tmp only)")
        );
        eprintln!(
            "  Network:   {}",
            if network { "enabled" } else { "disabled" }
        );
        eprintln!("  Policy:    STRICT (always)");
        if !all_readonly.is_empty() {
            eprintln!("  Read-only: {}", all_readonly);
        }
        if !cfg.paths.allowed.is_empty() {
            eprintln!("  Allowed:   {}", cfg.paths.allowed.join(":"));
        }
        if !all_denied.is_empty() {
            eprintln!("  Denied:    {}", all_denied);
        }
        if !ioctl_cmds.is_empty() {
            eprintln!("  Ioctls:    {} extra", ioctl_cmds.len());
        }
        if !sockopt_vals.is_empty() {
            eprintln!("  Sockopts:  {} extra", sockopt_vals.len());
        }
        if let Some(ref config_path) = cli.config {
            eprintln!("  Config:    {}", config_path);
        }
        if let Some(ref preset_name) = cli.preset {
            eprintln!("  Preset:    {}", preset_name);
        }

        unsafe {
            let has_seccomp = ffi::sandbox_has_seccomp_bpf();
            let kernel = ffi::sandbox_kernel_version();
            let kernel_str = if kernel.is_null() {
                "unknown".to_string()
            } else {
                std::ffi::CStr::from_ptr(kernel)
                    .to_string_lossy()
                    .into_owned()
            };
            eprintln!(
                "  seccomp:   {}",
                if has_seccomp == 1 {
                    "active"
                } else {
                    "NOT available"
                }
            );
            eprintln!("  Kernel:    {}", kernel_str);
        }
        eprint!("\x1b[0m");
    }

    // Configure sandbox (MUST be before sandbox_init)
    // Policy is ALWAYS STRICT — config only relaxes specific filters.
    unsafe {
        ffi::sandbox_set_policy(SandboxPolicyLevel::Strict);
        ffi::sandbox_set_exec_policy(SandboxExecPolicy::Brokered);
        ffi::sandbox_set_network_enabled(if network { 1 } else { 0 });

        if !all_allowed.is_empty() {
            let c_paths = CString::new(all_allowed).expect("invalid allowed paths");
            ffi::sandbox_set_allowed_paths(c_paths.as_ptr());
        }

        if !all_readonly.is_empty() {
            let c_paths = CString::new(all_readonly).expect("invalid readonly paths");
            ffi::sandbox_set_readonly_paths(c_paths.as_ptr());
        }

        if !all_denied.is_empty() {
            let c_paths = CString::new(all_denied).expect("invalid denied paths");
            ffi::sandbox_set_denied_paths(c_paths.as_ptr());
        }
    }

    // Configure audit mode (CLI flag > config > env var)
    let audit_enabled = cfg.sandbox.audit.unwrap_or(false)
        || std::env::var("SANDBOX_AUDIT")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
    let audit_path = cfg
        .sandbox
        .audit_log
        .clone()
        .unwrap_or_default();
    let audit_path = if audit_path.is_empty() {
        std::env::var("SANDBOX_AUDIT_LOG").unwrap_or_default()
    } else {
        audit_path
    };

    if audit_enabled {
        let c_path = CString::new(audit_path.as_str()).expect("invalid audit log path");
        unsafe {
            let rc = ffi::sandbox_set_audit_mode(1, c_path.as_ptr());
            if rc != 0 {
                eprintln!("sandbox-run: failed to open audit log: {}", audit_path);
                return ExitCode::from(1);
            }
        }
        if verbose {
            eprint!("\x1b[2m");
            eprintln!(
                "  Audit:     enabled ({})",
                if audit_path.is_empty() {
                    "stderr"
                } else {
                    audit_path.as_str()
                }
            );
            eprint!("\x1b[0m");
        }
    }

    // Configure extra ioctls
    if !ioctl_cmds.is_empty() {
        unsafe {
            ffi::sandbox_allow_ioctls(
                ioctl_cmds.as_ptr(),
                ioctl_cmds.len() as std::os::raw::c_int,
            );
        }
    }

    // Configure extra socket options
    if !sockopt_vals.is_empty() {
        unsafe {
            ffi::sandbox_allow_sockopts(
                sockopt_vals.as_ptr(),
                sockopt_vals.len() as std::os::raw::c_int,
            );
        }
    }

    // Apply environment variables from config/preset.
    // Must be set before sandbox_init() so the zygote inherits them.
    for (key, value) in &cfg.env {
        std::env::set_var(key, value);
    }

    // Initialize sandbox (creates zygote with full namespace isolation)
    let rc = unsafe { ffi::sandbox_init() };
    if rc != 0 {
        eprintln!("sandbox-run: failed to initialize sandbox (rc={})", rc);
        eprintln!("Ensure you have: unprivileged user namespaces, seccomp-BPF");
        return ExitCode::from(1);
    }

    // Build null-terminated argv for the sandboxed command
    let c_args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(*s).expect("command arg contains null byte"))
        .collect();
    let mut c_argv: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    c_argv.push(std::ptr::null());

    // Run interactively inside the sandbox (all 8 layers active)
    let exit_code = unsafe { ffi::sandbox_exec_interactive(c_argv.as_ptr()) };

    unsafe {
        ffi::sandbox_shutdown();
    }

    ExitCode::from(exit_code as u8)
}

/// Parse an audit log (JSONL) and generate a minimal TOML config.
///
/// The audit log contains one JSON line per broker event. We extract:
/// - Paths that were denied (to build readonly/allowed lists)
/// - Syscall categories that were blocked
/// - Socket options and ioctls that were denied
///
/// The output is a minimal TOML config that allows exactly what the tool needs.
fn generate_config_from_audit(audit_log_path: &str) -> ExitCode {
    let content = match std::fs::read_to_string(audit_log_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sandbox-run: failed to read audit log: {}", e);
            return ExitCode::from(1);
        }
    };

    // Track unique denied paths and their parent directories
    let mut denied_read_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut denied_write_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut needs_network = false;
    let mut _blocked_syscalls: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Minimal JSON parsing (no serde_json dependency — parse key fields manually)
        let decision = extract_json_string(line, "decision");
        let event = extract_json_string(line, "event");
        let path = extract_json_string(line, "path");
        let syscall = extract_json_string(line, "syscall");

        if decision == "deny" || event == "block" {
            if !path.is_empty() {
                // Categorize by syscall type
                let is_write = matches!(
                    syscall.as_str(),
                    "open" | "openat" | "creat" | "mkdir" | "mkdirat" | "unlink"
                        | "unlinkat" | "rename" | "renameat" | "renameat2"
                        | "chmod" | "fchmodat" | "chown" | "fchownat"
                        | "truncate" | "link" | "linkat" | "symlink" | "symlinkat"
                );

                if is_write {
                    denied_write_paths.insert(path.clone());
                }
                // All denied paths need at least read access
                denied_read_paths.insert(path);
            }

            // Track blocked syscall names for comments
            if !syscall.is_empty() {
                _blocked_syscalls.insert(syscall.clone());
            }

            // Detect network-related blocks
            if matches!(
                syscall.as_str(),
                "connect" | "sendto" | "recvfrom" | "socket" | "bind"
            ) {
                needs_network = true;
            }
        }
    }

    // Collapse paths into parent directories (principle of least privilege)
    let readonly_dirs = collapse_to_dirs(&denied_read_paths, &denied_write_paths);
    let allowed_dirs = collapse_to_dirs(&denied_write_paths, &std::collections::BTreeSet::new());

    // Generate TOML
    println!("# Auto-generated sandbox config from audit log: {}", audit_log_path);
    println!("# Review carefully before use — only allow what's truly needed.");
    println!("# Security: policy is always STRICT. Config only relaxes path filters.");
    println!();
    println!("[sandbox]");
    println!("# Policy is always STRICT (cannot be changed).");
    println!("network = {}", needs_network);
    println!();
    println!("[paths]");
    println!("# Read-only paths (runtimes, libraries — cannot write to these)");
    print!("readonly = [");
    for (i, p) in readonly_dirs.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("\"{}\"", p);
    }
    println!("]");
    println!();
    println!("# Read-write paths (workspace gets this automatically)");
    print!("allowed = [");
    for (i, p) in allowed_dirs.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("\"{}\"", p);
    }
    println!("]");
    println!();
    println!("# Denied paths — always blocked even if inside allowed dirs");
    println!("# Add sensitive files here: credentials, keys, shadow, etc.");
    println!("deny = [\"/etc/shadow\", \"/etc/gshadow\"]");
    println!();
    println!("[filters]");
    println!("# Extra ioctl commands (\"tty\" = TIOCGWINSZ/TIOCSWINSZ/TIOCSCTTY)");
    println!("ioctls = [\"tty\"]");
    println!();
    println!("# Extra socket options (for HTTPS/API calls)");
    println!("sockopts = [\"tcp_nodelay\", \"so_keepalive\"]");
    println!();
    println!("# Environment variables to document (not applied automatically)");
    println!("# [env]");
    println!("# ANTHROPIC_API_KEY = \"$ANTHROPIC_API_KEY\"");

    ExitCode::SUCCESS
}

/// Extract a string value for a given key from a JSON line.
/// Minimal parser — no serde_json dependency.
fn extract_json_string(json: &str, key: &str) -> String {
    let pattern = format!("\"{}\":\"", key);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = json[value_start..].find('"') {
            return json[value_start..value_start + end].to_string();
        }
    }
    // Also try with space after colon
    let pattern2 = format!("\"{}\": \"", key);
    if let Some(start) = json.find(&pattern2) {
        let value_start = start + pattern2.len();
        if let Some(end) = json[value_start..].find('"') {
            return json[value_start..value_start + end].to_string();
        }
    }
    String::new()
}

/// Collapse a set of paths into parent directories.
/// If multiple paths share a common parent, use the parent instead.
fn collapse_to_dirs(
    paths: &std::collections::BTreeSet<String>,
    exclude: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let mut dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for path in paths {
        if exclude.contains(path) {
            continue;
        }
        // Get the parent directory
        let parent = if let Some(pos) = path.rfind('/') {
            if pos == 0 {
                "/".to_string()
            } else {
                path[..pos].to_string()
            }
        } else {
            continue;
        };

        // Don't add root
        if parent == "/" {
            dirs.insert(path.clone());
        } else {
            dirs.insert(parent);
        }
    }

    // Remove dirs that are subsets of other dirs
    let dirs_vec: Vec<String> = dirs.into_iter().collect();
    let mut result: Vec<String> = Vec::new();
    for dir in &dirs_vec {
        let is_subset = dirs_vec
            .iter()
            .any(|other| other != dir && dir.starts_with(other) && dir[other.len()..].starts_with('/'));
        if !is_subset {
            result.push(dir.clone());
        }
    }

    result
}
