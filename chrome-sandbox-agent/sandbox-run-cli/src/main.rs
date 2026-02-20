//! sandbox-run: Portable Rust CLI for Chrome's seccomp-BPF sandbox.
//!
//! Single static binary. Wraps Chrome's extracted sandbox C++ code via FFI.
//! All 8 security layers active: User NS, PID NS, IPC NS, Net NS,
//! Mount NS + chroot, cap drop, seccomp-BPF, ptrace filesystem broker.

mod ffi;

use clap::Parser;
use std::ffi::CString;
use std::os::raw::c_char;
use std::process::ExitCode;

use ffi::{SandboxExecPolicy, SandboxPolicyLevel};

/// Run any command inside Chrome's seccomp-BPF sandbox.
///
/// Your current directory is bind-mounted as the workspace. The command runs
/// with full namespace isolation, chroot, capability dropping, and seccomp-BPF.
/// stdin/stdout/stderr stay connected to the terminal for interactive use.
#[derive(Parser, Debug)]
#[command(name = "sandbox-run", version, about, long_about = None)]
#[command(after_help = "\
EXAMPLES:
    sandbox-run bash                                    # Shell in sandbox
    sandbox-run --network claude                        # Claude with network
    sandbox-run --workspace ./proj python3 app.py       # Custom workspace
    sandbox-run --no-workspace bash                     # Ephemeral /tmp only
    sandbox-run --readonly /opt/node22:/root/.cargo --network claude

SECURITY:
    8 isolation layers (user/PID/IPC/net NS, chroot, caps, seccomp-BPF,
    ptrace broker). Sandboxed process sees only workspace + system dirs.

ENVIRONMENT:
    SANDBOX_WORKSPACE         Workspace directory
    SANDBOX_NETWORK=1         Enable network
    SANDBOX_READONLY_PATHS    Colon-separated read-only paths
    SANDBOX_ALLOWED_PATHS     Colon-separated read-write paths
    SANDBOX_POLICY            Policy level (STRICT/PERMISSIVE/TRACE_ALL)")]
struct Cli {
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

    /// seccomp-BPF policy: STRICT (default), PERMISSIVE, TRACE_ALL
    #[arg(long, default_value = "STRICT")]
    policy: String,

    /// Print sandbox configuration before launching
    #[arg(short, long)]
    verbose: bool,

    /// Command to run inside the sandbox
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Strip leading "--" from command if present
    let command: Vec<&str> = if cli.command.first().map(|s| s.as_str()) == Some("--") {
        cli.command[1..].iter().map(|s| s.as_str()).collect()
    } else {
        cli.command.iter().map(|s| s.as_str()).collect()
    };

    if command.is_empty() {
        eprintln!("sandbox-run: no command specified");
        return ExitCode::from(1);
    }

    // Resolve workspace: CLI flag > env var > CWD
    let workspace = if cli.no_workspace {
        None
    } else if let Some(ref ws) = cli.workspace {
        Some(ws.clone())
    } else if let Ok(ws) = std::env::var("SANDBOX_WORKSPACE") {
        if ws.is_empty() { None } else { Some(ws) }
    } else {
        std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    };

    // Resolve network: CLI flag > env var
    let network = cli.network
        || std::env::var("SANDBOX_NETWORK")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

    // Resolve readonly paths: CLI flag > env var
    let readonly = cli.readonly.clone().or_else(|| std::env::var("SANDBOX_READONLY_PATHS").ok());

    // Resolve allowed paths: CLI flag > env var
    let extra_allowed = cli.allowed.clone().or_else(|| std::env::var("SANDBOX_ALLOWED_PATHS").ok());

    // Resolve policy: CLI flag > env var
    let policy_str = if cli.policy != "STRICT" {
        cli.policy.clone()
    } else {
        std::env::var("SANDBOX_POLICY").unwrap_or_else(|_| cli.policy.clone())
    };

    let policy = match policy_str.as_str() {
        "STRICT" => SandboxPolicyLevel::Strict,
        "PERMISSIVE" => SandboxPolicyLevel::Permissive,
        "TRACE_ALL" => SandboxPolicyLevel::TraceAll,
        other => {
            eprintln!(
                "sandbox-run: unknown policy: {} (use STRICT, PERMISSIVE, or TRACE_ALL)",
                other
            );
            return ExitCode::from(1);
        }
    };

    // Build combined allowed paths: workspace + extras
    let mut all_allowed_parts: Vec<String> = Vec::new();
    if let Some(ref ws) = workspace {
        all_allowed_parts.push(ws.clone());
    }
    if let Some(ref extra) = extra_allowed {
        for p in extra.split(':') {
            if !p.is_empty() {
                all_allowed_parts.push(p.to_string());
            }
        }
    }
    let all_allowed = all_allowed_parts.join(":");

    // Verbose output
    let verbose = cli.verbose || std::env::var("SANDBOX_VERBOSE").is_ok();
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
        eprintln!("  Policy:    {}", policy_str);
        if let Some(ref ro) = readonly {
            eprintln!("  Read-only: {}", ro);
        }
        if let Some(ref ea) = extra_allowed {
            eprintln!("  Allowed:   {}", ea);
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
    unsafe {
        ffi::sandbox_set_policy(policy);
        ffi::sandbox_set_exec_policy(SandboxExecPolicy::Brokered);
        ffi::sandbox_set_network_enabled(if network { 1 } else { 0 });

        if !all_allowed.is_empty() {
            let c_paths = CString::new(all_allowed).expect("invalid allowed paths");
            ffi::sandbox_set_allowed_paths(c_paths.as_ptr());
        }

        if let Some(ref ro) = readonly {
            if !ro.is_empty() {
                let c_paths = CString::new(ro.as_str()).expect("invalid readonly paths");
                ffi::sandbox_set_readonly_paths(c_paths.as_ptr());
            }
        }
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
