//! Tiny subprocess primitive used by every adapter and the profiler.
//!
//! All external tooling (`cargo`, `go`, `perf`, `strace`, `git`, language
//! runtimes...) goes through [`run`] so that timeouts, working directories,
//! environment, and captured output are handled uniformly - and so that tests
//! can stub a single surface.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invocation {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub timeout: Option<Duration>,
    /// If true, a non-zero exit is NOT treated as an error. Used when we want
    /// to capture the exit code (e.g. `cargo test` returning 101 on failure).
    pub allow_nonzero: bool,
}

impl Invocation {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: vec![],
            cwd: None,
            env: HashMap::new(),
            timeout: Some(Duration::from_secs(600)),
            allow_nonzero: false,
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(items.into_iter().map(Into::into));
        self
    }

    pub fn cwd(mut self, p: impl Into<PathBuf>) -> Self {
        self.cwd = Some(p.into());
        self
    }

    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    pub fn allow_nonzero(mut self) -> Self {
        self.allow_nonzero = true;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == 0 && !self.timed_out
    }
}

/// Run an invocation to completion. Captures stdout/stderr into memory
/// (adapter outputs are bounded; streaming is unnecessary here).
pub async fn run(inv: &Invocation) -> Result<CommandOutput> {
    tracing::debug!(program = %inv.program, args = ?inv.args, "exec");
    let mut cmd = Command::new(&inv.program);
    cmd.args(&inv.args);
    if let Some(d) = &inv.cwd {
        cmd.current_dir(d);
    }
    for (k, v) in &inv.env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn `{}`", inv.program))?;

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    let mut so = child.stdout.take();
    let mut se = child.stderr.take();

    let capture = async {
        let so_task = async {
            if let Some(pipe) = so.as_mut() {
                pipe.read_to_end(&mut stdout_buf).await.ok();
            }
        };
        let se_task = async {
            if let Some(pipe) = se.as_mut() {
                pipe.read_to_end(&mut stderr_buf).await.ok();
            }
        };
        tokio::join!(so_task, se_task);
        child.wait().await
    };

    let (status, timed_out) = match inv.timeout {
        Some(t) => match tokio::time::timeout(t, capture).await {
            Ok(r) => (r.ok().and_then(|s| s.code()).unwrap_or(-1), false),
            Err(_) => {
                tracing::warn!(program = %inv.program, "timed out, killing");
                // best-effort kill: spawn a new handle via child would require
                // retaining it; in tokio the Child is consumed by `wait`, so
                // treat timeout as unrecoverable here.
                (-1, true)
            }
        },
        None => {
            let r = capture.await;
            (r.ok().and_then(|s| s.code()).unwrap_or(-1), false)
        }
    };

    let stdout = String::from_utf8_lossy(&stdout_buf).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_buf).into_owned();
    let out = CommandOutput {
        status,
        stdout,
        stderr,
        timed_out,
    };

    if !inv.allow_nonzero && !out.success() {
        anyhow::bail!(
            "`{} {}` exited {} (timed_out={}): {}",
            inv.program,
            inv.args.join(" "),
            out.status,
            out.timed_out,
            out.stderr.chars().take(800).collect::<String>()
        );
    }
    Ok(out)
}

/// Convenience: run with the current directory set, no env overrides,
/// default timeout, error on non-zero exit.
pub async fn run_at(program: &str, args: &[&str], cwd: &Path) -> Result<CommandOutput> {
    let inv = Invocation::new(program)
        .args(args.iter().map(|s| s.to_string()))
        .cwd(cwd);
    run(&inv).await
}

/// Check whether a binary is on PATH without running it.
pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_stdout() {
        let out = run(&Invocation::new("sh").arg("-c").arg("printf hello"))
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "hello");
    }

    #[tokio::test]
    async fn nonzero_errors_by_default() {
        let r = run(&Invocation::new("sh").arg("-c").arg("exit 7")).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn nonzero_allowed_when_opted_in() {
        let out = run(&Invocation::new("sh")
            .arg("-c")
            .arg("exit 7")
            .allow_nonzero())
        .await
        .unwrap();
        assert_eq!(out.status, 7);
    }

    #[tokio::test]
    async fn which_finds_sh() {
        assert!(which("sh").is_some());
    }
}
