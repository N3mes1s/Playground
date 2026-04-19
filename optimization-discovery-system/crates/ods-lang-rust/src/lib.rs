//! Rust language adapter. MVP detects a Cargo workspace and wires Criterion /
//! cargo-test / cargo-fuzz / perf / cargo-flamegraph. The concrete tool
//! invocations land in stage 1; today we expose a typed skeleton so the loop
//! compiles end-to-end.

use anyhow::{Context, Result};
use ods_core::TargetSig;
use ods_lang::{
    AstMatch, BenchReport, Build, Edit, FuzzReport, LanguageAdapter, Patch, ProfileReport,
    TestReport, TestScope,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct RustAdapter;

impl RustAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageAdapter for RustAdapter {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(repo.join("Cargo.toml").exists())
    }

    fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        // Stage 1 will apply the patch into a worktree and run `cargo build
        // --release`. For now we only assert the layout exists.
        let manifest = repo.join("Cargo.toml");
        if !manifest.exists() {
            anyhow::bail!("not a cargo workspace: {}", repo.display());
        }
        Ok(Build {
            workdir: repo.to_path_buf(),
            artifact: None,
            toolchain: detect_toolchain(repo).unwrap_or_else(|| "stable".into()),
        })
    }

    fn run_tests(&self, _build: &Build, _scope: TestScope) -> Result<TestReport> {
        // Stage 1: `cargo test --no-fail-fast --message-format=json`.
        Ok(TestReport {
            passed: 0,
            failed: 0,
            skipped: 0,
            log_path: None,
        })
    }

    fn run_bench(&self, _build: &Build, _target: &TargetSig) -> Result<BenchReport> {
        // Stage 1: `cargo bench --bench <name> -- --output-format bencher`.
        Ok(BenchReport { samples: vec![] })
    }

    fn profile(&self, _build: &Build, _target: &TargetSig) -> Result<ProfileReport> {
        // Stage 1: perf_event_open + aya eBPF for syscalls and allocs.
        Ok(ProfileReport {
            wall: Duration::ZERO,
            cycles: None,
            instructions: None,
            llc_misses: None,
            branch_misses: None,
            syscall_counts: vec![],
            alloc_count: None,
            alloc_bytes: None,
            flame_svg_path: None,
        })
    }

    fn ast_query(&self, _file: &Path, _query: &str) -> Result<Vec<AstMatch>> {
        // Stage 1: tree-sitter-rust with the tree-sitter crate.
        Ok(vec![])
    }

    fn emit_patch(&self, edits: &[Edit]) -> Result<Patch> {
        Ok(Patch {
            unified_diff: unified_diff_stub(edits),
            edits: edits.to_vec(),
        })
    }

    fn fuzz(&self, _build: &Build, _target: &TargetSig, budget: Duration) -> Result<FuzzReport> {
        // Stage 1: `cargo fuzz run <target> -- -max_total_time=<budget>`.
        Ok(FuzzReport {
            minutes: budget.as_secs() as u32 / 60,
            crashes: 0,
            seed_corpus_size: 0,
        })
    }
}

fn detect_toolchain(repo: &Path) -> Option<String> {
    let path = repo.join("rust-toolchain.toml");
    if !path.exists() {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("channel") {
            let rest = rest.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

fn unified_diff_stub(edits: &[Edit]) -> String {
    // Full unified-diff emission lands in stage 1 via `similar` crate. For now
    // produce a deterministic header-only skeleton so downstream consumers can
    // roundtrip the Patch struct.
    let mut out = String::new();
    for e in edits {
        out.push_str(&format!("--- a/{}\n", display_path(&e.file)));
        out.push_str(&format!("+++ b/{}\n", display_path(&e.file)));
    }
    out
}

fn display_path(p: &PathBuf) -> String {
    p.display().to_string()
}

pub fn sanity_check(repo: &Path) -> Result<()> {
    RustAdapter::new()
        .detect(repo)
        .context("detect rust project")?;
    Ok(())
}
