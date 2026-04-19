//! Go language adapter. Invokes `go test` and `go test -bench` via subprocess
//! and parses their output.
//!
//! Detection: a `go.mod` at the repo root.

use anyhow::{Context, Result};
use async_trait::async_trait;
use ods_core::TargetSig;
use ods_exec::{run, which, Invocation};
use ods_lang::{
    AstMatch, BenchReport, BenchSample, Build, Edit, FuzzReport, LanguageAdapter, Patch,
    ProfileReport, TestReport, TestScope,
};
use regex::Regex;
use std::path::Path;
use std::time::Duration;

pub struct GoAdapter {
    pub default_timeout: Duration,
}

impl GoAdapter {
    pub fn new() -> Self {
        Self {
            default_timeout: Duration::from_secs(600),
        }
    }
}

impl Default for GoAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LanguageAdapter for GoAdapter {
    fn name(&self) -> &'static str {
        "go"
    }

    async fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(repo.join("go.mod").exists())
    }

    async fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        if !repo.join("go.mod").exists() {
            anyhow::bail!("no go.mod at {}", repo.display());
        }
        if which("go").is_none() {
            anyhow::bail!("go not found on PATH");
        }
        run(&Invocation::new("go")
            .args(["build", "./..."].map(String::from))
            .cwd(repo)
            .timeout(self.default_timeout)
            .allow_nonzero())
        .await
        .context("go build ./...")?;
        Ok(Build {
            workdir: repo.to_path_buf(),
            artifact: None,
            toolchain: detect_go_version(repo).unwrap_or_else(|| "system".into()),
        })
    }

    async fn run_tests(&self, build: &Build, _scope: TestScope) -> Result<TestReport> {
        let out = run(&Invocation::new("go")
            .args(["test", "-count=1", "./..."].map(String::from))
            .cwd(&build.workdir)
            .timeout(self.default_timeout)
            .allow_nonzero())
        .await?;
        Ok(parse_go_test_output(&out.stdout))
    }

    async fn run_bench(&self, build: &Build, target: &TargetSig) -> Result<BenchReport> {
        let filter = if target.symbol.is_empty() {
            ".".to_string()
        } else {
            target.symbol.clone()
        };
        let out = run(&Invocation::new("go")
            .args([
                "test".to_string(),
                "-bench".to_string(),
                filter,
                "-benchmem".to_string(),
                "-run=^$".to_string(),
                "./...".to_string(),
            ])
            .cwd(&build.workdir)
            .timeout(self.default_timeout)
            .allow_nonzero())
        .await?;
        Ok(parse_go_bench_output(&out.stdout))
    }

    async fn profile(&self, _build: &Build, _target: &TargetSig) -> Result<ProfileReport> {
        // Go's own `-cpuprofile`/`-memprofile` land in stage 2; today we
        // return an empty report so the gate can still run.
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

    async fn ast_query(&self, file: &Path, query: &str) -> Result<Vec<AstMatch>> {
        let text = tokio::fs::read_to_string(file).await?;
        tree_sitter_ast_query(file, &text, query)
    }

    fn emit_patch(&self, edits: &[Edit]) -> Result<Patch> {
        let mut diff = String::new();
        for e in edits {
            let rel = e.file.display();
            diff.push_str(&format!("--- a/{rel}\n+++ b/{rel}\n"));
            let d = similar::TextDiff::from_lines(&e.before, &e.after);
            for hunk in d.unified_diff().header("before", "after").iter_hunks() {
                diff.push_str(&hunk.to_string());
            }
        }
        Ok(Patch {
            unified_diff: diff,
            edits: edits.to_vec(),
        })
    }

    async fn fuzz(
        &self,
        build: &Build,
        target: &TargetSig,
        budget: Duration,
    ) -> Result<FuzzReport> {
        if which("go").is_none() {
            return Ok(FuzzReport {
                minutes: 0,
                crashes: 0,
                seed_corpus_size: 0,
            });
        }
        let out = run(&Invocation::new("go")
            .args([
                "test".to_string(),
                "-run=^$".to_string(),
                format!("-fuzz={}", target.symbol),
                format!("-fuzztime={}s", budget.as_secs()),
                "./...".to_string(),
            ])
            .cwd(&build.workdir)
            .timeout(budget + Duration::from_secs(30))
            .allow_nonzero())
        .await?;
        let crashes = if out.stderr.contains("FAIL") || out.stdout.contains("failing input") {
            1
        } else {
            0
        };
        Ok(FuzzReport {
            minutes: (budget.as_secs() / 60) as u32,
            crashes,
            seed_corpus_size: 0,
        })
    }
}

pub fn tree_sitter_language() -> tree_sitter::Language {
    tree_sitter_go::language()
}

fn tree_sitter_ast_query(file: &Path, text: &str, query: &str) -> Result<Vec<AstMatch>> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::language())
        .map_err(|e| anyhow::anyhow!("load tree-sitter-go grammar: {e}"))?;
    let Some(tree) = parser.parse(text, None) else {
        anyhow::bail!("tree-sitter failed to parse {}", file.display());
    };
    let q = tree_sitter::Query::new(&tree_sitter_go::language(), query)
        .map_err(|e| anyhow::anyhow!("compile tree-sitter query `{query}`: {e}"))?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    for m in cursor.matches(&q, tree.root_node(), bytes) {
        for cap in m.captures {
            let node = cap.node;
            let start = node.start_position();
            let end = node.end_position();
            let matched = node.utf8_text(bytes).unwrap_or("").to_string();
            out.push(AstMatch {
                file: file.to_path_buf(),
                start_line: (start.row + 1) as u32,
                end_line: (end.row + 1) as u32,
                text: matched,
            });
        }
    }
    Ok(out)
}

fn detect_go_version(repo: &Path) -> Option<String> {
    let text = std::fs::read_to_string(repo.join("go.mod")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("go ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Parse `go test` output. Typical shape:
///   `ok     example.com/mod   0.012s`
///   `--- FAIL: TestFoo (0.00s)`
///   `FAIL    example.com/mod   0.012s`
pub fn parse_go_test_output(stdout: &str) -> TestReport {
    let mut failed = 0u32;
    let mut passed = 0u32;
    for line in stdout.lines() {
        if line.contains("--- FAIL:") {
            failed += 1;
        } else if line.contains("--- PASS:") {
            passed += 1;
        }
    }
    // Fall back to package-level ok/FAIL when per-test output isn't verbose.
    if passed == 0 && failed == 0 {
        for line in stdout.lines() {
            let t = line.trim_start();
            if t.starts_with("ok ") {
                passed += 1;
            } else if t.starts_with("FAIL") {
                failed += 1;
            }
        }
    }
    TestReport {
        passed,
        failed,
        skipped: 0,
        log_path: None,
    }
}

/// Parse `go test -bench` output:
///   `BenchmarkName-8    1000000    1234 ns/op    16 B/op    1 allocs/op`
pub fn parse_go_bench_output(stdout: &str) -> BenchReport {
    let re = Regex::new(r"(?m)^(Benchmark\S+)\s+(\d+)\s+([\d\.]+)\s+ns/op").unwrap();
    let mut samples = Vec::new();
    for caps in re.captures_iter(stdout) {
        let name = caps.get(1).unwrap().as_str().to_string();
        let iters: u64 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
        let ns: f64 = caps.get(3).unwrap().as_str().parse().unwrap_or(0.0);
        samples.push(BenchSample {
            name,
            ns_per_iter: ns,
            iters,
        });
    }
    BenchReport { samples }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_test_ok_and_fail() {
        let s = "\
ok      example.com/mod  0.010s
--- FAIL: TestOne (0.00s)
FAIL    example.com/mod  0.011s
";
        let r = parse_go_test_output(s);
        assert_eq!(r.failed, 1);
    }

    #[test]
    fn parses_go_bench() {
        let s = "BenchmarkFoo-8    1000000    1234 ns/op    16 B/op    1 allocs/op";
        let r = parse_go_bench_output(s);
        assert_eq!(r.samples.len(), 1);
        assert_eq!(r.samples[0].name, "BenchmarkFoo-8");
        assert_eq!(r.samples[0].iters, 1_000_000);
        assert!((r.samples[0].ns_per_iter - 1234.0).abs() < 1e-6);
    }
}
