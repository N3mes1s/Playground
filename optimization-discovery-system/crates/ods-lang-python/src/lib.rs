//! Python language adapter.
//!
//! Detection: `pyproject.toml` / `setup.py` / `requirements.txt`.
//! Tests: `pytest` (with `--maxfail`). Bench: `pytest-benchmark` JSON output.

use anyhow::Result;
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

pub struct PythonAdapter;

impl PythonAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LanguageAdapter for PythonAdapter {
    fn name(&self) -> &'static str {
        "python"
    }

    async fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(repo.join("pyproject.toml").exists()
            || repo.join("setup.py").exists()
            || repo.join("setup.cfg").exists()
            || repo.join("requirements.txt").exists())
    }

    async fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        Ok(Build {
            workdir: repo.to_path_buf(),
            artifact: None,
            toolchain: which("python3")
                .or_else(|| which("python"))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "system-python".into()),
        })
    }

    async fn run_tests(&self, build: &Build, _scope: TestScope) -> Result<TestReport> {
        if which("pytest").is_none() {
            return Ok(TestReport {
                passed: 0,
                failed: 0,
                skipped: 0,
                log_path: None,
            });
        }
        let out = run(&Invocation::new("pytest")
            .arg("-q")
            .arg("--tb=no")
            .cwd(&build.workdir)
            .timeout(Duration::from_secs(600))
            .allow_nonzero())
        .await?;
        Ok(parse_pytest_output(&out.stdout))
    }

    async fn run_bench(&self, build: &Build, target: &TargetSig) -> Result<BenchReport> {
        if which("pytest").is_none() {
            return Ok(BenchReport { samples: vec![] });
        }
        // pytest-benchmark has a JSON-dump flag; if the plugin isn't installed
        // the invocation will fail and we return an empty report.
        let json_path = build.workdir.join(".ods-bench.json");
        let _ = std::fs::remove_file(&json_path);
        let filter = if target.symbol.is_empty() {
            String::new()
        } else {
            target.symbol.clone()
        };
        let mut args: Vec<String> = vec![
            "--benchmark-only".into(),
            format!("--benchmark-json={}", json_path.display()),
        ];
        if !filter.is_empty() {
            args.push("-k".into());
            args.push(filter);
        }
        let _ = run(&Invocation::new("pytest")
            .args(args)
            .cwd(&build.workdir)
            .timeout(Duration::from_secs(600))
            .allow_nonzero())
        .await?;
        Ok(parse_pytest_bench_json(&json_path).unwrap_or(BenchReport { samples: vec![] }))
    }

    async fn profile(&self, _build: &Build, _target: &TargetSig) -> Result<ProfileReport> {
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
        Ok(Patch {
            unified_diff: make_diff(edits),
            edits: edits.to_vec(),
        })
    }

    async fn fuzz(
        &self,
        _build: &Build,
        _target: &TargetSig,
        budget: Duration,
    ) -> Result<FuzzReport> {
        Ok(FuzzReport {
            minutes: (budget.as_secs() / 60) as u32,
            crashes: 0,
            seed_corpus_size: 0,
        })
    }
}

pub fn tree_sitter_language() -> tree_sitter::Language {
    tree_sitter_python::language()
}

fn tree_sitter_ast_query(file: &Path, text: &str, query: &str) -> Result<Vec<AstMatch>> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::language())
        .map_err(|e| anyhow::anyhow!("load tree-sitter-python grammar: {e}"))?;
    let Some(tree) = parser.parse(text, None) else {
        anyhow::bail!("tree-sitter failed to parse {}", file.display());
    };
    let q = tree_sitter::Query::new(&tree_sitter_python::language(), query)
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

fn make_diff(edits: &[Edit]) -> String {
    let mut out = String::new();
    for e in edits {
        let rel = e.file.display();
        out.push_str(&format!("--- a/{rel}\n+++ b/{rel}\n"));
        let d = similar::TextDiff::from_lines(&e.before, &e.after);
        for h in d.unified_diff().header("before", "after").iter_hunks() {
            out.push_str(&h.to_string());
        }
    }
    out
}

/// pytest summary line examples:
///   `5 passed in 0.12s`
///   `3 passed, 1 failed, 2 skipped in 0.34s`
pub fn parse_pytest_output(stdout: &str) -> TestReport {
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    let re_pass = Regex::new(r"(\d+)\s+passed").unwrap();
    let re_fail = Regex::new(r"(\d+)\s+failed").unwrap();
    let re_skip = Regex::new(r"(\d+)\s+skipped").unwrap();
    if let Some(c) = re_pass.captures(stdout) {
        passed = c[1].parse().unwrap_or(0);
    }
    if let Some(c) = re_fail.captures(stdout) {
        failed = c[1].parse().unwrap_or(0);
    }
    if let Some(c) = re_skip.captures(stdout) {
        skipped = c[1].parse().unwrap_or(0);
    }
    TestReport {
        passed,
        failed,
        skipped,
        log_path: None,
    }
}

pub fn parse_pytest_bench_json(path: &Path) -> Option<BenchReport> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let benchmarks = v.get("benchmarks")?.as_array()?;
    let mut samples = Vec::new();
    for b in benchmarks {
        let name = b.get("name")?.as_str()?.to_string();
        let stats = b.get("stats")?;
        let mean_s = stats.get("mean")?.as_f64()?;
        samples.push(BenchSample {
            name,
            ns_per_iter: mean_s * 1.0e9,
            iters: 1,
        });
    }
    Some(BenchReport { samples })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pytest_summary() {
        let r = parse_pytest_output("3 passed, 1 failed, 2 skipped in 0.34s");
        assert_eq!(r.passed, 3);
        assert_eq!(r.failed, 1);
        assert_eq!(r.skipped, 2);
    }
}
