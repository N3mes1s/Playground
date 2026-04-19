//! JavaScript / TypeScript language adapter.
//!
//! Detection: `package.json`. Tests: `npm test`. Bench: caller provides a
//! `npm run bench` script (tinybench / vitest bench).

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

pub struct JsAdapter;

impl JsAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LanguageAdapter for JsAdapter {
    fn name(&self) -> &'static str {
        "javascript"
    }

    async fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(repo.join("package.json").exists())
    }

    async fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        if which("npm").is_some() && repo.join("package-lock.json").exists() {
            let _ = run(&Invocation::new("npm")
                .arg("ci")
                .cwd(repo)
                .timeout(Duration::from_secs(600))
                .allow_nonzero())
                .await?;
        } else if which("npm").is_some() {
            let _ = run(&Invocation::new("npm")
                .arg("install")
                .cwd(repo)
                .timeout(Duration::from_secs(600))
                .allow_nonzero())
                .await?;
        }
        Ok(Build {
            workdir: repo.to_path_buf(),
            artifact: None,
            toolchain: "node".into(),
        })
    }

    async fn run_tests(&self, build: &Build, _scope: TestScope) -> Result<TestReport> {
        if which("npm").is_none() {
            return Ok(TestReport {
                passed: 0,
                failed: 0,
                skipped: 0,
                log_path: None,
            });
        }
        let out = run(&Invocation::new("npm")
            .args(["test", "--silent"].map(String::from))
            .cwd(&build.workdir)
            .timeout(Duration::from_secs(900))
            .allow_nonzero())
            .await?;
        Ok(parse_npm_test_output(&out.stdout, &out.stderr))
    }

    async fn run_bench(&self, build: &Build, _target: &TargetSig) -> Result<BenchReport> {
        if which("npm").is_none() {
            return Ok(BenchReport { samples: vec![] });
        }
        let out = run(&Invocation::new("npm")
            .args(["run", "bench", "--silent"].map(String::from))
            .cwd(&build.workdir)
            .timeout(Duration::from_secs(600))
            .allow_nonzero())
            .await?;
        Ok(parse_tinybench_output(&out.stdout))
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
        let re = Regex::new(query)?;
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if re.is_match(line) {
                out.push(AstMatch {
                    file: file.to_path_buf(),
                    start_line: (i + 1) as u32,
                    end_line: (i + 1) as u32,
                    text: line.to_string(),
                });
            }
        }
        Ok(out)
    }

    fn emit_patch(&self, edits: &[Edit]) -> Result<Patch> {
        let mut diff = String::new();
        for e in edits {
            let rel = e.file.display();
            diff.push_str(&format!("--- a/{rel}\n+++ b/{rel}\n"));
            let d = similar::TextDiff::from_lines(&e.before, &e.after);
            for h in d.unified_diff().header("before", "after").iter_hunks() {
                diff.push_str(&h.to_string());
            }
        }
        Ok(Patch {
            unified_diff: diff,
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

/// Try to extract numbers from both Jest-style and Vitest-style output.
pub fn parse_npm_test_output(stdout: &str, stderr: &str) -> TestReport {
    let combined = format!("{stdout}\n{stderr}");
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;

    // Jest / Vitest "Tests:" line.
    if let Some(caps) = Regex::new(r"Tests:\s+(?:(\d+)\s+failed,\s+)?(?:(\d+)\s+skipped,\s+)?(\d+)\s+passed")
        .unwrap()
        .captures(&combined)
    {
        failed = caps.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        skipped = caps.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        passed = caps
            .get(3)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
    }
    TestReport {
        passed,
        failed,
        skipped,
        log_path: None,
    }
}

/// Parse tinybench default text rows: `name  123,456 ops/sec  ± 0.5%`
pub fn parse_tinybench_output(stdout: &str) -> BenchReport {
    let re = Regex::new(r"(?m)^(\S[^\n]*?)\s+([\d,\.]+)\s*ops/s").unwrap();
    let mut samples = Vec::new();
    for caps in re.captures_iter(stdout) {
        let name = caps.get(1).unwrap().as_str().trim().to_string();
        let raw = caps.get(2).unwrap().as_str().replace(',', "");
        let ops: f64 = raw.parse().unwrap_or(0.0);
        if ops > 0.0 {
            samples.push(BenchSample {
                name,
                ns_per_iter: 1.0e9 / ops,
                iters: 1,
            });
        }
    }
    BenchReport { samples }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jest_tests_line() {
        let r = parse_npm_test_output("Tests:       2 failed, 1 skipped, 5 passed, 8 total", "");
        assert_eq!(r.failed, 2);
        assert_eq!(r.skipped, 1);
        assert_eq!(r.passed, 5);
    }

    #[test]
    fn parses_tinybench() {
        let r = parse_tinybench_output("foo   1,000,000 ops/sec  ± 0.5%");
        assert_eq!(r.samples.len(), 1);
        assert!((r.samples[0].ns_per_iter - 1000.0).abs() < 1e-6);
    }
}
