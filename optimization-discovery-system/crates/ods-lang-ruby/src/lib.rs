//! Ruby language adapter.
//!
//! Detection: `Gemfile` at the repo root. Tests via `bundle exec rake test`
//! when available, falling back to `ruby -Ilib -Itest` on a test glob. Bench
//! via `bundle exec rake bench` or direct `benchmark-ips` scripts.

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

pub struct RubyAdapter;

impl RubyAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RubyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LanguageAdapter for RubyAdapter {
    fn name(&self) -> &'static str {
        "ruby"
    }

    async fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(repo.join("Gemfile").exists() || repo.join(".ruby-version").exists())
    }

    async fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        if which("bundle").is_some() && repo.join("Gemfile").exists() {
            run(&Invocation::new("bundle")
                .arg("install")
                .cwd(repo)
                .allow_nonzero()
                .timeout(Duration::from_secs(600)))
                .await?;
        }
        Ok(Build {
            workdir: repo.to_path_buf(),
            artifact: None,
            toolchain: detect_ruby_version(repo).unwrap_or_else(|| "system".into()),
        })
    }

    async fn run_tests(&self, build: &Build, _scope: TestScope) -> Result<TestReport> {
        if build.workdir.join("Rakefile").exists() && which("bundle").is_some() {
            let out = run(&Invocation::new("bundle")
                .args(["exec", "rake", "test"].map(String::from))
                .cwd(&build.workdir)
                .timeout(Duration::from_secs(600))
                .allow_nonzero())
                .await?;
            return Ok(parse_minitest_output(&out.stdout));
        }
        if build.workdir.join("spec").exists() && which("bundle").is_some() {
            let out = run(&Invocation::new("bundle")
                .args(["exec", "rspec", "--format", "documentation"].map(String::from))
                .cwd(&build.workdir)
                .timeout(Duration::from_secs(600))
                .allow_nonzero())
                .await?;
            return Ok(parse_rspec_output(&out.stdout));
        }
        Ok(TestReport {
            passed: 0,
            failed: 0,
            skipped: 0,
            log_path: None,
        })
    }

    async fn run_bench(&self, build: &Build, _target: &TargetSig) -> Result<BenchReport> {
        if !build.workdir.join("benchmark").exists() {
            return Ok(BenchReport { samples: vec![] });
        }
        // benchmark-ips prints a report block; we attempt to aggregate.
        if which("bundle").is_some() {
            let out = run(&Invocation::new("bundle")
                .args(["exec", "rake", "bench"].map(String::from))
                .cwd(&build.workdir)
                .timeout(Duration::from_secs(600))
                .allow_nonzero())
                .await?;
            return Ok(parse_benchmark_ips_output(&out.stdout));
        }
        Ok(BenchReport { samples: vec![] })
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
        regex_line_match(file, query).await
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

fn detect_ruby_version(repo: &Path) -> Option<String> {
    std::fs::read_to_string(repo.join(".ruby-version"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// minitest final line: `42 runs, 100 assertions, 0 failures, 0 errors, 1 skips`
pub fn parse_minitest_output(stdout: &str) -> TestReport {
    let re =
        Regex::new(r"(\d+)\s+runs,\s+\d+\s+assertions,\s+(\d+)\s+failures,\s+\d+\s+errors,\s+(\d+)\s+skips")
            .unwrap();
    for caps in re.captures_iter(stdout) {
        let runs: u32 = caps[1].parse().unwrap_or(0);
        let failures: u32 = caps[2].parse().unwrap_or(0);
        let skips: u32 = caps[3].parse().unwrap_or(0);
        return TestReport {
            passed: runs.saturating_sub(failures + skips),
            failed: failures,
            skipped: skips,
            log_path: None,
        };
    }
    TestReport {
        passed: 0,
        failed: 0,
        skipped: 0,
        log_path: None,
    }
}

/// rspec: `42 examples, 0 failures, 1 pending`
pub fn parse_rspec_output(stdout: &str) -> TestReport {
    let re = Regex::new(r"(\d+)\s+examples?,\s+(\d+)\s+failures?(?:,\s+(\d+)\s+pending)?").unwrap();
    for caps in re.captures_iter(stdout) {
        let total: u32 = caps[1].parse().unwrap_or(0);
        let failures: u32 = caps[2].parse().unwrap_or(0);
        let pending: u32 = caps
            .get(3)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        return TestReport {
            passed: total.saturating_sub(failures + pending),
            failed: failures,
            skipped: pending,
            log_path: None,
        };
    }
    TestReport {
        passed: 0,
        failed: 0,
        skipped: 0,
        log_path: None,
    }
}

/// benchmark-ips: `   Calculating -------------------------------------`
///                 `        name  1.234M (± 1.2%) i/s -  ... in 5.00s`
pub fn parse_benchmark_ips_output(stdout: &str) -> BenchReport {
    let re = Regex::new(r"(?m)^\s*(\S[^\n]*?)\s+([\d\.]+)([MkK])?\s*\(.*?\)\s*i/s").unwrap();
    let mut samples = Vec::new();
    for caps in re.captures_iter(stdout) {
        let name = caps.get(1).unwrap().as_str().trim().to_string();
        let n: f64 = caps.get(2).unwrap().as_str().parse().unwrap_or(0.0);
        let ips = match caps.get(3).map(|m| m.as_str()) {
            Some("M") => n * 1_000_000.0,
            Some("k") | Some("K") => n * 1_000.0,
            _ => n,
        };
        if ips <= 0.0 {
            continue;
        }
        let ns_per_iter = 1.0e9 / ips;
        samples.push(BenchSample {
            name,
            ns_per_iter,
            iters: 1,
        });
    }
    BenchReport { samples }
}

fn make_diff(edits: &[Edit]) -> String {
    let mut diff = String::new();
    for e in edits {
        let rel = e.file.display();
        diff.push_str(&format!("--- a/{rel}\n+++ b/{rel}\n"));
        let d = similar::TextDiff::from_lines(&e.before, &e.after);
        for hunk in d.unified_diff().header("before", "after").iter_hunks() {
            diff.push_str(&hunk.to_string());
        }
    }
    diff
}

async fn regex_line_match(file: &Path, query: &str) -> Result<Vec<AstMatch>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minitest() {
        let r = parse_minitest_output("42 runs, 100 assertions, 1 failures, 0 errors, 2 skips");
        assert_eq!(r.passed, 39);
        assert_eq!(r.failed, 1);
        assert_eq!(r.skipped, 2);
    }

    #[test]
    fn parses_rspec() {
        let r = parse_rspec_output("7 examples, 0 failures, 1 pending");
        assert_eq!(r.passed, 6);
        assert_eq!(r.skipped, 1);
    }

    #[test]
    fn parses_benchmark_ips() {
        let s = "\
   join fast path    1.234M (± 1.2%) i/s -   2.000M in   1.620s
   join slow path  123.456k (± 0.5%) i/s -   0.200M in   1.620s
";
        let r = parse_benchmark_ips_output(s);
        assert_eq!(r.samples.len(), 2);
        assert!(r.samples[0].ns_per_iter > 0.0);
    }
}
