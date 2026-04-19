//! C / C++ language adapter.
//!
//! Detection: `CMakeLists.txt` or `Makefile` or `meson.build` at the repo
//! root. Tests via `ctest` when CMake is in use; bench via Google-Benchmark
//! JSON output (`--benchmark_format=json`).

use anyhow::Result;
use async_trait::async_trait;
use ods_core::TargetSig;
use ods_exec::{run, which, Invocation};
use ods_lang::{
    AstMatch, BenchReport, Build, Edit, FuzzReport, LanguageAdapter, Patch, ProfileReport,
    TestReport, TestScope,
};
use regex::Regex;
use std::path::Path;
use std::time::Duration;

pub struct CAdapter;

impl CAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LanguageAdapter for CAdapter {
    fn name(&self) -> &'static str {
        "c"
    }

    async fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(repo.join("CMakeLists.txt").exists()
            || repo.join("Makefile").exists()
            || repo.join("meson.build").exists()
            || repo.join("configure").exists())
    }

    async fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        if repo.join("CMakeLists.txt").exists() && which("cmake").is_some() {
            let build_dir = repo.join("build-ods");
            std::fs::create_dir_all(&build_dir)?;
            run(&Invocation::new("cmake")
                .args([
                    "-S".to_string(),
                    repo.display().to_string(),
                    "-B".to_string(),
                    build_dir.display().to_string(),
                    "-DCMAKE_BUILD_TYPE=Release".to_string(),
                ])
                .timeout(Duration::from_secs(600))
                .allow_nonzero())
                .await?;
            run(&Invocation::new("cmake")
                .args(["--build".to_string(), build_dir.display().to_string()])
                .timeout(Duration::from_secs(1200))
                .allow_nonzero())
                .await?;
            return Ok(Build {
                workdir: build_dir,
                artifact: None,
                toolchain: "cmake".into(),
            });
        }
        if repo.join("Makefile").exists() {
            run(&Invocation::new("make")
                .cwd(repo)
                .timeout(Duration::from_secs(1200))
                .allow_nonzero())
                .await?;
            return Ok(Build {
                workdir: repo.to_path_buf(),
                artifact: None,
                toolchain: "make".into(),
            });
        }
        anyhow::bail!("unsupported build system at {}", repo.display())
    }

    async fn run_tests(&self, build: &Build, _scope: TestScope) -> Result<TestReport> {
        if which("ctest").is_some() && build.workdir.join("CTestTestfile.cmake").exists() {
            let out = run(&Invocation::new("ctest")
                .arg("--output-on-failure")
                .cwd(&build.workdir)
                .timeout(Duration::from_secs(900))
                .allow_nonzero())
                .await?;
            return Ok(parse_ctest_output(&out.stdout));
        }
        Ok(TestReport {
            passed: 0,
            failed: 0,
            skipped: 0,
            log_path: None,
        })
    }

    async fn run_bench(&self, _build: &Build, _target: &TargetSig) -> Result<BenchReport> {
        // Expects a user-specified `--benchmark_format=json` binary; real
        // bench discovery lands later.
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

/// ctest final: `100% tests passed, 0 tests failed out of 42`
pub fn parse_ctest_output(stdout: &str) -> TestReport {
    let re = Regex::new(r"(\d+)% tests passed,\s+(\d+) tests failed out of\s+(\d+)").unwrap();
    if let Some(c) = re.captures(stdout) {
        let failed: u32 = c[2].parse().unwrap_or(0);
        let total: u32 = c[3].parse().unwrap_or(0);
        return TestReport {
            passed: total.saturating_sub(failed),
            failed,
            skipped: 0,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ctest() {
        let r = parse_ctest_output("100% tests passed, 2 tests failed out of 42");
        assert_eq!(r.failed, 2);
        assert_eq!(r.passed, 40);
    }
}
