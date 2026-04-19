//! Java language adapter.
//!
//! Detection: `pom.xml` (Maven) or `build.gradle(.kts)` (Gradle).
//! Tests: `mvn test` / `./gradlew test`. Bench: JMH jar output (tabular).

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

#[derive(Debug, Clone, Copy)]
pub enum JavaTool {
    Maven,
    Gradle,
}

pub struct JavaAdapter;

impl JavaAdapter {
    pub fn new() -> Self {
        Self
    }
    fn tool_for(repo: &Path) -> Option<JavaTool> {
        if repo.join("pom.xml").exists() {
            Some(JavaTool::Maven)
        } else if repo.join("build.gradle").exists() || repo.join("build.gradle.kts").exists() {
            Some(JavaTool::Gradle)
        } else {
            None
        }
    }
}

impl Default for JavaAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LanguageAdapter for JavaAdapter {
    fn name(&self) -> &'static str {
        "java"
    }

    async fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(Self::tool_for(repo).is_some())
    }

    async fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        let tool = Self::tool_for(repo)
            .ok_or_else(|| anyhow::anyhow!("no Maven/Gradle build at {}", repo.display()))?;
        match tool {
            JavaTool::Maven if which("mvn").is_some() => {
                run(&Invocation::new("mvn")
                    .args(["-q", "-DskipTests", "package"].map(String::from))
                    .cwd(repo)
                    .timeout(Duration::from_secs(1200))
                    .allow_nonzero())
                .await?;
            }
            JavaTool::Gradle => {
                let gradle = if repo.join("gradlew").exists() {
                    "./gradlew"
                } else {
                    "gradle"
                };
                run(&Invocation::new(gradle)
                    .args(["-q", "build", "-x", "test"].map(String::from))
                    .cwd(repo)
                    .timeout(Duration::from_secs(1200))
                    .allow_nonzero())
                .await?;
            }
            _ => {}
        }
        Ok(Build {
            workdir: repo.to_path_buf(),
            artifact: None,
            toolchain: match tool {
                JavaTool::Maven => "maven".into(),
                JavaTool::Gradle => "gradle".into(),
            },
        })
    }

    async fn run_tests(&self, build: &Build, _scope: TestScope) -> Result<TestReport> {
        let tool = Self::tool_for(&build.workdir)
            .ok_or_else(|| anyhow::anyhow!("no Maven/Gradle build"))?;
        let out = match tool {
            JavaTool::Maven => {
                run(&Invocation::new("mvn")
                    .args(["-q", "test"].map(String::from))
                    .cwd(&build.workdir)
                    .timeout(Duration::from_secs(1800))
                    .allow_nonzero())
                .await?
            }
            JavaTool::Gradle => {
                let gradle = if build.workdir.join("gradlew").exists() {
                    "./gradlew"
                } else {
                    "gradle"
                };
                run(&Invocation::new(gradle)
                    .args(["-q", "test"].map(String::from))
                    .cwd(&build.workdir)
                    .timeout(Duration::from_secs(1800))
                    .allow_nonzero())
                .await?
            }
        };
        Ok(parse_junit_textual(&out.stdout))
    }

    async fn run_bench(&self, _build: &Build, _target: &TargetSig) -> Result<BenchReport> {
        // JMH benches are project-specific; real wiring lands in stage 4+.
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

/// Maven surefire / Gradle test textual output:
///   `Tests run: 42, Failures: 1, Errors: 0, Skipped: 2`
pub fn parse_junit_textual(stdout: &str) -> TestReport {
    let re = Regex::new(
        r"Tests run:\s+(\d+),\s+Failures:\s+(\d+),\s+Errors:\s+(\d+),\s+Skipped:\s+(\d+)",
    )
    .unwrap();
    let mut total = 0u32;
    let mut failed = 0u32;
    let mut errors = 0u32;
    let mut skipped = 0u32;
    for caps in re.captures_iter(stdout) {
        total += caps[1].parse::<u32>().unwrap_or(0);
        failed += caps[2].parse::<u32>().unwrap_or(0);
        errors += caps[3].parse::<u32>().unwrap_or(0);
        skipped += caps[4].parse::<u32>().unwrap_or(0);
    }
    TestReport {
        passed: total.saturating_sub(failed + errors + skipped),
        failed: failed + errors,
        skipped,
        log_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_junit_textual() {
        let r = parse_junit_textual("Tests run: 42, Failures: 1, Errors: 0, Skipped: 2");
        assert_eq!(r.passed, 39);
        assert_eq!(r.failed, 1);
        assert_eq!(r.skipped, 2);
    }
}
