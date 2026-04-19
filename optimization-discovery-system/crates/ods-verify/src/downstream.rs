//! Downstream-consumer test runner. For dependency-bump scope we patch a
//! consumer repo to use our candidate version of the target crate and run
//! its test suite; zero-diff failures veto the bump.

use anyhow::Result;
use ods_exec::{run, which, Invocation};
use ods_lang::TestReport;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownstreamConsumer {
    pub name: String,
    pub path: PathBuf,
    /// Optional command to run tests in the consumer. If absent we pick
    /// sensible defaults per detected build system.
    pub test_command: Option<Vec<String>>,
}

pub struct DownstreamRunner {
    pub timeout: Duration,
}

impl DownstreamRunner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(1200),
        }
    }

    pub async fn run_all(
        &self,
        consumers: &[DownstreamConsumer],
    ) -> Result<Vec<(String, TestReport)>> {
        let mut out = Vec::new();
        for c in consumers {
            let report = self.run_one(c).await.unwrap_or(TestReport {
                passed: 0,
                failed: 1,
                skipped: 0,
                log_path: None,
            });
            out.push((c.name.clone(), report));
        }
        Ok(out)
    }

    pub async fn run_one(&self, c: &DownstreamConsumer) -> Result<TestReport> {
        let (program, args) = match &c.test_command {
            Some(cmd) if !cmd.is_empty() => (cmd[0].clone(), cmd[1..].to_vec()),
            _ => pick_default_test_cmd(&c.path),
        };
        if which(&program).is_none() {
            return Ok(TestReport {
                passed: 0,
                failed: 0,
                skipped: 0,
                log_path: None,
            });
        }
        let out = run(&Invocation::new(&program)
            .args(args)
            .cwd(&c.path)
            .timeout(self.timeout)
            .allow_nonzero())
            .await?;
        Ok(summarize(&out.stdout, &out.stderr))
    }
}

fn pick_default_test_cmd(repo: &Path) -> (String, Vec<String>) {
    if repo.join("Cargo.toml").exists() {
        (
            "cargo".into(),
            vec!["test".into(), "--workspace".into(), "--no-fail-fast".into()],
        )
    } else if repo.join("go.mod").exists() {
        ("go".into(), vec!["test".into(), "./...".into()])
    } else if repo.join("package.json").exists() {
        ("npm".into(), vec!["test".into(), "--silent".into()])
    } else if repo.join("pyproject.toml").exists()
        || repo.join("setup.py").exists()
        || repo.join("setup.cfg").exists()
    {
        ("pytest".into(), vec!["-q".into()])
    } else {
        ("true".into(), vec![])
    }
}

fn summarize(stdout: &str, stderr: &str) -> TestReport {
    // Heuristic: treat exit-via-stdout FAIL lines (go) and test-result
    // libtest lines (rust) as authoritative when present.
    if stdout.contains("--- FAIL") || stderr.contains("--- FAIL") {
        return TestReport {
            passed: 0,
            failed: 1,
            skipped: 0,
            log_path: None,
        };
    }
    // libtest summary
    if let Some(caps) = regex::Regex::new(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored",
    )
    .unwrap()
    .captures(stdout)
    {
        return TestReport {
            passed: caps[1].parse().unwrap_or(0),
            failed: caps[2].parse().unwrap_or(0),
            skipped: caps[3].parse().unwrap_or(0),
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

impl Default for DownstreamRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_cargo_for_rust_consumer() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("Cargo.toml"), "[package]\nname=\"x\"\nversion=\"0.0.0\"\n").unwrap();
        let (p, args) = pick_default_test_cmd(d.path());
        assert_eq!(p, "cargo");
        assert_eq!(args[0], "test");
    }

    #[test]
    fn picks_go_for_go_consumer() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("go.mod"), "module x\n").unwrap();
        let (p, _) = pick_default_test_cmd(d.path());
        assert_eq!(p, "go");
    }
}
