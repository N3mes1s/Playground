use anyhow::Result;
use ods_exec::{run, which, Invocation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "kebab-case")]
pub enum SemverVerdict {
    Compatible,
    Breaking(Vec<String>),
    Unchecked(String),
}

pub struct SemverCheck;

impl SemverCheck {
    /// Typed stub kept for tests that don't want to shell out.
    pub fn run_stub(reason: impl Into<String>) -> SemverVerdict {
        SemverVerdict::Unchecked(reason.into())
    }

    /// Shell out to `cargo semver-checks check-release` in `workdir`. The tool
    /// is optional; its absence returns [`SemverVerdict::Unchecked`] so the
    /// gate can still decide whether a public-API change is acceptable.
    pub async fn check_release(workdir: &Path) -> Result<SemverVerdict> {
        if which("cargo").is_none() {
            return Ok(SemverVerdict::Unchecked("cargo not on PATH".into()));
        }
        // `cargo semver-checks` is registered as a subcommand via the
        // `cargo-semver-checks` binary; detect either spelling.
        let has_subcommand = which("cargo-semver-checks").is_some();
        if !has_subcommand {
            return Ok(SemverVerdict::Unchecked(
                "cargo-semver-checks not installed".into(),
            ));
        }
        let out = run(&Invocation::new("cargo")
            .args(["semver-checks", "check-release", "--workspace"].map(String::from))
            .cwd(workdir)
            .timeout(Duration::from_secs(600))
            .allow_nonzero())
        .await?;
        if out.status == 0 {
            return Ok(SemverVerdict::Compatible);
        }
        let items = parse_breaking_items(&out.stderr, &out.stdout);
        Ok(SemverVerdict::Breaking(items))
    }
}

/// Extract breaking-change lines from cargo-semver-checks output. The tool
/// prints lines like `--- failure <lint_name>: <description>`.
fn parse_breaking_items(stderr: &str, stdout: &str) -> Vec<String> {
    let re = Regex::new(r"(?m)^---\s+failure\s+(.+)$").unwrap();
    let mut out = Vec::new();
    for hay in [stderr, stdout] {
        for caps in re.captures_iter(hay) {
            out.push(caps.get(1).unwrap().as_str().trim().to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failure_lines() {
        let stderr = "\
Checking foo v0.1.0 -> v0.2.0
--- failure trait_method_removed: method removed in public trait
--- failure struct_missing_field: required field removed
all done
";
        let items = parse_breaking_items(stderr, "");
        assert_eq!(items.len(), 2);
        assert!(items[0].contains("trait_method_removed"));
    }
}
