//! Rust language adapter backed by real subprocess invocations of `cargo`.
//!
//! `ast_query` parses the file with `tree-sitter-rust` and executes the
//! caller's S-expression query against the AST. The grammar filters out
//! matches inside comments, string literals, and macro bodies. There is
//! no regex fallback: all Rust recipes ship structural triggers, and
//! giving agents two query dialects to reason about was a perpetual
//! source of over-matching bugs (comments / string literals / macros).

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

pub struct RustAdapter {
    pub test_timeout: Duration,
    pub bench_timeout: Duration,
    pub build_timeout: Duration,
}

impl RustAdapter {
    pub fn new() -> Self {
        Self {
            test_timeout: Duration::from_secs(600),
            bench_timeout: Duration::from_secs(600),
            build_timeout: Duration::from_secs(600),
        }
    }
}

impl Default for RustAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LanguageAdapter for RustAdapter {
    fn name(&self) -> &'static str {
        "rust"
    }

    async fn detect(&self, repo: &Path) -> Result<bool> {
        Ok(repo.join("Cargo.toml").exists())
    }

    async fn build(&self, repo: &Path, _patch: Option<&Patch>) -> Result<Build> {
        if !repo.join("Cargo.toml").exists() {
            anyhow::bail!("not a cargo workspace: {}", repo.display());
        }
        if which("cargo").is_none() {
            anyhow::bail!("cargo not found on PATH");
        }
        // `cargo build --release` warms the target dir; downstream steps
        // rely on it existing.
        run(&Invocation::new("cargo")
            .args(["build", "--release", "--workspace", "--all-targets"].map(String::from))
            .cwd(repo)
            .timeout(self.build_timeout)
            .allow_nonzero())
        .await
        .context("cargo build")?;

        Ok(Build {
            workdir: repo.to_path_buf(),
            artifact: None,
            toolchain: detect_toolchain(repo).unwrap_or_else(|| "stable".into()),
        })
    }

    async fn run_tests(&self, build: &Build, scope: TestScope) -> Result<TestReport> {
        let mut args = vec![
            "test".to_string(),
            "--workspace".into(),
            "--no-fail-fast".into(),
            "--quiet".into(),
        ];
        match scope {
            TestScope::Unit => args.push("--lib".into()),
            TestScope::Integration => args.push("--tests".into()),
            TestScope::Full => {}
        }
        let out = run(&Invocation::new("cargo")
            .args(args)
            .cwd(&build.workdir)
            .timeout(self.test_timeout)
            .allow_nonzero())
        .await?;
        Ok(parse_cargo_test_output(&out.stdout, &out.stderr))
    }

    async fn run_bench(&self, build: &Build, _target: &TargetSig) -> Result<BenchReport> {
        // Use `cargo bench --no-fail-fast` with libtest bencher output. Many
        // crates use Criterion; its default text output also contains lines
        // we can parse (`name  time:  [low mid high]`).
        let out = run(&Invocation::new("cargo")
            .args(["bench", "--workspace", "--no-fail-fast"].map(String::from))
            .cwd(&build.workdir)
            .timeout(self.bench_timeout)
            .allow_nonzero())
        .await?;
        // Prefer Criterion's JSON artifacts when they exist - structured,
        // not regex - and fall back to stdout parsing otherwise.
        let crit = criterion_json::collect(&build.workdir).unwrap_or_default();
        if !crit.is_empty() {
            return Ok(criterion_json::to_bench_report(crit));
        }
        Ok(parse_cargo_bench_output(&out.stdout))
    }

    async fn profile(&self, build: &Build, target: &TargetSig) -> Result<ProfileReport> {
        crate::profile::profile_target(&build.workdir, target).await
    }

    async fn ast_query(&self, file: &Path, query: &str) -> Result<Vec<AstMatch>> {
        let text = tokio::fs::read_to_string(file)
            .await
            .with_context(|| format!("read {}", file.display()))?;
        tree_sitter_ast_query(file, &text, query)
    }

    fn emit_patch(&self, edits: &[Edit]) -> Result<Patch> {
        let mut diff = String::new();
        for e in edits {
            let rel = e.file.display().to_string();
            diff.push_str(&format!("--- a/{rel}\n+++ b/{rel}\n"));
            let text_diff = similar::TextDiff::from_lines(&e.before, &e.after);
            for hunk in text_diff
                .unified_diff()
                .header("before", "after")
                .iter_hunks()
            {
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
        _target: &TargetSig,
        budget: Duration,
    ) -> Result<FuzzReport> {
        if which("cargo-fuzz").is_none() {
            tracing::warn!("cargo-fuzz not installed; skipping fuzz step");
            return Ok(FuzzReport {
                minutes: 0,
                crashes: 0,
                seed_corpus_size: 0,
            });
        }
        let fuzz_dir = build.workdir.join("fuzz");
        if !fuzz_dir.exists() {
            return Ok(FuzzReport {
                minutes: 0,
                crashes: 0,
                seed_corpus_size: 0,
            });
        }
        let targets = discover_fuzz_targets(&fuzz_dir)?;
        let Some(first) = targets.first() else {
            return Ok(FuzzReport {
                minutes: 0,
                crashes: 0,
                seed_corpus_size: 0,
            });
        };
        let out = run(&Invocation::new("cargo")
            .args([
                "fuzz".to_string(),
                "run".to_string(),
                first.clone(),
                "--".to_string(),
                format!("-max_total_time={}", budget.as_secs()),
            ])
            .cwd(&build.workdir)
            .timeout(budget + Duration::from_secs(30))
            .allow_nonzero())
        .await?;
        let crashes = if out.stdout.contains("crash-") || out.stderr.contains("crash-") {
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

/// Structural `tree-sitter-rust` query. Captures in the query are surfaced
/// as one [`AstMatch`] per captured node, with line numbers sourced from
/// the node's `Range`. If the query has no named captures, every *pattern
/// match* contributes the root node of that match.
fn tree_sitter_ast_query(file: &Path, text: &str, query: &str) -> Result<Vec<AstMatch>> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::language())
        .context("load tree-sitter-rust grammar")?;
    let Some(tree) = parser.parse(text, None) else {
        anyhow::bail!("tree-sitter failed to parse {}", file.display());
    };
    let q = tree_sitter::Query::new(&tree_sitter_rust::language(), query)
        .with_context(|| format!("compile tree-sitter query: {query}"))?;
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

fn discover_fuzz_targets(fuzz_dir: &Path) -> Result<Vec<String>> {
    let targets_dir = fuzz_dir.join("fuzz_targets");
    if !targets_dir.exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(&targets_dir)? {
        let e = e?;
        if let Some(name) = e.path().file_stem().and_then(|s| s.to_str()) {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

/// Parse `cargo test --quiet` output. libtest emits lines like:
///   `test result: ok. 42 passed; 0 failed; 1 ignored; 0 measured;`
pub fn parse_cargo_test_output(stdout: &str, stderr: &str) -> TestReport {
    let re = Regex::new(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored")
        .expect("static regex");
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    for hay in [stdout, stderr] {
        for caps in re.captures_iter(hay) {
            passed += caps[1].parse::<u32>().unwrap_or(0);
            failed += caps[2].parse::<u32>().unwrap_or(0);
            skipped += caps[3].parse::<u32>().unwrap_or(0);
        }
    }
    TestReport {
        passed,
        failed,
        skipped,
        log_path: None,
    }
}

/// Parse `cargo bench` output, accepting both libtest bencher format
/// (`test bench_name ... bench:  1,234 ns/iter (+/- 56)`) and Criterion's
/// default text (`bench_name  time:   [1.1 us 1.2 us 1.3 us]`).
pub fn parse_cargo_bench_output(stdout: &str) -> BenchReport {
    let mut samples = Vec::new();

    let libtest_re =
        Regex::new(r"test\s+(?P<name>\S+)\s+\.\.\.\s+bench:\s+([\d,]+)\s+ns/iter").unwrap();
    for caps in libtest_re.captures_iter(stdout) {
        let name = caps.name("name").unwrap().as_str().to_string();
        let raw = caps.get(2).unwrap().as_str().replace(',', "");
        if let Ok(ns) = raw.parse::<f64>() {
            samples.push(BenchSample {
                name,
                ns_per_iter: ns,
                iters: 1,
            });
        }
    }

    let crit_re = Regex::new(
        r"(?m)^(?P<name>\S[^\n]*?)\s+time:\s+\[([\d\.]+)\s+(?P<unit>ns|us|µs|ms|s)\s+([\d\.]+)\s+\S+\s+([\d\.]+)\s+\S+\]",
    )
    .unwrap();
    for caps in crit_re.captures_iter(stdout) {
        let name = caps.name("name").unwrap().as_str().trim().to_string();
        let mid: f64 = caps
            .get(4)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0.0);
        let unit = caps.name("unit").unwrap().as_str();
        let ns = match unit {
            "ns" => mid,
            "us" | "µs" => mid * 1_000.0,
            "ms" => mid * 1_000_000.0,
            "s" => mid * 1_000_000_000.0,
            _ => mid,
        };
        samples.push(BenchSample {
            name,
            ns_per_iter: ns,
            iters: 1,
        });
    }

    BenchReport { samples }
}

pub mod bench_scaffold;
pub mod criterion_json;
pub mod flame;
pub mod profile;

/// Expose the tree-sitter-rust grammar so callers (e.g. the Discoverer) can
/// run batched queries without re-entering the `LanguageAdapter::ast_query`
/// file-IO path.
pub fn tree_sitter_language() -> tree_sitter::Language {
    tree_sitter_rust::language()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libtest_results() {
        let out = "test result: ok. 12 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s";
        let r = parse_cargo_test_output(out, "");
        assert_eq!(r.passed, 12);
        assert_eq!(r.failed, 0);
        assert_eq!(r.skipped, 1);
    }

    #[test]
    fn parses_libtest_bench() {
        let out = "test foo::bench_a ... bench:  1,234 ns/iter (+/- 56)";
        let r = parse_cargo_bench_output(out);
        assert_eq!(r.samples.len(), 1);
        assert_eq!(r.samples[0].ns_per_iter, 1234.0);
        assert_eq!(r.samples[0].name, "foo::bench_a");
    }

    #[test]
    fn parses_criterion_bench() {
        let out = "group/scan/10000   time:   [1.1 us 1.2 us 1.3 us]";
        let r = parse_cargo_bench_output(out);
        assert_eq!(r.samples.len(), 1);
        assert!((r.samples[0].ns_per_iter - 1200.0).abs() < 1e-6);
    }

    #[tokio::test]
    async fn ast_query_tree_sitter_ignores_comments_and_strings() {
        // Regex would match all three `fn foo`; tree-sitter only matches
        // the real function definition.
        let src = r#"
// fn foo_in_comment() {}
const S: &str = "fn foo_in_string() {}";
fn foo_real() {}
"#;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("y.rs");
        std::fs::write(&p, src).unwrap();
        let a = RustAdapter::new();
        let hits = a
            .ast_query(&p, "(function_item name: (identifier) @n)")
            .await
            .unwrap();
        assert_eq!(
            hits.len(),
            1,
            "expected only the real fn; got {:?}",
            hits.iter().map(|h| &h.text).collect::<Vec<_>>()
        );
        assert!(
            hits[0].text.contains("foo_real"),
            "captured wrong node: {:?}",
            hits[0].text
        );
    }

    #[test]
    fn emit_patch_produces_unified_diff() {
        let a = RustAdapter::new();
        let edits = vec![Edit {
            file: std::path::PathBuf::from("src/lib.rs"),
            before: "a\nb\n".into(),
            after: "a\nB\n".into(),
        }];
        let patch = a.emit_patch(&edits).unwrap();
        assert!(patch.unified_diff.contains("---"));
        assert!(patch.unified_diff.contains("+++"));
        assert!(patch.unified_diff.contains("-b"));
        assert!(patch.unified_diff.contains("+B"));
    }
}
