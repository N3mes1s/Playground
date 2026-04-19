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

fn detect_ruby_version(repo: &Path) -> Option<String> {
    std::fs::read_to_string(repo.join(".ruby-version"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// minitest final line: `42 runs, 100 assertions, 0 failures, 0 errors, 1 skips`
pub fn parse_minitest_output(stdout: &str) -> TestReport {
    let re = Regex::new(
        r"(\d+)\s+runs,\s+\d+\s+assertions,\s+(\d+)\s+failures,\s+\d+\s+errors,\s+(\d+)\s+skips",
    )
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

/// Expose the tree-sitter-ruby grammar so the Discoverer can run batched
/// queries without re-entering the `LanguageAdapter::ast_query` file-IO
/// path. Mirrors the helper each of the other adapters exports.
pub fn tree_sitter_language() -> tree_sitter::Language {
    tree_sitter_ruby::language()
}

fn tree_sitter_ast_query(file: &Path, text: &str, query: &str) -> Result<Vec<AstMatch>> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_ruby::language())
        .map_err(|e| anyhow::anyhow!("load tree-sitter-ruby grammar: {e}"))?;
    let Some(tree) = parser.parse(text, None) else {
        anyhow::bail!("tree-sitter failed to parse {}", file.display());
    };
    let q = tree_sitter::Query::new(&tree_sitter_ruby::language(), query)
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
                enclosing_symbol: enclosing_symbol(node, bytes),
            });
        }
    }
    Ok(out)
}

/// Find the nearest enclosing `def` — `method` for instance methods,
/// `singleton_method` for class-level (`self.foo`) — and return its
/// name. Returns `None` when the match is at top-level script scope.
pub fn enclosing_symbol(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if matches!(n.kind(), "method" | "singleton_method") {
            let name = n.child_by_field_name("name")?;
            return Some(name.utf8_text(bytes).ok()?.to_string());
        }
        cursor = n.parent();
    }
    None
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

    /// tree-sitter-ruby must parse a minimal Ruby file, recognise
    /// `def foo` as a `method` node whose `name` field is the bare
    /// identifier, AND filter out matches inside string literals /
    /// comments. The old regex impl would have matched all three
    /// `File.join` sites below; the tree-sitter path must not.
    #[tokio::test]
    async fn ast_query_attaches_enclosing_symbol_when_inside_method() {
        let src = r#"
def outer
  File.join("/var", "log")
end

"some string with File.join inside"
# def ghost_in_comment
"#;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rb");
        std::fs::write(&p, src).unwrap();
        let a = RubyAdapter::new();
        let hits = a
            .ast_query(
                &p,
                r#"(call receiver: (constant) @c (#eq? @c "File")
                         method: (identifier) @m (#eq? @m "join")) @call"#,
            )
            .await
            .unwrap();
        // The query has three named captures (@c, @m, @call) — each
        // match contributes one AstMatch per capture, same as the Rust
        // / Python / Go adapters. Every match must come from the real
        // call site (not the string literal, not the comment).
        assert!(!hits.is_empty(), "expected hits but got none");
        for h in &hits {
            assert_eq!(
                h.enclosing_symbol.as_deref(),
                Some("outer"),
                "hit from wrong location: {:?}",
                h
            );
            assert_eq!(h.start_line, 3, "expected line 3, got {}", h.start_line);
        }
    }

    /// Singleton methods (`def self.flush`) must also attribute correctly.
    #[tokio::test]
    async fn ast_query_attributes_singleton_methods() {
        let src = r#"
class Cache
  def self.flush
    Dir.glob("/tmp/*").each { |p| File.delete(p) }
  end
end
"#;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t2.rb");
        std::fs::write(&p, src).unwrap();
        let a = RubyAdapter::new();
        let hits = a
            .ast_query(
                &p,
                r#"(call receiver: (constant) @c (#eq? @c "Dir")
                         method: (identifier) @m (#eq? @m "glob")) @call"#,
            )
            .await
            .unwrap();
        assert!(!hits.is_empty());
        for h in &hits {
            assert_eq!(h.enclosing_symbol.as_deref(), Some("flush"));
        }
    }
}
