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

    async fn ast_query_batch(&self, file: &Path, queries: &[&str]) -> Result<Vec<Vec<AstMatch>>> {
        let text = tokio::fs::read_to_string(file)
            .await
            .with_context(|| format!("read {}", file.display()))?;
        tree_sitter_ast_query_batch(file, &text, queries)
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
    let results = tree_sitter_ast_query_batch(file, text, &[query])?;
    Ok(results.into_iter().next().unwrap_or_default())
}

/// Parse `text` once, then execute every query in `queries` against the
/// shared tree. Returns one `Vec<AstMatch>` per query, in input order.
fn tree_sitter_ast_query_batch(
    file: &Path,
    text: &str,
    queries: &[&str],
) -> Result<Vec<Vec<AstMatch>>> {
    let lang = tree_sitter_rust::language();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&lang)
        .context("load tree-sitter-rust grammar")?;
    let Some(tree) = parser.parse(text, None) else {
        anyhow::bail!("tree-sitter failed to parse {}", file.display());
    };
    let bytes = text.as_bytes();
    let mut results = Vec::with_capacity(queries.len());
    for query in queries {
        let q = tree_sitter::Query::new(&lang, query)
            .with_context(|| format!("compile tree-sitter query: {query}"))?;
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut out = Vec::new();
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
        results.push(out);
    }
    Ok(results)
}

/// Walk `node.parent()` until we hit a Rust function-like declaration and
/// return its `name` field. Returns `None` at module scope. Exposed so the
/// Discoverer can share one implementation with the agent-facing tool.
pub fn enclosing_symbol(node: tree_sitter::Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = Some(node);
    while let Some(n) = cursor {
        if matches!(n.kind(), "function_item" | "function_signature_item") {
            let name = n.child_by_field_name("name")?;
            return Some(name.utf8_text(bytes).ok()?.to_string());
        }
        cursor = n.parent();
    }
    None
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

/// Parse `cargo bench` output, accepting:
/// - libtest bencher format (`test bench_name ... bench: 1,234 ns/iter (+/- 56)`)
/// - Criterion default text (`bench_name  time: [1.1 us 1.2 us 1.3 us]`)
/// - **divan** (`├─ bench_name  370.7 ns │ … │ 389.7 ns │ 573.9 ns │ … `).
///   Divan tables are box-drawing-character separated; each leaf row
///   has six columns: name, fastest, slowest, median, mean, samples,
///   iters. We use median as `ns_per_iter`. Group header rows (no
///   numeric columns) are skipped. Added because clap moved to divan
///   and our prior parser returned zero samples on its output —
///   blocked the end-to-end run on clap-class repos.
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

    samples.extend(parse_divan_table(stdout));

    BenchReport { samples }
}

/// Parse divan's box-drawing benchmark table. Returns one sample per
/// leaf row with `ns_per_iter` set to the row's MEDIAN column (most
/// representative against tail outliers).
///
/// Divan's column structure on each row is:
///     <prefix>  <name>  <fastest>  │  <slowest>  │  <median>  │  <mean>  │  <samples>  │  <iters>
///
/// Group rows (named ancestors with no values) are skipped because
/// their value columns are empty. We approximate group qualification
/// by remembering the most recent non-leaf "group" name seen at a
/// shallower indent, joining `group::leaf`.
fn parse_divan_table(stdout: &str) -> Vec<BenchSample> {
    let mut out = Vec::new();
    // Track ancestor groups by tree-depth (column where the name
    // starts). Each ancestor stays valid until a sibling/leaf at the
    // same or shallower indent appears.
    let mut group_stack: Vec<(usize, String)> = Vec::new();
    for line in stdout.lines() {
        // A divan row contains at least 5 of the box-drawing column
        // separators `│`. Anything less is regular text we ignore.
        if line.matches('│').count() < 5 {
            continue;
        }
        let cols: Vec<&str> = line.split('│').collect();
        // Divan rows have the shape:
        //   col[0] = "<prefix><name>     <fastest_value>"
        //   col[1] = " <slowest> "
        //   col[2] = " <median> "    ← we use this
        //   col[3] = " <mean> "
        //   col[4] = " <samples> "
        //   col[5] = " <iters> "
        // …so we need at least 6 bar-separated columns for a leaf row.
        if cols.len() < 6 {
            continue;
        }
        // Skip the table header row. Divan prints column titles
        // (`fastest │ slowest │ median │ …`) above data; the title
        // tokens are bar-separated like data, so a naive parser
        // treats the header as a group row and pollutes every nested
        // leaf with `fastest::` as an ancestor.
        let is_header = cols.iter().any(|c| {
            matches!(
                c.trim(),
                "slowest" | "median" | "mean" | "samples" | "iters"
            )
        });
        if is_header {
            continue;
        }
        // Split col[0] at the boundary between name and fastest value.
        // Use the LAST run of 2+ spaces as the separator — names can
        // contain single spaces but the column padding is always wider.
        let head = cols[0];
        let (indent, name_with_value) = strip_divan_tree_prefix(head);
        let name = head_name_only(&name_with_value);
        if name.is_empty() {
            continue;
        }
        let median_raw = cols.get(2).map(|s| s.trim()).unwrap_or("");
        // A leaf row has a non-empty median value column. A group
        // header row (e.g. `╰─ startup`) shows blank value columns.
        let Some(ns) = parse_value_with_unit(median_raw) else {
            // Pure group row — push onto stack at this indent and
            // pop any deeper-or-equal entries first.
            while group_stack
                .last()
                .map(|(d, _)| *d >= indent)
                .unwrap_or(false)
            {
                group_stack.pop();
            }
            group_stack.push((indent, name));
            continue;
        };
        // Pop ancestors that are NOT a strict prefix of this row.
        while group_stack
            .last()
            .map(|(d, _)| *d >= indent)
            .unwrap_or(false)
        {
            group_stack.pop();
        }
        let qualified = if group_stack.is_empty() {
            name.clone()
        } else {
            let parents: Vec<String> = group_stack.iter().map(|(_, n)| n.clone()).collect();
            format!("{}::{}", parents.join("::"), name)
        };
        out.push(BenchSample {
            name: qualified,
            ns_per_iter: ns,
            iters: 1,
        });
    }
    out
}

/// Extract just the leaf name from divan's combined "<name>   <fastest>"
/// first-column text. Splits at the LAST run of 2+ spaces — names may
/// contain a single space but column padding is always wider.
fn head_name_only(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Find the rightmost split point at 2+ spaces.
    let bytes = trimmed.as_bytes();
    let mut split_at: Option<usize> = None;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b' ' && bytes[i + 1] == b' ' {
            split_at = Some(i);
            // Skip over the whole run of spaces.
            while i < bytes.len() && bytes[i] == b' ' {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    match split_at {
        Some(idx) => trimmed[..idx].trim().to_string(),
        None => trimmed.to_string(),
    }
}

/// Strip box-drawing tree prefix characters and return `(indent_col,
/// name)`. The indent_col is the byte column where the name starts —
/// useful for nesting detection.
fn strip_divan_tree_prefix(s: &str) -> (usize, String) {
    let mut chars = s.char_indices().peekable();
    let mut last_prefix_end = 0;
    while let Some(&(_, ch)) = chars.peek() {
        match ch {
            ' ' | '├' | '╰' | '─' | '┬' | '│' | '┌' | '└' | '┼' | '┤' | '┴' | '╭' | '╮' | '╯' =>
            {
                let (i, _) = chars.next().unwrap();
                last_prefix_end = i + ch.len_utf8();
            }
            _ => break,
        }
    }
    let rest = &s[last_prefix_end..];
    let name = rest.trim().to_string();
    (last_prefix_end, name)
}

fn parse_value_with_unit(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Format: `<number><whitespace?><unit>` where unit ∈ {ns, µs, us, ms, s}.
    let (num_part, unit_part) = match s.split_once(|c: char| c.is_whitespace()) {
        Some((n, u)) => (n, u.trim()),
        None => {
            // No unit at all — bail.
            return None;
        }
    };
    let n: f64 = num_part.parse().ok()?;
    let mul = match unit_part {
        "ns" => 1.0,
        "µs" | "us" => 1_000.0,
        "ms" => 1_000_000.0,
        "s" => 1_000_000_000.0,
        _ => return None,
    };
    Some(n * mul)
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

    #[test]
    fn parses_divan_table_with_groups_and_leaves() {
        // Captured verbatim from `cargo bench --bench simple` on
        // /tmp/ods-dogfood/clap/clap_bench. The `startup` row is a
        // group header (no values) with three children. Test lines
        // are joined with explicit `\n` (not Rust's `\` continuation,
        // which would silently eat the leading-space indent on the
        // nested rows and turn this into a fake-passing test).
        let lines: &[&str] = &[
            "Timer precision: 28 ns",
            "simple          fastest       │ slowest       │ median        │ mean          │ samples │ iters",
            "├─ build        370.7 ns      │ 4.471 µs      │ 389.7 ns      │ 573.9 ns      │ 100     │ 100",
            "├─ render_help  7.001 µs      │ 52 µs         │ 7.074 µs      │ 7.911 µs      │ 100     │ 100",
            "╰─ startup                    │               │               │               │         │",
            "   ├─ flag      1.878 µs      │ 42.56 µs      │ 2.061 µs      │ 2.484 µs      │ 100     │ 100",
            "   ├─ opt       2.219 µs      │ 23.16 µs      │ 2.331 µs      │ 2.795 µs      │ 100     │ 100",
            "   ╰─ pos       2.156 µs      │ 5.115 µs      │ 2.276 µs      │ 2.3 µs        │ 100     │ 100",
        ];
        let out = lines.join("\n");
        let out = out.as_str();
        let r = parse_cargo_bench_output(out);
        let by_name: std::collections::HashMap<&str, f64> = r
            .samples
            .iter()
            .map(|s| (s.name.as_str(), s.ns_per_iter))
            .collect();
        // Five leaf rows (build, render_help, startup::flag, ::opt, ::pos);
        // the "startup" line is a group header → no entry.
        let dump = r
            .samples
            .iter()
            .map(|s| (s.name.clone(), s.ns_per_iter))
            .collect::<Vec<_>>();
        assert_eq!(r.samples.len(), 5, "expected 5 samples, got {dump:?}");
        assert!(by_name.contains_key("build"), "missing 'build' in {dump:?}");
        assert!((by_name["build"] - 389.7).abs() < 0.01);
        assert!((by_name["render_help"] - 7074.0).abs() < 0.1);
        let dump = r
            .samples
            .iter()
            .map(|s| (s.name.clone(), s.ns_per_iter))
            .collect::<Vec<_>>();
        assert!(
            by_name.contains_key("startup::flag"),
            "missing startup::flag in {dump:?}"
        );
        assert!((by_name["startup::flag"] - 2061.0).abs() < 0.1);
        assert!((by_name["startup::opt"] - 2331.0).abs() < 0.1);
        assert!((by_name["startup::pos"] - 2276.0).abs() < 0.1);
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

    #[tokio::test]
    async fn ast_query_attaches_enclosing_symbol_when_inside_fn() {
        let src = r#"
fn outer() {
    let v: Vec<u8> = Vec::new();
}
const TOP: &str = "hi";
"#;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("z.rs");
        std::fs::write(&p, src).unwrap();
        let a = RustAdapter::new();
        let hits = a
            .ast_query(
                &p,
                "(call_expression function: (scoped_identifier \
                 path: (identifier) @_ (#eq? @_ \"Vec\") \
                 name: (identifier) @m (#eq? @m \"new\"))) @call",
            )
            .await
            .unwrap();
        let inside_fn = hits
            .iter()
            .find(|h| h.enclosing_symbol.as_deref() == Some("outer"));
        assert!(
            inside_fn.is_some(),
            "expected a match with enclosing_symbol=outer; got {:?}",
            hits.iter()
                .map(|h| (h.start_line, h.enclosing_symbol.clone()))
                .collect::<Vec<_>>()
        );
    }

    /// The batch variant must produce identical results to running each
    /// query individually via `ast_query` — the parse-reuse
    /// optimisation must not quietly lose or reorder hits.
    #[tokio::test]
    async fn ast_query_batch_matches_individual_calls() {
        let src = r#"
fn foo() {
    let v: Vec<u8> = Vec::new();
    let s = format!("hi");
    let _ = (v, s);
}

fn bar() {
    for _ in 0..10 {
        let _ = "clone".to_string();
    }
}
"#;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("b.rs");
        std::fs::write(&p, src).unwrap();
        let a = RustAdapter::new();
        let queries = [
            "(call_expression function: (scoped_identifier path: (identifier) @p (#eq? @p \"Vec\") name: (identifier) @m (#eq? @m \"new\"))) @match",
            "(macro_invocation macro: (identifier) @m (#eq? @m \"format\")) @match",
            "(for_expression) @match",
        ];
        let mut individual: Vec<Vec<AstMatch>> = Vec::new();
        for q in &queries {
            individual.push(a.ast_query(&p, q).await.unwrap());
        }
        let batch = a.ast_query_batch(&p, &queries).await.unwrap();
        assert_eq!(batch.len(), queries.len());
        for (i, (b, ind)) in batch.iter().zip(individual.iter()).enumerate() {
            assert_eq!(
                b.len(),
                ind.len(),
                "pattern {i}: batch len {} != individual len {}",
                b.len(),
                ind.len()
            );
            for (bh, ih) in b.iter().zip(ind.iter()) {
                assert_eq!(bh.start_line, ih.start_line);
                assert_eq!(bh.end_line, ih.end_line);
                assert_eq!(bh.enclosing_symbol, ih.enclosing_symbol);
                assert_eq!(bh.text, ih.text);
            }
        }
        assert!(!batch[0].is_empty(), "expected Vec::new match");
        assert!(!batch[1].is_empty(), "expected format! match");
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
