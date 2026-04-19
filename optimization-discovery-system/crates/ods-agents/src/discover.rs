//! Lightweight candidate discovery for `ods scan`.
//!
//! Until tree-sitter and per-language profilers land, the discoverer
//! enumerates plausible hot primitives via:
//!
//! 1. **Bench-suite scan.** Walk `benches/`, `bench/`, `*_bench*` files and
//!    extract the `criterion` / `bencher` group names referenced from each
//!    file.
//! 2. **Naive-alt heuristic.** For each candidate symbol look for
//!    user-written alternatives in the source tree (`format!()` near
//!    `Path::join`, manual loops near `iter().sum()`, etc.) and rank them
//!    higher when found.
//!
//! The output is intentionally a ranked list of [`Candidate`]s the user can
//! feed straight into `ods run --target ...`.

use anyhow::Result;
use ods_recipes::{
    retrieval_score,
    schema::{PromotionState, Recipe, RecipeId},
    RecipeQuery, Store,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tree_sitter::{Language, Parser, Query, QueryCursor};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub language: String,
    pub module: String,
    pub symbol: String,
    pub source_file: PathBuf,
    pub source_line: u32,
    pub bench_files: Vec<PathBuf>,
    pub naive_alt_hint: Option<String>,
    /// Recipes in the corpus whose `trigger.ast_pattern` fired on this
    /// source file. Each one is a signal that the target may match a known
    /// optimization pattern.
    #[serde(default)]
    pub matched_recipes: Vec<RecipeId>,
    /// Anti-pattern recipes (promotion=AntiPattern) that fired on this
    /// file — marker signals, never auto-applied.
    #[serde(default)]
    pub anti_patterns: Vec<RecipeId>,
    /// Cheap call-site estimate: count of `<symbol>(` occurrences under
    /// `src/`. Rough but useful for ranking high-fanin symbols.
    #[serde(default)]
    pub fan_in: u32,
    #[serde(default)]
    pub has_bench: bool,
    pub score: f64,
}

#[derive(Debug, Clone)]
pub struct Discoverer {
    pub max_files: usize,
    pub max_size_bytes: u64,
}

impl Default for Discoverer {
    fn default() -> Self {
        Self {
            max_files: 5_000,
            max_size_bytes: 256 * 1024,
        }
    }
}

impl Discoverer {
    /// Scan `repo` and return ranked candidates. Language-specific
    /// heuristics are applied based on file extensions.
    pub fn scan(&self, repo: &Path) -> Result<Vec<Candidate>> {
        let mut bench_files = Vec::new();
        let mut source_files = Vec::new();
        let mut count = 0usize;
        for entry in WalkDir::new(repo)
            .into_iter()
            .filter_entry(|e| !is_ignored(e.path()))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            count += 1;
            if count > self.max_files {
                break;
            }
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if size > self.max_size_bytes {
                continue;
            }
            if is_bench_file(path) {
                bench_files.push(path.to_path_buf());
            }
            if is_source_file(path) {
                source_files.push(path.to_path_buf());
            }
        }

        let mut out = Vec::new();
        for bf in &bench_files {
            let Ok(text) = std::fs::read_to_string(bf) else {
                continue;
            };
            for cand in extract_bench_targets(bf, &text) {
                out.push(cand);
            }
        }
        // Score boost: candidate symbol appears in non-bench source too.
        let symbols: Vec<String> = out.iter().map(|c| c.symbol.clone()).collect();
        let alts = find_naive_alts(&source_files, &symbols);
        for c in &mut out {
            if let Some(hint) = alts.get(&c.symbol) {
                c.naive_alt_hint = Some(hint.clone());
                c.score += 0.5;
            }
        }
        out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        out.truncate(50);
        Ok(out)
    }
}

fn is_ignored(p: &Path) -> bool {
    p.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some(".git")
                | Some("target")
                | Some("node_modules")
                | Some(".venv")
                | Some("venv")
                | Some("__pycache__")
                | Some("vendor")
                | Some("build")
                | Some("dist")
        )
    })
}

fn is_bench_file(p: &Path) -> bool {
    let path_s = p.to_string_lossy();
    path_s.contains("/benches/")
        || path_s.contains("/bench/")
        || path_s.contains("/benchmark/")
        || p.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.contains("bench"))
            .unwrap_or(false)
}

fn is_source_file(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|s| s.to_str()),
        Some("rs")
            | Some("go")
            | Some("py")
            | Some("rb")
            | Some("c")
            | Some("cc")
            | Some("cpp")
            | Some("h")
            | Some("hpp")
            | Some("js")
            | Some("ts")
            | Some("java")
    )
}

fn detect_language(p: &Path) -> &'static str {
    match p.extension().and_then(|s| s.to_str()) {
        Some("rs") => "rust",
        Some("go") => "go",
        Some("py") => "python",
        Some("rb") => "ruby",
        Some("c") | Some("h") => "c",
        Some("cc") | Some("cpp") | Some("hpp") => "cpp",
        Some("js") => "javascript",
        Some("ts") => "typescript",
        Some("java") => "java",
        _ => "unknown",
    }
}

/// Given a bench-file's text, extract candidates by pulling the symbol out
/// of common bench harness call shapes:
///   * Criterion `c.bench_function("name", ...)` / `bench_with_input("name", ...)`
///   * libtest `#[bench] fn bench_name(b: &mut Bencher)`
///   * Go `func BenchmarkName(b *testing.B)`
fn extract_bench_targets(file: &Path, text: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    let language = detect_language(file).to_string();
    let mut push_cand = |lang: String, module: String, symbol: String, line: usize, score: f64| {
        out.push(Candidate {
            language: lang,
            module,
            symbol,
            source_file: file.to_path_buf(),
            source_line: (line + 1) as u32,
            bench_files: vec![file.to_path_buf()],
            naive_alt_hint: None,
            matched_recipes: vec![],
            anti_patterns: vec![],
            fan_in: 0,
            has_bench: true,
            score,
        });
    };
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        // Criterion style
        if let Some(start) = l.find("bench_function(\"") {
            let rest = &l[start + "bench_function(\"".len()..];
            if let Some(end) = rest.find('"') {
                push_cand(
                    language.clone(),
                    bench_module(file),
                    rest[..end].to_string(),
                    i,
                    1.0,
                );
            }
        }
        // libtest #[bench] fn name(...)
        if l.starts_with("fn bench_") || l.contains(" bench_") {
            if let Some(rest) = l.split("fn ").nth(1) {
                if let Some(end) = rest.find('(') {
                    let name = rest[..end].trim().to_string();
                    if !name.is_empty() {
                        push_cand(language.clone(), bench_module(file), name, i, 0.8);
                    }
                }
            }
        }
        // Go BenchmarkXxx
        if l.starts_with("func Benchmark") {
            if let Some(after) = l.strip_prefix("func ") {
                if let Some(end) = after.find('(') {
                    push_cand(
                        "go".into(),
                        bench_module(file),
                        after[..end].trim().to_string(),
                        i,
                        0.9,
                    );
                }
            }
        }
    }
    out
}

impl Discoverer {
    /// Autonomous-discovery pass: scan the repo + consult the recipe
    /// corpus and an optional anti-pattern library. Returns candidates
    /// ranked by `promotion_weight * (1 - negative_penalty) + anti_pattern_hits
    /// + log(fan_in + 1) + has_bench`.
    pub fn scan_with_recipes(
        &self,
        repo: &Path,
        store: &Store,
        top_k: usize,
    ) -> Result<Vec<Candidate>> {
        // Start from the bench-based candidates so existing harnesses still
        // surface.
        let mut candidates = self.scan(repo)?;

        // Load recipes once. Two buckets:
        //   * applicable recipes (Hypothesized..Corpus)   -- influence ranking AND can be applied
        //   * anti-patterns (promotion=AntiPattern)       -- only surface as targets
        let applicable = store
            .search(&RecipeQuery {
                language: None,
                category: None,
                min_promotion: Some(PromotionState::Hypothesized),
                limit: Some(10_000),
            })
            .unwrap_or_default();
        let anti = store
            .search(&RecipeQuery {
                language: None,
                category: None,
                min_promotion: Some(PromotionState::AntiPattern),
                limit: Some(10_000),
            })
            .unwrap_or_default();

        let compiled_applicable = compile_triggers(&applicable);
        let compiled_anti = compile_triggers(&anti);

        // Walk source files; for each file, parse once with the matching
        // tree-sitter grammar and run every recipe trigger whose language
        // matches. Multi-language corpora share one discover pass.
        for entry in WalkDir::new(repo)
            .into_iter()
            .filter_entry(|e| !is_ignored(e.path()))
        {
            let Ok(e) = entry else { continue };
            let p = e.path();
            if !p.is_file() || !is_source_file(p) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(p) else {
                continue;
            };

            let lang_name = detect_language(p);
            let Some(parsed) = parse_with_grammar(lang_name, &text) else {
                continue;
            };

            // Collect every pattern match with its enclosing-symbol name
            // (the nearest fn / def / func ancestor of the matched node).
            // Matches outside any function are attributed to the file stem
            // so module-level patterns (e.g. `static X: Lazy`) still surface.
            let module = module_from_path(repo, p);
            let file_stem_sym = module.split("::").last().unwrap_or("").to_string();
            let mut per_symbol: std::collections::HashMap<String, SymbolHits<'_>> =
                std::collections::HashMap::new();
            collect_matches(
                &parsed,
                text.as_bytes(),
                lang_name,
                &compiled_applicable,
                lang_name,
                &file_stem_sym,
                &mut per_symbol,
                HitKind::Applicable,
            );
            collect_matches(
                &parsed,
                text.as_bytes(),
                lang_name,
                &compiled_anti,
                lang_name,
                &file_stem_sym,
                &mut per_symbol,
                HitKind::AntiPattern,
            );
            if per_symbol.is_empty() {
                continue;
            }

            for (symbol, hits) in per_symbol {
                let fan_in = estimate_fan_in(repo, &symbol);
                let recipe_score: f64 = hits
                    .applicable
                    .iter()
                    .map(|(r, n)| retrieval_score(r, 5) * (*n as f64).min(5.0))
                    .sum();
                let anti_score: f64 = hits
                    .anti
                    .iter()
                    .map(|(_, n)| (*n as f64).min(5.0) * 0.5)
                    .sum();
                let fan_in_score = ((fan_in + 1) as f64).ln() * 0.3;
                candidates.push(Candidate {
                    language: lang_name.to_string(),
                    module: module.clone(),
                    symbol,
                    source_file: p.to_path_buf(),
                    source_line: hits.first_line,
                    bench_files: vec![],
                    naive_alt_hint: None,
                    matched_recipes: hits.applicable.iter().map(|(r, _)| r.id.clone()).collect(),
                    anti_patterns: hits.anti.iter().map(|(r, _)| r.id.clone()).collect(),
                    fan_in,
                    has_bench: false,
                    score: recipe_score + anti_score + fan_in_score,
                });
            }
        }

        // Re-rank and trim.
        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        candidates.truncate(top_k);
        Ok(candidates)
    }
}

struct CompiledTrigger<'a> {
    recipe: &'a Recipe,
    language: &'static str,
    query: Query,
}

/// Compile each recipe's `trigger.ast_pattern` into a tree-sitter `Query`
/// bound to the recipe's language grammar. Recipes whose language isn't one
/// of the three supported grammars, whose pattern is empty, or whose pattern
/// fails to compile are dropped with a warning.
fn compile_triggers(recipes: &[Recipe]) -> Vec<CompiledTrigger<'_>> {
    let mut out = Vec::new();
    for r in recipes {
        if r.trigger.ast_pattern.trim().is_empty() {
            continue;
        }
        let Some((name, lang)) = language_for_recipe(&r.language) else {
            tracing::warn!(
                recipe = %r.id.0,
                language = %r.language,
                "no tree-sitter grammar for recipe language; skipping trigger"
            );
            continue;
        };
        match Query::new(&lang, &r.trigger.ast_pattern) {
            Ok(q) => out.push(CompiledTrigger {
                recipe: r,
                language: name,
                query: q,
            }),
            Err(e) => tracing::warn!(
                recipe = %r.id.0,
                err = %e,
                pattern = %r.trigger.ast_pattern,
                "failed to compile recipe trigger as tree-sitter query",
            ),
        }
    }
    out
}

fn language_for_recipe(recipe_lang: &str) -> Option<(&'static str, Language)> {
    match recipe_lang {
        "rust" => Some(("rust", ods_lang_rust::tree_sitter_language())),
        "python" => Some(("python", ods_lang_python::tree_sitter_language())),
        "go" => Some(("go", ods_lang_go::tree_sitter_language())),
        _ => None,
    }
}

/// Parse `text` with the grammar associated with `lang_name`. Returns
/// `None` for unsupported languages or parser failures so the caller can
/// skip the file without surfacing an error.
fn parse_with_grammar(lang_name: &str, text: &str) -> Option<tree_sitter::Tree> {
    let (_, lang) = language_for_recipe(lang_name)?;
    let mut parser = Parser::new();
    parser.set_language(&lang).ok()?;
    parser.parse(text, None)
}

#[derive(Debug, Clone, Copy)]
enum HitKind {
    Applicable,
    AntiPattern,
}

/// Per-symbol aggregation: how many times each trigger fired under this
/// containing function, plus the first matched line (used as the
/// candidate's `source_line`).
#[derive(Debug, Default)]
struct SymbolHits<'a> {
    applicable: Vec<(&'a Recipe, u32)>,
    anti: Vec<(&'a Recipe, u32)>,
    first_line: u32,
}

/// Walk every pattern match for every applicable trigger and group the
/// results by their enclosing-symbol name. Each trigger contributes one
/// `(recipe, count)` entry per symbol it fires under, so a recipe that
/// matches twice inside `fn foo` shows up as `(recipe, 2)` once.
fn collect_matches<'a>(
    tree: &tree_sitter::Tree,
    bytes: &[u8],
    lang_name: &str,
    triggers: &'a [CompiledTrigger<'a>],
    _grammar_key: &str,
    file_stem_sym: &str,
    out: &mut std::collections::HashMap<String, SymbolHits<'a>>,
    kind: HitKind,
) {
    for trigger in triggers {
        if trigger.language != lang_name {
            continue;
        }
        let mut cursor = QueryCursor::new();
        let mut per_sym: std::collections::HashMap<String, (u32, u32)> =
            std::collections::HashMap::new();
        for m in cursor.matches(&trigger.query, tree.root_node(), bytes) {
            let Some(cap) = m.captures.first() else {
                continue;
            };
            let line = cap.node.start_position().row as u32 + 1;
            let sym = enclosing_symbol(cap.node, bytes, lang_name)
                .unwrap_or_else(|| file_stem_sym.to_string());
            let e = per_sym.entry(sym).or_insert((0, line));
            e.0 += 1;
            if line < e.1 {
                e.1 = line;
            }
        }
        for (sym, (count, line)) in per_sym {
            let bucket = out.entry(sym).or_default();
            match kind {
                HitKind::Applicable => bucket.applicable.push((trigger.recipe, count)),
                HitKind::AntiPattern => bucket.anti.push((trigger.recipe, count)),
            }
            if bucket.first_line == 0 || line < bucket.first_line {
                bucket.first_line = line;
            }
        }
    }
}

/// Dispatch to the matching adapter's `enclosing_symbol` helper so the
/// Discoverer and the agent-facing `ast_query` tool share one source of
/// truth per language. Returns `None` at module scope.
fn enclosing_symbol(node: tree_sitter::Node, bytes: &[u8], lang: &str) -> Option<String> {
    match lang {
        "rust" => ods_lang_rust::enclosing_symbol(node, bytes),
        "python" => ods_lang_python::enclosing_symbol(node, bytes),
        "go" => ods_lang_go::enclosing_symbol(node, bytes),
        _ => None,
    }
}

fn module_from_path(repo: &Path, file: &Path) -> String {
    let Ok(rel) = file.strip_prefix(repo) else {
        return file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("mod")
            .to_string();
    };
    let stem = rel.with_extension("");
    stem.components()
        .filter_map(|c| c.as_os_str().to_str())
        .filter(|s| *s != "src" && *s != "lib")
        .collect::<Vec<_>>()
        .join("::")
}

fn estimate_fan_in(repo: &Path, symbol: &str) -> u32 {
    if symbol.is_empty() {
        return 0;
    }
    let pat = format!(r"\b{}\s*\(", regex::escape(symbol));
    let Ok(re) = Regex::new(&pat) else {
        return 0;
    };
    let mut count = 0u32;
    for entry in WalkDir::new(repo)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.path()))
    {
        let Ok(e) = entry else { continue };
        let p = e.path();
        if !p.is_file() || !is_source_file(p) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(p) else {
            continue;
        };
        count += text.lines().filter(|l| re.is_match(l)).count() as u32;
        if count > 1000 {
            break; // cap to keep the scan cheap
        }
    }
    count
}

fn bench_module(file: &Path) -> String {
    file.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("bench")
        .to_string()
}

fn find_naive_alts(
    sources: &[PathBuf],
    symbols: &[String],
) -> std::collections::HashMap<String, String> {
    let mut hints = std::collections::HashMap::new();
    if symbols.is_empty() {
        return hints;
    }
    for f in sources {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for sym in symbols {
            if hints.contains_key(sym) {
                continue;
            }
            // A simple heuristic: the symbol is referenced in non-bench code.
            // The presence alone is a hint; we capture the first matching
            // line's context for the report.
            if let Some(pos) = text.find(sym) {
                let snip: String = text[pos..]
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(120)
                    .collect();
                hints.insert(
                    sym.clone(),
                    format!("referenced in {}: {snip}", f.display()),
                );
            }
        }
    }
    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_criterion_targets() {
        let dir = tempfile::tempdir().unwrap();
        let bench_dir = dir.path().join("benches");
        std::fs::create_dir_all(&bench_dir).unwrap();
        std::fs::write(
            bench_dir.join("foo_bench.rs"),
            r#"
fn bench_join(c: &mut Criterion) {
    c.bench_function("path_join_two", |b| { b.iter(|| {}) });
}
"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        let d = Discoverer::default();
        let cands = d.scan(dir.path()).unwrap();
        assert!(cands.iter().any(|c| c.symbol == "path_join_two"));
    }

    #[test]
    fn discovers_go_benchmarks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("go.mod"), "module x\n").unwrap();
        std::fs::write(
            dir.path().join("foo_bench_test.go"),
            "package x\nfunc BenchmarkJoin(b *testing.B) {}\n",
        )
        .unwrap();
        let d = Discoverer::default();
        let cands = d.scan(dir.path()).unwrap();
        assert!(cands.iter().any(|c| c.symbol == "BenchmarkJoin"));
    }

    /// Discoverer must attribute recipe matches to the *enclosing function*
    /// they live in, not the file stem. This lets `ods discover | ods run`
    /// target real symbols like `rust::mod::fn_name` instead of `rust::file`.
    #[test]
    fn discover_attributes_matches_to_enclosing_function() {
        use ods_recipes::schema::{
            PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe,
        };
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::create_dir_all(repo.join("src")).unwrap();
        // Two functions, each with one Vec::new() call. The discoverer
        // should produce two candidates keyed on `hot_a` and `hot_b`.
        std::fs::write(
            repo.join("src/lib.rs"),
            r#"
pub fn hot_a() {
    let v: Vec<u8> = Vec::new();
    let _ = v;
}

pub fn cold_b() {
    let _ = 1;
}

pub fn hot_c() {
    let v: Vec<u8> = Vec::new();
    let _ = v;
}
"#,
        )
        .unwrap();
        let store = Store::in_memory().unwrap();
        store
            .upsert(&Recipe {
                id: RecipeId("rust-smallvec".into()),
                name: "prefer SmallVec for hot small collections".into(),
                category: ods_core::OptimizationCategory::AllocReduction,
                language: "rust".into(),
                promotion: PromotionState::Seed,
                trigger: Trigger {
                    ast_pattern: "(call_expression function: (scoped_identifier \
                                 path: (identifier) @p (#eq? @p \"Vec\") \
                                 name: (identifier) @m (#eq? @m \"new\"))) @match"
                        .into(),
                    profile_signature: vec![],
                    naive_alt_ratio_min: None,
                },
                transformation: Transformation { steps: vec![] },
                verification: VerificationRecipe {
                    test_selectors: vec![],
                    property_seeds: vec![],
                    fuzz_minutes: 0,
                    semver_check: false,
                },
                benchmark_template: "".into(),
                success_history: vec![],
                negative_history: vec![],
                generalized_from: None,
                generalized_as: None,
                source_patch_ref: None,
                embedding: None,
            })
            .unwrap();

        let d = Discoverer::default();
        let cands = d.scan_with_recipes(repo, &store, 10).unwrap();
        let symbols: std::collections::HashSet<String> =
            cands.iter().map(|c| c.symbol.clone()).collect();
        assert!(
            symbols.contains("hot_a"),
            "expected a candidate for hot_a, got {symbols:?}"
        );
        assert!(
            symbols.contains("hot_c"),
            "expected a candidate for hot_c, got {symbols:?}"
        );
        assert!(
            !symbols.contains("cold_b"),
            "cold_b has no Vec::new, should not be a candidate; got {symbols:?}"
        );
        assert!(
            !symbols.contains("lib"),
            "file-stem fallback should NOT be used when enclosing fn exists; got {symbols:?}"
        );
        // Each candidate should have source_line pointing at the Vec::new line,
        // not the fallback `1`.
        for c in &cands {
            if c.symbol == "hot_a" || c.symbol == "hot_c" {
                assert!(
                    c.source_line > 1,
                    "expected real line for {}, got {}",
                    c.symbol,
                    c.source_line
                );
            }
        }
    }

    /// Every shipped recipe YAML must have an `ast_pattern` that compiles
    /// cleanly against the tree-sitter grammar for its `language` field.
    /// If this test fails, either the pattern is malformed or a node name
    /// drifted with a grammar upgrade — both are real bugs, not flakes.
    #[test]
    fn every_shipped_recipe_compiles_as_tree_sitter_query() {
        let roots = [
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("recipes/seed"),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("recipes/antipatterns"),
        ];
        let mut checked = 0usize;
        let mut failures: Vec<String> = Vec::new();
        for root in &roots {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let recipe: ods_recipes::schema::Recipe = serde_yaml::from_str(&text)
                    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
                if recipe.trigger.ast_pattern.trim().is_empty() {
                    continue;
                }
                let Some((_, lang)) = language_for_recipe(&recipe.language) else {
                    // No grammar for this language yet — skip without failing.
                    continue;
                };
                if let Err(e) = Query::new(&lang, &recipe.trigger.ast_pattern) {
                    failures.push(format!(
                        "{}: {e}\n---\n{}",
                        path.display(),
                        recipe.trigger.ast_pattern
                    ));
                }
                checked += 1;
            }
        }
        assert!(
            failures.is_empty(),
            "{} recipes failed to compile:\n{}",
            failures.len(),
            failures.join("\n\n")
        );
        assert!(
            checked > 40,
            "expected 40+ recipes with patterns, saw {checked}"
        );
    }
}
