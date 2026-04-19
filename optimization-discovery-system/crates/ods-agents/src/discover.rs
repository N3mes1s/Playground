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

        // Recipe-id -> Recipe lookup for hydrating cached file buckets
        // back into ref-holding `SymbolHits<'_>` without re-parsing.
        let mut recipe_by_id: std::collections::HashMap<&str, &Recipe> =
            std::collections::HashMap::new();
        for r in applicable.iter().chain(anti.iter()) {
            recipe_by_id.insert(r.id.0.as_str(), r);
        }

        // Corpus hash: stable over recipe id+pattern. If this changes,
        // the cache is stale and we rebuild from scratch.
        let corpus_hash = corpus_hash(&applicable, &anti);
        let cache_path = repo.join(".ods").join("discover-cache.json");
        let mut cache = DiscoverCache::load(&cache_path, &corpus_hash);
        let mut next_cache = DiscoverCache::new(corpus_hash.clone());

        // Two-pass discover so we can apply a precision penalty:
        //
        // Pass 1 walks every source file, collects the per-symbol hits
        // locally, and maintains a distinct-file-count per recipe id.
        // Dogfood against 12 OSS repos (docs/dogfood-12-repos.md) showed
        // that when a recipe's trigger is too broad (matches >5% of
        // files), the recipe floods the top of the ranked list and
        // drowns out the genuine signals. Tracking file-count lets us
        // assign each recipe a `precision_weight = min(1, threshold /
        // match_rate)` that gets multiplied into its score contribution.
        //
        // Pass 2 emits candidates with the weighted scores. We intentionally
        // still surface the hit so the user sees which broad recipe
        // matched; we just don't let it win the ranking on noise alone.
        const BROAD_MATCH_THRESHOLD: f64 = 0.05; // 5% of source files
        let mut file_buckets: Vec<FileBucket<'_>> = Vec::new();
        let mut recipe_file_count: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        let mut total_source_files: u32 = 0;

        for entry in WalkDir::new(repo)
            .into_iter()
            .filter_entry(|e| !is_ignored(e.path()))
        {
            let Ok(e) = entry else { continue };
            let p = e.path();
            if !p.is_file() || !is_source_file(p) {
                continue;
            }
            total_source_files += 1;

            // Cache key: (mtime_secs, size). If the file hasn't changed
            // since the last discover pass AND the recipe corpus is
            // unchanged, skip the parse and hydrate from cache.
            let (mtime_secs, size_bytes) = match file_stamp(p) {
                Some(s) => s,
                None => continue,
            };
            let key = p.to_string_lossy().to_string();
            if let Some(cached) = cache.take(&key, mtime_secs, size_bytes) {
                match hydrate_cached_bucket(&cached, &recipe_by_id) {
                    Some(Some(mut bucket)) => {
                        // `hydrate_cached_bucket` doesn't know the path;
                        // set it here so downstream candidate emission
                        // reports the right source_file.
                        bucket.path = p.to_path_buf();
                        next_cache.insert(
                            key,
                            CachedFileEntry {
                                mtime_secs,
                                size_bytes,
                                module: bucket.module.clone(),
                                lang: bucket.lang_name.to_string(),
                                per_symbol: symbol_hits_to_cached(&bucket.per_symbol),
                            },
                        );
                        account_and_push(bucket, &mut recipe_file_count, &mut file_buckets);
                        continue;
                    }
                    Some(None) => {
                        // Cached "zero-hit" file. Persist the same zero
                        // entry to avoid re-parsing next time.
                        next_cache.insert(
                            key,
                            CachedFileEntry {
                                mtime_secs,
                                size_bytes,
                                module: String::new(),
                                lang: String::new(),
                                per_symbol: std::collections::HashMap::new(),
                            },
                        );
                        continue;
                    }
                    None => {
                        // Cached entry references a recipe the user
                        // removed. Fall through to the cache-miss path.
                    }
                }
            }

            // Cache miss: parse + match + record for next time.
            if let Some(bucket) = parse_and_match(repo, p, &compiled_applicable, &compiled_anti) {
                next_cache.insert(
                    key,
                    CachedFileEntry {
                        mtime_secs,
                        size_bytes,
                        module: bucket.module.clone(),
                        lang: bucket.lang_name.to_string(),
                        per_symbol: symbol_hits_to_cached(&bucket.per_symbol),
                    },
                );
                account_and_push(bucket, &mut recipe_file_count, &mut file_buckets);
            } else {
                // File had no hits; cache an empty entry so we still
                // skip the parse next time.
                next_cache.insert(
                    key,
                    CachedFileEntry {
                        mtime_secs,
                        size_bytes,
                        module: String::new(),
                        lang: String::new(),
                        per_symbol: std::collections::HashMap::new(),
                    },
                );
            }
        }

        // Persist. Errors are non-fatal — the product works without
        // the cache, it's just slower next time.
        if let Err(e) = next_cache.save(&cache_path) {
            tracing::debug!(path = %cache_path.display(), err = %e, "failed to save discover cache");
        }

        // Per-recipe precision weights. A recipe that fired in 5% or
        // fewer source files keeps weight 1.0; anything above gets
        // linearly down-weighted so a recipe matching 50% of files
        // contributes 1/10th of its raw score.
        let precision_weights: std::collections::HashMap<String, f64> = if total_source_files == 0 {
            std::collections::HashMap::new()
        } else {
            recipe_file_count
                .iter()
                .map(|(id, cnt)| {
                    let rate = *cnt as f64 / total_source_files as f64;
                    let w = if rate > BROAD_MATCH_THRESHOLD {
                        (BROAD_MATCH_THRESHOLD / rate).max(0.01)
                    } else {
                        1.0
                    };
                    (id.clone(), w)
                })
                .collect()
        };

        // Pass 2: emit candidates with precision-weighted scores.
        for bucket in file_buckets {
            let FileBucket {
                path: p,
                module,
                lang_name,
                per_symbol,
            } = bucket;
            for (symbol, hits) in per_symbol {
                let fan_in = estimate_fan_in(&repo, &symbol);
                let recipe_score: f64 = hits
                    .applicable
                    .iter()
                    .map(|(r, n)| {
                        let pw = precision_weights.get(&r.id.0).copied().unwrap_or(1.0);
                        retrieval_score(r, 5) * (*n as f64).min(5.0) * pw
                    })
                    .sum();
                let anti_score: f64 = hits
                    .anti
                    .iter()
                    .map(|(r, n)| {
                        let pw = precision_weights.get(&r.id.0).copied().unwrap_or(1.0);
                        (*n as f64).min(5.0) * 0.5 * pw
                    })
                    .sum();
                let fan_in_score = ((fan_in + 1) as f64).ln() * 0.3;
                candidates.push(Candidate {
                    language: lang_name.to_string(),
                    module: module.clone(),
                    symbol,
                    source_file: p.clone(),
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

/// One source file's accumulated hits, buffered between pass 1 (the
/// file walk) and pass 2 (candidate emission with precision weights).
/// The `'a` lifetime borrows into the `applicable` / `anti` recipe
/// slices owned by `scan_with_recipes`.
struct FileBucket<'a> {
    path: PathBuf,
    module: String,
    lang_name: &'static str,
    per_symbol: std::collections::HashMap<String, SymbolHits<'a>>,
}

// ---------------------------------------------------------------------
// Discover cache (incremental scanning).
//
// Rationale: the dogfood at docs/dogfood-12-repos.md showed full-tree
// scans timing out on fastapi / prometheus / rails because we re-parse
// every source file every run. In steady-state dev loops only a handful
// of files change between runs. We persist per-file match results at
// `{repo}/.ods/discover-cache.json`, keyed on `(path, mtime, size)`,
// and invalidate the whole cache on recipe-corpus changes via a hash.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscoverCache {
    corpus_hash: String,
    files: std::collections::HashMap<String, CachedFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedFileEntry {
    mtime_secs: u64,
    size_bytes: u64,
    module: String,
    lang: String,
    per_symbol: std::collections::HashMap<String, CachedSymbolHits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSymbolHits {
    applicable: Vec<(String, u32)>,
    anti: Vec<(String, u32)>,
    first_line: u32,
}

impl DiscoverCache {
    fn new(corpus_hash: String) -> Self {
        Self {
            corpus_hash,
            files: std::collections::HashMap::new(),
        }
    }

    fn load(path: &Path, current_corpus_hash: &str) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return Self::new(current_corpus_hash.to_string()),
        };
        let parsed: DiscoverCache = match serde_json::from_str(&text) {
            Ok(p) => p,
            Err(_) => return Self::new(current_corpus_hash.to_string()),
        };
        if parsed.corpus_hash != current_corpus_hash {
            // Corpus changed — everything cached is stale.
            return Self::new(current_corpus_hash.to_string());
        }
        parsed
    }

    /// Consume (remove + return) a matching cache entry. Returns `None`
    /// if the entry is missing or its (mtime, size) don't match — in
    /// both cases the caller must re-scan.
    fn take(
        &mut self,
        path_key: &str,
        mtime_secs: u64,
        size_bytes: u64,
    ) -> Option<CachedFileEntry> {
        let entry = self.files.remove(path_key)?;
        if entry.mtime_secs == mtime_secs && entry.size_bytes == size_bytes {
            Some(entry)
        } else {
            // Stat changed — reject the entry so the caller re-parses.
            None
        }
    }

    fn insert(&mut self, path_key: String, entry: CachedFileEntry) {
        self.files.insert(path_key, entry);
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }
}

/// Stable hash over the recipe corpus — id + pattern. Order-insensitive.
fn corpus_hash(applicable: &[Recipe], anti: &[Recipe]) -> String {
    let mut entries: Vec<String> = applicable
        .iter()
        .chain(anti.iter())
        .map(|r| format!("{}:{}", r.id.0, r.trigger.ast_pattern))
        .collect();
    entries.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    for e in &entries {
        e.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

fn file_stamp(p: &Path) -> Option<(u64, u64)> {
    let md = std::fs::metadata(p).ok()?;
    let size = md.len();
    let mtime = md
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((mtime, size))
}

fn symbol_hits_to_cached(
    per_symbol: &std::collections::HashMap<String, SymbolHits<'_>>,
) -> std::collections::HashMap<String, CachedSymbolHits> {
    per_symbol
        .iter()
        .map(|(sym, hits)| {
            (
                sym.clone(),
                CachedSymbolHits {
                    applicable: hits
                        .applicable
                        .iter()
                        .map(|(r, n)| (r.id.0.clone(), *n))
                        .collect(),
                    anti: hits
                        .anti
                        .iter()
                        .map(|(r, n)| (r.id.0.clone(), *n))
                        .collect(),
                    first_line: hits.first_line,
                },
            )
        })
        .collect()
}

/// Reconstruct a live `FileBucket<'a>` from a cached entry by looking
/// every recipe id back up in the current corpus. Returns `None` if any
/// referenced recipe id is no longer present (i.e. the user removed a
/// recipe between runs) — the caller re-parses in that case.
fn hydrate_cached_bucket<'a>(
    cached: &CachedFileEntry,
    recipe_by_id: &std::collections::HashMap<&str, &'a Recipe>,
) -> Option<Option<FileBucket<'a>>> {
    if cached.per_symbol.is_empty() {
        // Zero-hit cached file — no bucket to push but also no reason
        // to re-parse.
        return Some(None);
    }
    // Map static strings so lang_name stays `&'static str`.
    let lang_name: &'static str = match cached.lang.as_str() {
        "rust" => "rust",
        "python" => "python",
        "go" => "go",
        "ruby" => "ruby",
        _ => return None,
    };
    let mut per_symbol: std::collections::HashMap<String, SymbolHits<'a>> =
        std::collections::HashMap::new();
    for (sym, hits) in &cached.per_symbol {
        let mut applicable = Vec::with_capacity(hits.applicable.len());
        for (id, n) in &hits.applicable {
            let r = recipe_by_id.get(id.as_str())?;
            applicable.push((*r, *n));
        }
        let mut anti = Vec::with_capacity(hits.anti.len());
        for (id, n) in &hits.anti {
            let r = recipe_by_id.get(id.as_str())?;
            anti.push((*r, *n));
        }
        per_symbol.insert(
            sym.clone(),
            SymbolHits {
                applicable,
                anti,
                first_line: hits.first_line,
            },
        );
    }
    Some(Some(FileBucket {
        path: PathBuf::new(), // set by caller
        module: cached.module.clone(),
        lang_name,
        per_symbol,
    }))
}

/// Parse + match the file and produce a `FileBucket`. Returns `None`
/// for unreadable, unparseable, or unsupported-language files, and for
/// files where no recipe matched.
fn parse_and_match<'a>(
    repo: &Path,
    p: &Path,
    compiled_applicable: &'a [CompiledTrigger<'a>],
    compiled_anti: &'a [CompiledTrigger<'a>],
) -> Option<FileBucket<'a>> {
    let text = std::fs::read_to_string(p).ok()?;
    let lang_name = detect_language(p);
    let parsed = parse_with_grammar(lang_name, &text)?;
    let module = module_from_path(repo, p);
    let file_stem_sym = module.split("::").last().unwrap_or("").to_string();
    let mut per_symbol: std::collections::HashMap<String, SymbolHits<'a>> =
        std::collections::HashMap::new();
    collect_matches(
        &parsed,
        text.as_bytes(),
        lang_name,
        compiled_applicable,
        lang_name,
        &file_stem_sym,
        &mut per_symbol,
        HitKind::Applicable,
    );
    collect_matches(
        &parsed,
        text.as_bytes(),
        lang_name,
        compiled_anti,
        lang_name,
        &file_stem_sym,
        &mut per_symbol,
        HitKind::AntiPattern,
    );
    if per_symbol.is_empty() {
        return None;
    }
    Some(FileBucket {
        path: p.to_path_buf(),
        module,
        lang_name,
        per_symbol,
    })
}

/// Count distinct files each recipe matched in (any symbol under this
/// file counts once) and push the bucket onto the per-pass list. Factored
/// out so the cache-hit and cache-miss paths share it.
fn account_and_push<'a>(
    bucket: FileBucket<'a>,
    recipe_file_count: &mut std::collections::HashMap<String, u32>,
    file_buckets: &mut Vec<FileBucket<'a>>,
) {
    let mut fired_here: std::collections::HashSet<String> = std::collections::HashSet::new();
    for hits in bucket.per_symbol.values() {
        for (r, _) in &hits.applicable {
            fired_here.insert(r.id.0.clone());
        }
        for (r, _) in &hits.anti {
            fired_here.insert(r.id.0.clone());
        }
    }
    for id in fired_here {
        *recipe_file_count.entry(id).or_insert(0) += 1;
    }
    file_buckets.push(bucket);
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
        "ruby" => Some(("ruby", ods_lang_ruby::tree_sitter_language())),
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
        "ruby" => ods_lang_ruby::enclosing_symbol(node, bytes),
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

    /// The discover cache must (1) persist hits per file between runs,
    /// (2) invalidate on mtime+size change, and (3) invalidate the
    /// whole cache when the recipe corpus hash changes. This test
    /// exercises all three via two sequential scans + a corpus swap.
    #[test]
    fn discover_cache_honours_mtime_and_corpus_hash() {
        use ods_recipes::schema::{
            PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe,
        };

        fn make_recipe(id: &str, pattern: &str) -> Recipe {
            Recipe {
                id: RecipeId(id.into()),
                name: id.into(),
                category: ods_core::OptimizationCategory::Algorithmic,
                language: "rust".into(),
                promotion: PromotionState::Seed,
                trigger: Trigger {
                    ast_pattern: pattern.into(),
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
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/lib.rs"), "pub fn a() { let _ = 1; }\n").unwrap();

        let store = Store::in_memory().unwrap();
        store
            .upsert(&make_recipe(
                "fn-recipe",
                "(function_item name: (identifier) @n) @match",
            ))
            .unwrap();

        let d = Discoverer::default();
        // First pass: no cache exists yet. Should write one.
        let first = d.scan_with_recipes(repo, &store, 10).unwrap();
        assert!(
            !first.is_empty(),
            "first pass should find at least one candidate"
        );
        let cache_path = repo.join(".ods").join("discover-cache.json");
        assert!(
            cache_path.exists(),
            "first scan must persist cache at {}",
            cache_path.display()
        );
        let cache_text_v1 = std::fs::read_to_string(&cache_path).unwrap();
        assert!(
            cache_text_v1.contains("fn-recipe"),
            "cache should reference the recipe that fired"
        );

        // Second pass, no file changes. The cache should be re-used:
        // the saved cache file must have the same mtime-key entry.
        let second = d.scan_with_recipes(repo, &store, 10).unwrap();
        assert_eq!(
            first.len(),
            second.len(),
            "unchanged repo should produce same candidate count"
        );

        // Touch the file. Different mtime (best effort) + different
        // size — both invalidate the entry. Second scan recomputes.
        std::fs::write(
            repo.join("src/lib.rs"),
            "pub fn a() { let _ = 1; }\npub fn b() { let _ = 2; }\n",
        )
        .unwrap();
        let third = d.scan_with_recipes(repo, &store, 10).unwrap();
        // Now two functions should surface (or at least not fewer).
        assert!(
            third.len() >= first.len(),
            "after adding fn b, candidates should be >= first run (was {}, got {})",
            first.len(),
            third.len()
        );

        // Swap the corpus. Different recipe → different corpus hash →
        // whole cache invalidated. Old cache file is overwritten.
        let store2 = Store::in_memory().unwrap();
        store2
            .upsert(&make_recipe("different-recipe", "(let_declaration) @match"))
            .unwrap();
        let fourth = d.scan_with_recipes(repo, &store2, 10).unwrap();
        assert!(!fourth.is_empty(), "new corpus should still find something");
        let cache_text_v2 = std::fs::read_to_string(&cache_path).unwrap();
        assert!(
            cache_text_v2.contains("different-recipe"),
            "cache must now reference the new corpus's recipe"
        );
        assert!(
            !cache_text_v2.contains("fn-recipe"),
            "cache must have dropped the old recipe's entries after corpus hash change"
        );
    }

    /// A broad trigger that fires in >5% of source files must receive
    /// a precision penalty so it doesn't crowd out more-specific
    /// recipes on the final ranking. This test sets up a fixture with
    /// two recipes: one narrow (fires once), one broad (fires in every
    /// file). After ranking, the narrow recipe's candidate must score
    /// higher.
    #[test]
    fn broad_recipes_are_precision_penalized() {
        use ods_recipes::schema::{
            PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe,
        };
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::create_dir_all(repo.join("src")).unwrap();
        // 10 files, each with one `fn foo() {}` and one `HashMap::new()`.
        // The "every function" trigger fires 10×; the "HashMap::new"
        // trigger also fires 10× — so both are "broad" by file-count.
        // To make the test discriminating, ONE file has a unique narrow
        // trigger.
        for i in 0..10 {
            let content = format!("pub fn foo_{i}() {{ let _ = {i}; }}");
            std::fs::write(repo.join(format!("src/file_{i}.rs")), content).unwrap();
        }
        std::fs::write(
            repo.join("src/unique.rs"),
            "pub fn narrow_hit() { let _ = memchr::memmem::Finder::new(b\"xyz\"); }",
        )
        .unwrap();

        let store = Store::in_memory().unwrap();
        // Broad: matches every `fn` declaration.
        store
            .upsert(&Recipe {
                id: RecipeId("rust-broad-fn".into()),
                name: "every function".into(),
                category: ods_core::OptimizationCategory::FastPathSpecialization,
                language: "rust".into(),
                promotion: PromotionState::Seed,
                trigger: Trigger {
                    ast_pattern: "(function_item name: (identifier) @n) @match".into(),
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
        // Narrow: matches `Finder::new`.
        store
            .upsert(&Recipe {
                id: RecipeId("rust-narrow-finder".into()),
                name: "Finder::new".into(),
                category: ods_core::OptimizationCategory::AllocReduction,
                language: "rust".into(),
                promotion: PromotionState::Seed,
                trigger: Trigger {
                    ast_pattern: "(call_expression function: (scoped_identifier \
                                  path: (scoped_identifier) name: (identifier) @m \
                                  (#eq? @m \"new\"))) @match"
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
        let cands = d.scan_with_recipes(repo, &store, 50).unwrap();
        // The narrow-only candidate (only matched by rust-narrow-finder
        // in 1 file out of 11) must score ABOVE at least one of the
        // broad-only candidates (matched by rust-broad-fn in every file,
        // so penalty = 1/11 ≈ 0.09).
        let narrow_hit = cands
            .iter()
            .find(|c| {
                c.matched_recipes
                    .iter()
                    .any(|r| r.0 == "rust-narrow-finder")
            })
            .expect("narrow recipe must produce at least one candidate");
        let broad_only = cands
            .iter()
            .filter(|c| {
                c.matched_recipes.iter().any(|r| r.0 == "rust-broad-fn")
                    && !c
                        .matched_recipes
                        .iter()
                        .any(|r| r.0 == "rust-narrow-finder")
            })
            .collect::<Vec<_>>();
        assert!(!broad_only.is_empty(), "expected broad-only candidates");
        for b in &broad_only {
            assert!(
                narrow_hit.score >= b.score,
                "narrow candidate ({}, score={:.3}) should rank >= broad ({}, score={:.3}) \
                 after precision penalty",
                narrow_hit.symbol,
                narrow_hit.score,
                b.symbol,
                b.score
            );
        }
    }

    /// Cross-language proof: Ruby recipes must also route through the
    /// per-language Discoverer dispatch and attribute matches to the
    /// enclosing Ruby `method` (not a file-stem fallback).
    #[test]
    fn discover_attributes_ruby_matches_to_enclosing_method() {
        use ods_recipes::schema::{
            PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe,
        };
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();
        std::fs::create_dir_all(repo.join("lib")).unwrap();
        // `hot_method` calls `File.join`; `ghost_method` only has a
        // commented-out call + a string literal with matching text. A
        // regex-based matcher would flag `ghost_method` too; tree-sitter
        // must suppress that.
        std::fs::write(
            repo.join("lib/app.rb"),
            r#"
def hot_method
  File.join("/var", "log")
end

def ghost_method
  # File.join("/fake", "x")
  "File.join in a string should not match"
end
"#,
        )
        .unwrap();
        let store = Store::in_memory().unwrap();
        store
            .upsert(&Recipe {
                id: RecipeId("ruby-file-join".into()),
                name: "File.join usage".into(),
                category: ods_core::OptimizationCategory::FastPathSpecialization,
                language: "ruby".into(),
                promotion: PromotionState::Seed,
                trigger: Trigger {
                    ast_pattern: r#"(call receiver: (constant) @c (#eq? @c "File")
                                         method: (identifier) @m (#eq? @m "join")) @match"#
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
            symbols.contains("hot_method"),
            "expected candidate for hot_method; got {symbols:?}"
        );
        assert!(
            !symbols.contains("ghost_method"),
            "tree-sitter must suppress comment / string matches; got {symbols:?}"
        );
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
