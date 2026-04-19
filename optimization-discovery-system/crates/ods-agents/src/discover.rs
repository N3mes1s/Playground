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
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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
        Some("rs") | Some("go") | Some("py") | Some("rb") | Some("c") | Some("cc") | Some("cpp") | Some("h") | Some("hpp") | Some("js") | Some("ts") | Some("java")
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
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        // Criterion style
        if let Some(start) = l.find("bench_function(\"") {
            let rest = &l[start + "bench_function(\"".len()..];
            if let Some(end) = rest.find('"') {
                out.push(Candidate {
                    language: language.clone(),
                    module: bench_module(file),
                    symbol: rest[..end].to_string(),
                    source_file: file.to_path_buf(),
                    source_line: (i + 1) as u32,
                    bench_files: vec![file.to_path_buf()],
                    naive_alt_hint: None,
                    score: 1.0,
                });
            }
        }
        // libtest #[bench] fn name(...)
        if l.starts_with("fn bench_") || l.contains(" bench_") {
            if let Some(rest) = l.split("fn ").nth(1) {
                if let Some(end) = rest.find('(') {
                    let name = rest[..end].trim().to_string();
                    if !name.is_empty() {
                        out.push(Candidate {
                            language: language.clone(),
                            module: bench_module(file),
                            symbol: name,
                            source_file: file.to_path_buf(),
                            source_line: (i + 1) as u32,
                            bench_files: vec![file.to_path_buf()],
                            naive_alt_hint: None,
                            score: 0.8,
                        });
                    }
                }
            }
        }
        // Go BenchmarkXxx
        if l.starts_with("func Benchmark") {
            if let Some(after) = l.strip_prefix("func ") {
                if let Some(end) = after.find('(') {
                    out.push(Candidate {
                        language: "go".into(),
                        module: bench_module(file),
                        symbol: after[..end].trim().to_string(),
                        source_file: file.to_path_buf(),
                        source_line: (i + 1) as u32,
                        bench_files: vec![file.to_path_buf()],
                        naive_alt_hint: None,
                        score: 0.9,
                    });
                }
            }
        }
    }
    out
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
                hints.insert(sym.clone(), format!("referenced in {}: {snip}", f.display()));
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
}
