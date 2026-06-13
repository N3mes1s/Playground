//! Repository encoder (paper §3.1).
//!
//! Maps a repository on disk to a single fixed-size embedding
//! `e = [ weighted_mean(file_vecs) ; max_pool(file_vecs) ] ∈ R^{2d}`.
//!
//! Two-step, training-free design from the paper:
//!   1. file-level: chunk each file (4096-token windows, 512 overlap), embed
//!      each chunk with a frozen embedder, mean-pool chunks -> file vector.
//!   2. repo-level: importance-weight file vectors (content distinctiveness,
//!      file size, path importance) and concat weighted-mean with max-pool.
//!
//! The paper uses a frozen Qwen3-Embedding-0.6B (d=1024). To keep this crate
//! self-contained and runnable anywhere (no multi-GB model download, no GPU) the
//! default backend is a deterministic feature-hashing embedder behind the
//! `Embedder` trait. It is content-sensitive and reproducible, which is all the
//! downstream hypernetwork forward pass requires; swap in a real neural embedder
//! by implementing `Embedder` (see README "Real embeddings").

use crate::tensor::l2_normalize;
use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

/// Embedding width per chunk/file (matches Qwen3-Embedding-0.6B).
pub const EMBED_DIM: usize = 1024;
const CHUNK_TOKENS: usize = 4096;
const CHUNK_OVERLAP: usize = 512;

/// A frozen text embedder: text -> unit vector in R^{EMBED_DIM}.
pub trait Embedder {
    fn embed(&self, text: &str) -> Vec<f32>;
    fn dim(&self) -> usize {
        EMBED_DIM
    }
}

/// Deterministic feature-hashing embedder (hashing-trick / signed random
/// projection over token unigrams+bigrams). Stand-in for a neural embedder.
pub struct HashEmbedder {
    dim: usize,
}

impl Default for HashEmbedder {
    fn default() -> Self {
        HashEmbedder { dim: EMBED_DIM }
    }
}

impl HashEmbedder {
    fn hash(s: &[u8], salt: u64) -> u64 {
        // FNV-1a with a salt so unigram/bigram streams don't collide.
        let mut h = 0xcbf29ce484222325u64 ^ salt;
        for &b in s {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }
}

impl Embedder for HashEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; self.dim];
        let toks = tokenize(text);
        for w in toks.windows(2) {
            // bigram
            let key = format!("{}\u{1}{}", w[0], w[1]);
            let hh = Self::hash(key.as_bytes(), 0x9E37);
            let idx = (hh % self.dim as u64) as usize;
            let sign = if (hh >> 63) & 1 == 1 { 1.0 } else { -1.0 };
            v[idx] += sign * 0.5;
        }
        for t in &toks {
            // unigram
            let hh = Self::hash(t.as_bytes(), 0x1234);
            let idx = (hh % self.dim as u64) as usize;
            let sign = if (hh >> 63) & 1 == 1 { 1.0 } else { -1.0 };
            v[idx] += sign;
        }
        l2_normalize(&mut v);
        v
    }
}

/// Identifier-aware tokenizer: keeps `[A-Za-z0-9_]` runs, lowercased.
fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch.to_ascii_lowercase());
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Mean-pool the per-chunk embeddings of one file.
fn embed_file(emb: &dyn Embedder, text: &str) -> Vec<f32> {
    let toks = tokenize(text);
    let dim = emb.dim();
    if toks.is_empty() {
        return vec![0.0; dim];
    }
    let mut acc = vec![0.0f32; dim];
    let mut n = 0usize;
    let step = CHUNK_TOKENS - CHUNK_OVERLAP;
    let mut start = 0;
    loop {
        let end = (start + CHUNK_TOKENS).min(toks.len());
        let chunk = toks[start..end].join(" ");
        let e = emb.embed(&chunk);
        for i in 0..dim {
            acc[i] += e[i];
        }
        n += 1;
        if end == toks.len() {
            break;
        }
        start += step;
    }
    for x in acc.iter_mut() {
        *x /= n as f32;
    }
    acc
}

/// A file's encoded contribution.
struct FileVec {
    path: String,
    tokens: usize,
    vec: Vec<f32>,
}

#[derive(Debug, Default)]
pub struct EncodeStats {
    pub files: usize,
    pub total_tokens: usize,
    pub top_files: Vec<(String, f32)>,
}

/// Encode a repository directory into `e ∈ R^{2*EMBED_DIM}`.
pub fn encode_repo(root: &Path, emb: &dyn Embedder) -> Result<(Vec<f32>, EncodeStats)> {
    let dim = emb.dim();
    let mut files: Vec<FileVec> = Vec::new();
    let mut total_tokens = 0usize;

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored_dir(e.path()))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() || !is_source_file(entry.path()) {
            continue;
        }
        let text = match std::fs::read(entry.path()) {
            Ok(bytes) if looks_textual(&bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            _ => continue,
        };
        let toks = tokenize(&text).len();
        if toks == 0 {
            continue;
        }
        total_tokens += toks;
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();
        files.push(FileVec {
            path: rel,
            tokens: toks,
            vec: embed_file(emb, &text),
        });
    }

    anyhow::ensure!(!files.is_empty(), "no source files found under {}", root.display());

    // Centroid for content-distinctiveness scoring.
    let mut centroid = vec![0.0f32; dim];
    for f in &files {
        for i in 0..dim {
            centroid[i] += f.vec[i];
        }
    }
    for x in centroid.iter_mut() {
        *x /= files.len() as f32;
    }
    let mut centroid_unit = centroid.clone();
    l2_normalize(&mut centroid_unit);

    // Importance weights: size * path * (0.5 + distinctiveness).
    let mut weights = Vec::with_capacity(files.len());
    for f in &files {
        let mut fu = f.vec.clone();
        l2_normalize(&mut fu);
        let cos = dot(&fu, &centroid_unit);
        let distinctiveness = (1.0 - cos).clamp(0.0, 2.0);
        let size_w = (1.0 + f.tokens as f32).ln();
        let path_w = path_importance(&f.path);
        weights.push(size_w * path_w * (0.5 + distinctiveness));
    }
    let wsum: f32 = weights.iter().sum::<f32>().max(1e-9);
    for w in weights.iter_mut() {
        *w /= wsum;
    }

    // Weighted mean and max pool over file vectors.
    let mut wmean = vec![0.0f32; dim];
    let mut maxp = vec![f32::NEG_INFINITY; dim];
    for (f, &w) in files.iter().zip(weights.iter()) {
        for i in 0..dim {
            wmean[i] += w * f.vec[i];
            if f.vec[i] > maxp[i] {
                maxp[i] = f.vec[i];
            }
        }
    }

    let mut e = Vec::with_capacity(2 * dim);
    e.extend_from_slice(&wmean);
    e.extend_from_slice(&maxp);

    // Report the most influential files for explainability.
    let mut ranked: Vec<(String, f32)> = files
        .iter()
        .zip(weights.iter())
        .map(|(f, &w)| (f.path.clone(), w))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    ranked.truncate(8);

    let stats = EncodeStats {
        files: files.len(),
        total_tokens,
        top_files: ranked,
    };
    Ok((e, stats))
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn path_importance(path: &str) -> f32 {
    let p = path.replace('\\', "/").to_lowercase();
    if p.contains("/vendor/")
        || p.contains("third_party/")
        || p.contains("node_modules/")
        || p.contains("/dist/")
        || p.contains("/build/")
        || p.contains("/.venv/")
        || p.contains("site-packages/")
    {
        return 0.1;
    }
    if p.contains("/test")
        || p.contains("tests/")
        || p.starts_with("test")
        || p.contains("_test.")
        || p.contains("/test_")
    {
        return 0.35;
    }
    let base = p.rsplit('/').next().unwrap_or(&p);
    if base == "__init__.py" || base == "lib.rs" || base == "main.rs" || base == "mod.rs" {
        return 1.3;
    }
    if base.starts_with("readme") || p.ends_with(".md") {
        return 0.7;
    }
    1.0
}

fn is_ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|s| {
            matches!(
                s,
                ".git" | "node_modules" | "target" | ".venv" | "venv" | "__pycache__"
                    | "dist" | "build" | ".mypy_cache" | ".pytest_cache"
            )
        })
        .unwrap_or(false)
}

fn looks_textual(bytes: &[u8]) -> bool {
    let n = bytes.len().min(8192);
    if n == 0 {
        return false;
    }
    let nul = bytes[..n].iter().filter(|&&b| b == 0).count();
    nul == 0
}

fn is_source_file(path: &Path) -> bool {
    const EXTS: &[&str] = &[
        "py", "rs", "js", "ts", "tsx", "jsx", "go", "java", "c", "h", "cpp", "cc", "hpp",
        "cs", "rb", "php", "swift", "kt", "scala", "sh", "bash", "lua", "r", "jl", "m",
        "sql", "toml", "yaml", "yml", "json", "cfg", "ini", "md", "txt", "rst",
    ];
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_lowercase());
    match ext {
        Some(e) => EXTS.contains(&e.as_str()),
        None => false,
    }
}
