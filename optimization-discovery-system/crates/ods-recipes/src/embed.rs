//! Hash-based feature-vector embeddings for recipes.
//!
//! We avoid a heavy embedding model dependency here. Instead, each recipe is
//! represented as a fixed-dimension sparse vector produced by the feature
//! hashing trick over its tokens (name + category + language + steps +
//! profile signatures). Retrieval uses cosine similarity in Rust against
//! the query vector built the same way.
//!
//! This keeps the binary single-file and gives us a semantic-search shape
//! (embeddings + cosine) that we can swap out for a real model or
//! `sqlite-vec` later without changing callers.

use crate::schema::Recipe;

pub const EMBED_DIM: usize = 128;

/// FNV-1a 64-bit hash. Stable across platforms and versions so the
/// embedding produced on one host matches another.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x00000100000001B3);
    }
    h
}

fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

fn ngrams(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(tokens.len() * 2);
    for t in tokens {
        out.push(t.clone());
    }
    for w in tokens.windows(2) {
        out.push(format!("{}_{}", w[0], w[1]));
    }
    out
}

fn embed_tokens(text: &str) -> [f32; EMBED_DIM] {
    let mut v = [0f32; EMBED_DIM];
    let toks = tokenize(text);
    if toks.is_empty() {
        return v;
    }
    for g in ngrams(&toks) {
        let h = fnv1a(g.as_bytes());
        let idx = (h as usize) % EMBED_DIM;
        // Second hash decides the sign to reduce collision bias.
        let sign = if (h >> 1) & 1 == 0 { 1.0 } else { -1.0 };
        v[idx] += sign;
    }
    // L2 normalise so cosine reduces to a dot product.
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut v {
            *x /= norm;
        }
    }
    v
}

pub fn embed_recipe(r: &Recipe) -> Vec<f32> {
    let text = format!(
        "{} {} {} {} {} {}",
        r.name,
        r.language,
        r.category,
        r.transformation.steps.join(" "),
        r.trigger.profile_signature.join(" "),
        r.trigger.ast_pattern,
    );
    embed_tokens(&text).to_vec()
}

pub fn embed_query(q: &str) -> Vec<f32> {
    embed_tokens(q).to_vec()
}

pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
    }
    // Vectors are pre-normalised so dot == cosine.
    dot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{PromotionState, RecipeId, Transformation, Trigger, VerificationRecipe};
    use ods_core::OptimizationCategory;

    fn mk(name: &str, signature: &str) -> Recipe {
        Recipe {
            id: RecipeId(name.into()),
            name: name.into(),
            category: OptimizationCategory::SyscallElimination,
            language: "rust".into(),
            promotion: PromotionState::Seed,
            trigger: Trigger {
                ast_pattern: "".into(),
                profile_signature: vec![signature.into()],
                naive_alt_ratio_min: None,
            },
            transformation: Transformation {
                steps: vec!["noop".into()],
            },
            verification: VerificationRecipe {
                test_selectors: vec![],
                property_seeds: vec![],
                fuzz_minutes: 0,
                semver_check: false,
            },
            benchmark_template: "".into(),
            success_history: vec![],
            embedding: None,
        }
    }

    #[test]
    fn cosine_is_stable() {
        let a = embed_query("readdir stat syscall");
        let b = embed_query("readdir stat syscall");
        assert!((cosine(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn related_terms_score_higher_than_unrelated() {
        let q = embed_query("avoid stat on readdir entries");
        let close = embed_recipe(&mk("readdir d_type", "syscall:stat"));
        let far = embed_recipe(&mk("ascii fast path", "branch:encoding"));
        let sc_close = cosine(&q, &close);
        let sc_far = cosine(&q, &far);
        assert!(sc_close > sc_far, "close={sc_close} far={sc_far}");
    }
}
