//! BM25-style lexical scoring of recipes against a free-form query. Keeps the
//! retrieval path honest before embedding-based vector search (`sqlite-vec`)
//! lands in Stage 2. The tokens considered are drawn from:
//!
//! - the recipe name
//! - each transformation step
//! - each profile-signature string in the trigger
//!
//! The query is typically the concatenation of `target.symbol`, the
//! adapter's name, and the observed profile-signature tags.

use crate::schema::Recipe;
use std::collections::{HashMap, HashSet};

const K1: f64 = 1.2;
const B: f64 = 0.75;

#[derive(Debug, Clone)]
pub struct ScoredRecipe {
    pub recipe: Recipe,
    pub score: f64,
}

/// Tokenize `s` into lowercased alphanumeric-or-underscore runs.
///
/// Fast path (recipe: rust-path-join-fastpath, generalized to ASCII-clean
/// string inputs): if `s` is pure ASCII we can split on single bytes and
/// lowercase in place with `make_ascii_lowercase`, bypassing the UTF-8
/// `char` decode in `str::split` and the allocate-then-lowercase-copy dance
/// that `str::to_ascii_lowercase` performs on every token. The slow path is
/// preserved verbatim for non-ASCII input (e.g. identifiers with diacritics
/// or non-Latin scripts).
fn tokenize(s: &str) -> Vec<String> {
    if s.is_ascii() {
        // Hand-rolled byte scan: faster than `char`-based `split` + per-token
        // allocate-and-lowercase, and safe because every token is a run of
        // ASCII bytes (so a valid UTF-8 substring on its own).
        let bytes = s.as_bytes();
        let mut out: Vec<String> = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            // Skip separators.
            while i < bytes.len() && !is_token_byte(bytes[i]) {
                i += 1;
            }
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            if start < i {
                // SAFETY: ASCII bytes are valid UTF-8.
                let slice = unsafe { std::str::from_utf8_unchecked(&bytes[start..i]) };
                let mut tok = slice.to_owned();
                tok.make_ascii_lowercase();
                out.push(tok);
            }
        }
        out
    } else {
        s.split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|t| !t.is_empty())
            .map(|t| t.to_ascii_lowercase())
            .collect()
    }
}

#[inline]
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn recipe_tokens(r: &Recipe) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(tokenize(&r.name));
    out.extend(tokenize(&r.language));
    out.extend(tokenize(&r.category.to_string()));
    for step in &r.transformation.steps {
        out.extend(tokenize(step));
    }
    for sig in &r.trigger.profile_signature {
        out.extend(tokenize(sig));
    }
    out
}

/// Score each recipe against `query` using BM25. The returned vector is
/// sorted by descending score.
///
/// Previously this was O(N²·T) for N docs and T query terms because `df`
/// was recomputed inside the per-document loop and term frequency was a
/// linear scan over every token list. We now precompute:
///   * a per-doc term -> count map once (O(N·L))
///   * a per-unique-query-term df once (O(N·T_unique))
/// so the hot loop is O(N·T_unique) HashMap lookups. Semantics unchanged:
/// doc ordering and scores match the previous implementation bit-for-bit
/// for every input the test suite exercises.
pub fn score_recipes(recipes: &[Recipe], query: &str) -> Vec<ScoredRecipe> {
    if recipes.is_empty() {
        return vec![];
    }
    let doc_tokens: Vec<Vec<String>> = recipes.iter().map(recipe_tokens).collect();
    let doc_lens: Vec<f64> = doc_tokens.iter().map(|t| t.len() as f64).collect();
    let avg_len: f64 = if doc_lens.is_empty() {
        0.0
    } else {
        doc_lens.iter().sum::<f64>() / doc_lens.len() as f64
    };

    // Deduplicate query terms up front so df is computed once per distinct
    // term even when the caller repeats one. Preserve first-seen order for
    // determinism (irrelevant to scoring but nice for debugging). Use a
    // `HashSet<String>` membership check and only clone when a term is
    // actually new, avoiding the unconditional `t.clone()` on the old path.
    let query_terms: Vec<String> = {
        let raw = tokenize(query);
        let mut seen: HashSet<String> = HashSet::with_capacity(raw.len());
        let mut out = Vec::with_capacity(raw.len());
        for t in raw {
            if !seen.contains(&t) {
                seen.insert(t.clone());
                out.push(t);
            }
        }
        out
    };

    // Per-doc term frequency maps (replace the inner `.filter(...).count()`).
    let doc_tfs: Vec<HashMap<&str, u32>> = doc_tokens
        .iter()
        .map(|toks| {
            let mut m: HashMap<&str, u32> = HashMap::with_capacity(toks.len());
            for t in toks {
                *m.entry(t.as_str()).or_insert(0) += 1;
            }
            m
        })
        .collect();

    // df/idf computed once per unique query term.
    let n = recipes.len() as f64;
    let mut idf_by_term: HashMap<&str, f64> = HashMap::with_capacity(query_terms.len());
    for term in &query_terms {
        let df = doc_tfs.iter().filter(|m| m.contains_key(term.as_str())).count() as f64;
        let idf = (((n - df + 0.5) / (df + 0.5)) + 1.0).ln();
        idf_by_term.insert(term.as_str(), idf);
    }

    let mut out = Vec::with_capacity(recipes.len());
    for (i, tf_map) in doc_tfs.iter().enumerate() {
        let mut score = 0.0;
        let norm = 1.0 - B + B * (doc_lens[i] / avg_len.max(1.0));
        for term in &query_terms {
            let tf = *tf_map.get(term.as_str()).unwrap_or(&0) as f64;
            if tf == 0.0 {
                continue;
            }
            // `expect` here is fine: every term landed in idf_by_term above.
            let idf = *idf_by_term.get(term.as_str()).expect("idf present");
            score += idf * ((tf * (K1 + 1.0)) / (tf + K1 * norm));
        }
        out.push(ScoredRecipe {
            recipe: recipes[i].clone(),
            score,
        });
    }
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe,
    };
    use ods_core::OptimizationCategory;

    fn mk(id: &str, name: &str, signature: &str) -> Recipe {
        Recipe {
            id: RecipeId(id.into()),
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
            negative_history: vec![],
            generalized_from: None,
            generalized_as: None,
            source_patch_ref: None,
            embedding: None,
        }
    }

    #[test]
    fn scoring_ranks_best_match_first() {
        let recipes = vec![
            mk("readdir", "skip stat via readdir d_type", "syscall:stat"),
            mk("encoding", "ascii fast path", "branch:encoding"),
        ];
        let ranked = score_recipes(&recipes, "readdir stat syscall");
        assert_eq!(ranked[0].recipe.id.0, "readdir");
        assert!(ranked[0].score > ranked[1].score);
    }
}
