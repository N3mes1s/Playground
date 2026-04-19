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

const K1: f64 = 1.2;
const B: f64 = 0.75;

#[derive(Debug, Clone)]
pub struct ScoredRecipe {
    pub recipe: Recipe,
    pub score: f64,
}

fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
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

    let query_terms = tokenize(query);
    // doc frequencies
    let n = recipes.len() as f64;
    let mut out = Vec::with_capacity(recipes.len());
    for (i, tokens) in doc_tokens.iter().enumerate() {
        let mut score = 0.0;
        for term in &query_terms {
            let tf = tokens.iter().filter(|t| *t == term).count() as f64;
            if tf == 0.0 {
                continue;
            }
            let df = doc_tokens
                .iter()
                .filter(|d| d.iter().any(|t| t == term))
                .count() as f64;
            let idf = (((n - df + 0.5) / (df + 0.5)) + 1.0).ln();
            let norm = 1.0 - B + B * (doc_lens[i] / avg_len.max(1.0));
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
