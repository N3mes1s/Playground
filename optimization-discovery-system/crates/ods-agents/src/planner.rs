use crate::specialist::SpecialistKind;
use ods_core::{Hypothesis, OptimizationCategory, TargetSig};
use ods_recipes::Store;

pub struct Planner<'a> {
    pub store: &'a Store,
}

impl<'a> Planner<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// Vector-first routing: build a query string from the target
    /// signature and observed categories, retrieve top-K recipes by
    /// (cosine similarity * negative-history-adjusted promotion weight),
    /// then emit one hypothesis per hit.
    ///
    /// Previous iteration of this function fetched by (language,
    /// category, min_promotion) symbolically and stopped there. That
    /// missed cross-category matches and couldn't leverage the
    /// embeddings we already populate on every upsert.
    ///
    /// When the corpus returns nothing, falls back to enumerating every
    /// specialist so downstream can race them in parallel worktrees.
    pub fn plan(
        &self,
        target: &TargetSig,
        observed_categories: &[OptimizationCategory],
    ) -> anyhow::Result<Vec<(SpecialistKind, Hypothesis)>> {
        let mut out = Vec::new();

        let query = compose_query(target, observed_categories);
        let ranked = self.store.retrieve(Some(&target.language), &query, 8)?;

        for (recipe, _score) in ranked {
            let category = recipe.category;
            out.push((
                specialist_for(category),
                Hypothesis {
                    category,
                    target: target.clone(),
                    rationale: format!("recipe hit: {}", recipe.name),
                    seed_recipe_id: Some(recipe.id.to_string()),
                },
            ));
        }

        if out.is_empty() {
            for category in OptimizationCategory::ALL {
                out.push((
                    specialist_for(*category),
                    Hypothesis {
                        category: *category,
                        target: target.clone(),
                        rationale: "cold start, no recipe match".into(),
                        seed_recipe_id: None,
                    },
                ));
            }
        }

        Ok(out)
    }
}

fn compose_query(target: &TargetSig, categories: &[OptimizationCategory]) -> String {
    let mut tokens: Vec<String> = Vec::new();
    tokens.push(target.language.clone());
    tokens.push(target.module.clone());
    tokens.push(target.symbol.clone());
    for c in categories {
        tokens.push(c.to_string());
    }
    tokens.join(" ")
}

fn specialist_for(c: OptimizationCategory) -> SpecialistKind {
    use OptimizationCategory::*;
    match c {
        SyscallElimination => SpecialistKind::SyscallEliminator,
        AllocReduction => SpecialistKind::AllocReducer,
        FastPathSpecialization => SpecialistKind::FastPathSpecializer,
        Algorithmic => SpecialistKind::AlgorithmicFixer,
        ValidationRemoval => SpecialistKind::ValidationRemover,
        Caching => SpecialistKind::CachingSpecialist,
        DependencyOptimization => SpecialistKind::DependencyOptimizer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ods_recipes::schema::{
        PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe,
    };

    fn fixture_recipe(id: &str, name: &str, cat: OptimizationCategory, sig: &str) -> Recipe {
        Recipe {
            id: RecipeId(id.into()),
            name: name.into(),
            category: cat,
            language: "rust".into(),
            promotion: PromotionState::Seed,
            trigger: Trigger {
                ast_pattern: String::new(),
                profile_signature: vec![sig.into()],
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
            benchmark_template: String::new(),
            success_history: vec![],
            negative_history: vec![],
            generalized_from: None,
            generalized_as: None,
            source_patch_ref: None,
            embedding: None,
        }
    }

    #[test]
    fn cold_start_enumerates_all_specialists() {
        let store = Store::in_memory().unwrap();
        let planner = Planner::new(&store);
        let target = TargetSig {
            language: "rust".into(),
            module: "std::fs".into(),
            symbol: "read_dir".into(),
            arity: Some(1),
        };
        let plan = planner
            .plan(&target, &[OptimizationCategory::SyscallElimination])
            .unwrap();
        assert_eq!(plan.len(), OptimizationCategory::ALL.len());
    }

    #[test]
    fn vector_retrieval_returns_recipes_when_corpus_non_empty() {
        // When the store contains any Seed+ recipe, the plan should be
        // populated from the corpus (not from the cold-start fallback).
        // We don't assert a specific ranking - the hash-based embedding
        // has enough collisions that two recipes' relative order varies
        // across targets; this check validates the plumbing, not the
        // ranking quality.
        let store = Store::in_memory().unwrap();
        store
            .upsert(&fixture_recipe(
                "r-syscall",
                "skip stat on readdir d_type entries",
                OptimizationCategory::SyscallElimination,
                "syscall:stat",
            ))
            .unwrap();
        let planner = Planner::new(&store);
        let target = TargetSig {
            language: "rust".into(),
            module: "fs".into(),
            symbol: "readdir".into(),
            arity: None,
        };
        let plan = planner
            .plan(&target, &[OptimizationCategory::Algorithmic])
            .unwrap();
        // Non-empty (we have a recipe) and not the cold-start fallback
        // (which would return ALL::len() = 7 entries with seed_recipe_id
        // = None).
        assert!(!plan.is_empty());
        assert_ne!(plan.len(), OptimizationCategory::ALL.len());
        assert!(plan
            .iter()
            .all(|(_, h)| h.seed_recipe_id.as_deref() == Some("r-syscall")));
    }
}
