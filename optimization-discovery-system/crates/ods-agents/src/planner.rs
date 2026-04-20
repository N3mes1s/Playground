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

    /// Category-scoped, specialist-first routing. For each
    /// `OptimizationCategory` we run retrieval against a cover pool of
    /// recipes, bucket the hits by the recipe's own category, then emit
    /// at most `PER_CATEGORY` hypotheses per specialist kind. If a
    /// category has zero matching recipes we skip that specialist
    /// entirely — no blank-seed hypothesis, no forced-abstain tax.
    ///
    /// Why this shape: the prior iteration did `for hit in retrieve(..)`
    /// and mapped `hit.category -> specialist` downstream. That meant
    /// specialist identity was a pure function of retrieval output
    /// order. On corpora skewed toward one category (rust-url in
    /// dogfood: 5+ fast-path recipes, 0 alloc recipes) the plan filled
    /// with FastPathSpecializer slots and AllocReducer never appeared.
    /// When a non-fast-path specialist DID make the cut it got seeded
    /// with a fast-path recipe's `transformation.steps` and dutifully
    /// re-applied `#[cold]/#[inline(never)]` — an AlgorithmicFixer
    /// wearing a FastPath hat. Stage 26 makes the category a
    /// pre-filter so seed_recipe and specialist kind can never
    /// disagree.
    ///
    /// Cover pool: we fetch `RETRIEVAL_COVER = 32` recipes from the
    /// store in one call. Any category whose top-K hits all rank past
    /// position 32 is effectively treated as absent from the corpus —
    /// acceptable because ranking past 32 means the query embedding is
    /// a poor match for that category on this target anyway.
    ///
    /// When the cover pool is empty (fresh store or store error), we
    /// fall back to enumerating every specialist with no seed — the
    /// race can still cold-start and harvest new recipes.
    pub fn plan(
        &self,
        target: &TargetSig,
        observed_categories: &[OptimizationCategory],
    ) -> anyhow::Result<Vec<(SpecialistKind, Hypothesis)>> {
        const RETRIEVAL_COVER: usize = 32;
        const PER_CATEGORY: usize = 3;

        let query = compose_query(target, observed_categories);
        let ranked = self
            .store
            .retrieve(Some(&target.language), &query, RETRIEVAL_COVER)?;

        if ranked.is_empty() {
            return Ok(cold_start_plan(target));
        }

        // Bucket retrieval hits by the recipe's declared category.
        // Iteration preserves vector-rank order so the first entry per
        // bucket is the highest-ranked recipe for that category — which
        // becomes the seed the specialist actually receives first.
        let mut by_category: std::collections::HashMap<
            OptimizationCategory,
            Vec<ods_recipes::schema::Recipe>,
        > = std::collections::HashMap::new();
        for (recipe, _score) in ranked {
            by_category
                .entry(recipe.category)
                .or_default()
                .push(recipe);
        }

        let mut out = Vec::new();
        for category in OptimizationCategory::ALL {
            let Some(bucket) = by_category.get(category) else {
                continue;
            };
            for recipe in bucket.iter().take(PER_CATEGORY) {
                out.push((
                    specialist_for(*category),
                    Hypothesis {
                        category: *category,
                        target: target.clone(),
                        rationale: format!("recipe hit: {}", recipe.name),
                        seed_recipe_id: Some(recipe.id.to_string()),
                    },
                ));
            }
        }

        // Cover pool had hits but none passed the per-category bucket
        // walk — shouldn't happen given the same iteration set, but
        // preserve the cold-start safety net rather than silently
        // returning an empty plan.
        if out.is_empty() {
            return Ok(cold_start_plan(target));
        }
        Ok(out)
    }
}

fn cold_start_plan(target: &TargetSig) -> Vec<(SpecialistKind, Hypothesis)> {
    OptimizationCategory::ALL
        .iter()
        .map(|category| {
            (
                specialist_for(*category),
                Hypothesis {
                    category: *category,
                    target: target.clone(),
                    rationale: "cold start, no recipe match".into(),
                    seed_recipe_id: None,
                },
            )
        })
        .collect()
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
        RuntimeConfig => SpecialistKind::RuntimeConfigurator,
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
        // (which would return ALL::len() entries with seed_recipe_id =
        // None).
        assert!(!plan.is_empty());
        assert_ne!(plan.len(), OptimizationCategory::ALL.len());
        assert!(plan
            .iter()
            .all(|(_, h)| h.seed_recipe_id.as_deref() == Some("r-syscall")));
    }

    #[test]
    fn specialists_without_corpus_match_are_skipped() {
        // The rust-url regression: corpus has only fast-path recipes
        // for this target's neighbourhood. Before Stage 26 the plan
        // still contained AllocReducer / AlgorithmicFixer / etc. slots,
        // each seeded with a mis-categorised fast-path recipe, and
        // those specialists would dutifully re-apply the fast-path
        // transform wearing the wrong hat.
        //
        // Stage 26: if retrieval returns nothing in a category's
        // bucket, that specialist must NOT appear in the plan.
        let store = Store::in_memory().unwrap();
        for (id, name) in [
            ("fp-a", "fast-path ascii short-circuit"),
            ("fp-b", "fast-path zero-length bail"),
            ("fp-c", "fast-path single-arg specialisation"),
        ] {
            store
                .upsert(&fixture_recipe(
                    id,
                    name,
                    OptimizationCategory::FastPathSpecialization,
                    "branch:cold",
                ))
                .unwrap();
        }
        let planner = Planner::new(&store);
        let target = TargetSig {
            language: "rust".into(),
            module: "parser".into(),
            symbol: "parse".into(),
            arity: None,
        };
        let plan = planner.plan(&target, &[]).unwrap();

        assert!(!plan.is_empty(), "corpus had fast-path hits");
        // Every hypothesis must be FastPathSpecializer — no
        // AllocReducer, no AlgorithmicFixer, no SyscallEliminator.
        for (kind, hyp) in &plan {
            assert_eq!(
                *kind,
                SpecialistKind::FastPathSpecializer,
                "kind leaked: {kind:?}",
            );
            assert_eq!(
                hyp.category,
                OptimizationCategory::FastPathSpecialization,
                "category leaked: {:?}",
                hyp.category
            );
        }
    }

    #[test]
    fn specialist_kind_matches_recipe_category_per_hypothesis() {
        // Invariant the prior planner did not enforce: whatever
        // specialist kind a hypothesis carries MUST match its
        // seeded recipe's category. This was the mechanism that
        // produced AlgorithmicFixer-with-fast-path-recipe in the
        // rust-url dogfood run.
        let store = Store::in_memory().unwrap();
        store
            .upsert(&fixture_recipe(
                "sc-1",
                "batch readdir via getdents",
                OptimizationCategory::SyscallElimination,
                "syscall:getdents",
            ))
            .unwrap();
        store
            .upsert(&fixture_recipe(
                "al-1",
                "O(n^2) -> O(n) single-pass scan",
                OptimizationCategory::Algorithmic,
                "cycles",
            ))
            .unwrap();
        let planner = Planner::new(&store);
        let target = TargetSig {
            language: "rust".into(),
            module: "m".into(),
            symbol: "s".into(),
            arity: None,
        };
        let plan = planner.plan(&target, &[]).unwrap();
        for (kind, hyp) in &plan {
            assert_eq!(specialist_for(hyp.category), *kind);
        }
    }
}
