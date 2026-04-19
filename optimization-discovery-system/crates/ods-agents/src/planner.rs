use crate::specialist::SpecialistKind;
use ods_core::{Hypothesis, OptimizationCategory, TargetSig};
use ods_recipes::{PromotionState, RecipeQuery, Store};

pub struct Planner<'a> {
    pub store: &'a Store,
}

impl<'a> Planner<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// Recipe-first routing: retrieve candidate recipes for the target's
    /// language + observed categories, and emit one hypothesis per hit. When
    /// the corpus has nothing to say, fall back to enumerating all specialists
    /// so downstream can race them in parallel worktrees.
    pub fn plan(
        &self,
        target: &TargetSig,
        observed_categories: &[OptimizationCategory],
    ) -> anyhow::Result<Vec<(SpecialistKind, Hypothesis)>> {
        let mut out = Vec::new();

        for category in observed_categories {
            let hits = self.store.search(&RecipeQuery {
                language: Some(target.language.clone()),
                category: Some(*category),
                min_promotion: Some(PromotionState::Seed),
                limit: Some(5),
            })?;
            for recipe in hits {
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

fn specialist_for(c: OptimizationCategory) -> SpecialistKind {
    use OptimizationCategory::*;
    match c {
        SyscallElimination     => SpecialistKind::SyscallEliminator,
        AllocReduction         => SpecialistKind::AllocReducer,
        FastPathSpecialization => SpecialistKind::FastPathSpecializer,
        Algorithmic            => SpecialistKind::AlgorithmicFixer,
        ValidationRemoval      => SpecialistKind::ValidationRemover,
        Caching                => SpecialistKind::CachingSpecialist,
        DependencyOptimization => SpecialistKind::DependencyOptimizer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
