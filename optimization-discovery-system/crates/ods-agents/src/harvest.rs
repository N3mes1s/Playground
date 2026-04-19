//! Auto-harvest: build a `Recipe` from the winning specialist's transform
//! and persist it as `Candidate`. Repeat wins across different repos
//! promote it automatically via `promote_on_success`.

use crate::race::WinnerRecord;
use ods_core::TargetSig;
use ods_recipes::{
    promote::{promote_on_success, PromotionRules},
    schema::{
        PromotionState, Recipe, RecipeId, SuccessRecord, Transformation, Trigger,
        VerificationRecipe,
    },
    Store,
};

/// Build a candidate Recipe from a race winner and upsert it. Returns the
/// recipe id that was stored.
pub fn harvest(
    winner: &WinnerRecord,
    target: &TargetSig,
    repo: &str,
    commit: &str,
    store: &Store,
) -> anyhow::Result<RecipeId> {
    let id = synthesize_id(&winner.outcome.kind, target);
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)?;
    let mut recipe = Recipe {
        id: RecipeId(id.clone()),
        name: format!(
            "{:?} on {}::{}::{}",
            winner.outcome.kind, target.language, target.module, target.symbol
        ),
        category: winner.outcome.kind.category(),
        language: target.language.clone(),
        promotion: PromotionState::Candidate,
        trigger: Trigger {
            ast_pattern: extract_ast_hint(&winner.patch.unified_diff),
            profile_signature: vec![format!(
                "hot:{}::{}",
                target.module, target.symbol
            )],
            naive_alt_ratio_min: None,
        },
        transformation: Transformation {
            steps: split_rationale(&winner.outcome.rationale),
        },
        verification: VerificationRecipe {
            test_selectors: vec![],
            property_seeds: vec![],
            fuzz_minutes: 1,
            semver_check: false,
        },
        benchmark_template: String::new(),
        success_history: vec![SuccessRecord {
            repo: repo.to_string(),
            commit: commit.to_string(),
            speedup: winner.verdict.speedup_point,
            ci_lower_bound: winner.verdict.speedup_lower,
            merged: false,
            recorded_at: now,
        }],
        embedding: None,
    };
    // Prior candidate with the same id? Merge the new success record.
    if let Some(prior) = store.get(&recipe.id)? {
        recipe.success_history = {
            let mut h = prior.success_history;
            h.extend(recipe.success_history);
            h
        };
        recipe.promotion = max_promotion(prior.promotion, PromotionState::Candidate);
    }
    // Auto-promote based on accumulated history.
    let _ = promote_on_success(&mut recipe, &PromotionRules::default());
    store.upsert(&recipe)?;
    Ok(RecipeId(id))
}

fn synthesize_id(kind: &crate::specialist::SpecialistKind, target: &TargetSig) -> String {
    format!(
        "auto-{}-{}-{}-{}",
        target.language,
        kind_slug(kind),
        target.module.replace("::", "-"),
        target.symbol
    )
}

fn kind_slug(k: &crate::specialist::SpecialistKind) -> &'static str {
    use crate::specialist::SpecialistKind::*;
    match k {
        SyscallEliminator => "syscall",
        AllocReducer => "alloc",
        FastPathSpecializer => "fastpath",
        AlgorithmicFixer => "algo",
        ValidationRemover => "validation",
        CachingSpecialist => "cache",
        DependencyOptimizer => "dep",
    }
}

fn split_rationale(r: &str) -> Vec<String> {
    let truncated: String = r.chars().take(2_000).collect();
    truncated
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .take(10)
        .collect()
}

/// Pull a rough AST hint out of the unified diff header / first added line
/// so the retriever can locate the same shape on the next run.
fn extract_ast_hint(diff: &str) -> String {
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix('+') {
            let t = rest.trim();
            if t.is_empty() || t.starts_with("++") {
                continue;
            }
            return t.chars().take(240).collect();
        }
    }
    String::new()
}

/// Monotonic max without implementing `Ord` on a foreign type.
fn max_promotion(a: PromotionState, b: PromotionState) -> PromotionState {
    fn rank(s: PromotionState) -> u8 {
        match s {
            PromotionState::Seed => 0,
            PromotionState::Candidate => 1,
            PromotionState::Validated => 2,
            PromotionState::Corpus => 3,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_shape_is_stable() {
        let t = TargetSig {
            language: "rust".into(),
            module: "std::fs".into(),
            symbol: "read_dir".into(),
            arity: None,
        };
        let id = synthesize_id(&crate::specialist::SpecialistKind::SyscallEliminator, &t);
        assert_eq!(id, "auto-rust-syscall-std-fs-read_dir");
    }

    #[test]
    fn ast_hint_picks_first_added_line() {
        let diff = "--- a/x\n+++ b/x\n@@\n-foo\n+bar\n+baz\n";
        assert_eq!(extract_ast_hint(diff), "bar");
    }
}
