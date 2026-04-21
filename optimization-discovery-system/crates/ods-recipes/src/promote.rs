//! Automatic promotion rules. A recipe graduates from one state to the next
//! when its success history satisfies the configured thresholds. Promotion
//! is idempotent and monotonic (never regresses) unless the caller demotes
//! explicitly.

#[cfg(test)]
use crate::schema::NegativeRecord;
use crate::schema::{NegativeOutcome, PromotionState, Recipe, SuccessRecord};

#[derive(Debug, Clone)]
pub struct PromotionRules {
    /// Any success → at least `candidate`.
    pub min_successes_for_candidate: u32,
    /// Distinct repos required for `validated`.
    pub distinct_repos_for_validated: u32,
    /// Additional constraint for validated: each success must be a
    /// merged PR with a CI-lower-bound speedup above this value.
    pub validated_min_lower_bound: f64,
    /// Promotion to `corpus` requires a `validated` recipe plus this many
    /// recent successes (rolling window implied by caller).
    pub corpus_extra_successes: u32,
    /// A Hypothesized recipe is auto-deleted when it accumulates at least
    /// this many distinct-repo negatives with zero successes. Guards
    /// against Explorer churn.
    pub hypothesized_delete_distinct_repos: u32,
    /// A Seed/Candidate/Validated recipe is auto-demoted to
    /// `AntiPattern` when its negative-history length reaches this
    /// count AND it has zero successes. Covers the case where
    /// Hypothesized got promoted quickly via a single accidental
    /// success then kept failing — Retire would be wrong (we'd
    /// lose the history) but leaving it in retrieval is worse.
    pub demote_on_negative_count_without_wins: u32,
}

impl Default for PromotionRules {
    fn default() -> Self {
        Self {
            min_successes_for_candidate: 1,
            distinct_repos_for_validated: 3,
            validated_min_lower_bound: 1.15,
            corpus_extra_successes: 2,
            hypothesized_delete_distinct_repos: 3,
            demote_on_negative_count_without_wins: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionOutcome {
    Unchanged,
    Promoted {
        from: PromotionState,
        to: PromotionState,
    },
    /// The recipe should be deleted from the corpus (Hypothesized-only
    /// outcome after sustained negatives with zero wins).
    Retire,
    /// A non-Hypothesized recipe with sustained negatives and zero
    /// wins should be flipped to AntiPattern: preserved for
    /// historical reference, but no longer part of retrieval's
    /// "apply this" pool. Callers write this by setting
    /// `recipe.promotion = AntiPattern` and upserting.
    Demote {
        from: PromotionState,
        to: PromotionState,
    },
}

/// Consider promoting a recipe given its current success history. Returns
/// the outcome; the caller is responsible for persisting the change.
pub fn promote_on_success(recipe: &mut Recipe, rules: &PromotionRules) -> PromotionOutcome {
    let current = recipe.promotion;
    let target = decide(recipe, rules);
    if target == current {
        return PromotionOutcome::Unchanged;
    }
    // Never regress automatically.
    if rank(target) < rank(current) {
        return PromotionOutcome::Unchanged;
    }
    recipe.promotion = target;
    PromotionOutcome::Promoted {
        from: current,
        to: target,
    }
}

/// Consider demoting / retiring a recipe in light of its negative
/// history.
///
/// Two rules fire in priority order:
/// 1. `Retire` — Hypothesized + 0 successes + ≥N distinct-repo
///    negatives. The recipe never earned its keep; delete it.
/// 2. `Demote` — Seed/Candidate/Validated + 0 successes + ≥M total
///    negatives. Flips to AntiPattern so the retrieval pool drops
///    it but provenance survives. A human can re-promote if they
///    disagree.
///
/// Corpus/AntiPattern recipes are never auto-changed. Successful
/// recipes (any `success_history`) are never demoted — a single win
/// already earned at least candidate tier.
pub fn promote_on_negative(recipe: &Recipe, rules: &PromotionRules) -> PromotionOutcome {
    // Corpus / AntiPattern never auto-change.
    if matches!(
        recipe.promotion,
        PromotionState::Corpus | PromotionState::AntiPattern
    ) {
        return PromotionOutcome::Unchanged;
    }
    // Any success at all protects from demotion.
    if !recipe.success_history.is_empty() {
        return PromotionOutcome::Unchanged;
    }
    let distinct: std::collections::BTreeSet<&str> = recipe
        .negative_history
        .iter()
        .filter(|n| {
            matches!(
                n.outcome,
                NegativeOutcome::Abstained
                    | NegativeOutcome::RejectedByGate
                    | NegativeOutcome::NoMeasuredSpeedup
            )
        })
        .map(|n| n.repo.as_str())
        .collect();

    // Rule 1: Retire Hypothesized.
    if matches!(recipe.promotion, PromotionState::Hypothesized)
        && distinct.len() as u32 >= rules.hypothesized_delete_distinct_repos
    {
        return PromotionOutcome::Retire;
    }

    // Rule 2: Demote Seed/Candidate/Validated with sustained negatives.
    if matches!(
        recipe.promotion,
        PromotionState::Seed | PromotionState::Candidate | PromotionState::Validated
    ) && (recipe.negative_history.len() as u32) >= rules.demote_on_negative_count_without_wins
    {
        return PromotionOutcome::Demote {
            from: recipe.promotion,
            to: PromotionState::AntiPattern,
        };
    }
    PromotionOutcome::Unchanged
}

fn rank(s: PromotionState) -> u8 {
    match s {
        PromotionState::Hypothesized => 0,
        PromotionState::Seed => 1,
        PromotionState::Candidate => 2,
        PromotionState::Validated => 3,
        PromotionState::Corpus => 4,
        // AntiPattern is outside the progression ladder. Treat it as
        // "already at its terminal state"; promotion rules never touch it.
        PromotionState::AntiPattern => 5,
    }
}

fn decide(recipe: &Recipe, rules: &PromotionRules) -> PromotionState {
    if matches!(recipe.promotion, PromotionState::AntiPattern) {
        return PromotionState::AntiPattern;
    }
    let history = &recipe.success_history;
    let total_successes = history.len() as u32;
    if total_successes < rules.min_successes_for_candidate {
        return recipe.promotion;
    }

    let merged_above_bound: Vec<&SuccessRecord> = history
        .iter()
        .filter(|s| s.merged && s.ci_lower_bound >= rules.validated_min_lower_bound)
        .collect();
    let distinct_repos = {
        let mut set = std::collections::BTreeSet::new();
        for s in &merged_above_bound {
            set.insert(s.repo.as_str());
        }
        set.len() as u32
    };

    // Enough distinct repos → validated, possibly corpus.
    if distinct_repos >= rules.distinct_repos_for_validated {
        if merged_above_bound.len() as u32
            >= rules.distinct_repos_for_validated + rules.corpus_extra_successes
        {
            return PromotionState::Corpus;
        }
        return PromotionState::Validated;
    }

    PromotionState::Candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Recipe, RecipeId, Transformation, Trigger, VerificationRecipe};
    use ods_core::OptimizationCategory;

    fn mk_success(repo: &str, speedup: f64, merged: bool, lower: f64) -> SuccessRecord {
        SuccessRecord {
            repo: repo.into(),
            commit: "deadbeef".into(),
            speedup,
            ci_lower_bound: lower,
            merged,
            recorded_at: "2026-04-19T00:00:00Z".into(),
        }
    }

    fn mk_neg(repo: &str, outcome: NegativeOutcome) -> NegativeRecord {
        NegativeRecord {
            repo: repo.into(),
            target_symbol: "foo".into(),
            outcome,
            recorded_at: "2026-04-19T00:00:00Z".into(),
        }
    }

    fn base() -> Recipe {
        Recipe {
            id: RecipeId("x".into()),
            name: "x".into(),
            category: OptimizationCategory::SyscallElimination,
            language: "rust".into(),
            promotion: PromotionState::Seed,
            trigger: Trigger {
                ast_pattern: "".into(),
                profile_signature: vec![],
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
    fn seed_to_candidate_on_first_success() {
        let mut r = base();
        r.success_history.push(mk_success("a/b", 2.0, true, 1.5));
        let o = promote_on_success(&mut r, &PromotionRules::default());
        assert_eq!(
            o,
            PromotionOutcome::Promoted {
                from: PromotionState::Seed,
                to: PromotionState::Candidate
            }
        );
    }

    #[test]
    fn hypothesized_to_candidate_on_first_success() {
        let mut r = base();
        r.promotion = PromotionState::Hypothesized;
        r.success_history.push(mk_success("a/b", 2.0, true, 1.5));
        let o = promote_on_success(&mut r, &PromotionRules::default());
        assert_eq!(
            o,
            PromotionOutcome::Promoted {
                from: PromotionState::Hypothesized,
                to: PromotionState::Candidate,
            }
        );
    }

    #[test]
    fn three_repos_promote_to_validated() {
        let mut r = base();
        for (i, repo) in ["a/b", "c/d", "e/f"].iter().enumerate() {
            r.success_history
                .push(mk_success(repo, 2.0 + i as f64 * 0.1, true, 1.5));
        }
        let _ = promote_on_success(&mut r, &PromotionRules::default());
        assert_eq!(r.promotion, PromotionState::Validated);
    }

    #[test]
    fn never_regresses() {
        let mut r = base();
        r.promotion = PromotionState::Validated;
        r.success_history.push(mk_success("a/b", 1.1, false, 1.0));
        let o = promote_on_success(&mut r, &PromotionRules::default());
        assert_eq!(o, PromotionOutcome::Unchanged);
        assert_eq!(r.promotion, PromotionState::Validated);
    }

    #[test]
    fn hypothesized_retires_after_three_repo_abstains() {
        let mut r = base();
        r.promotion = PromotionState::Hypothesized;
        for repo in ["a/b", "c/d", "e/f"] {
            r.negative_history
                .push(mk_neg(repo, NegativeOutcome::Abstained));
        }
        assert_eq!(
            promote_on_negative(&r, &PromotionRules::default()),
            PromotionOutcome::Retire
        );
    }

    #[test]
    fn seed_never_auto_retires() {
        // Retire is Hypothesized-only; Seed gets the Demote path or
        // stays Unchanged, never Retire.
        let mut r = base();
        r.promotion = PromotionState::Seed;
        for repo in ["a/b", "c/d", "e/f"] {
            r.negative_history
                .push(mk_neg(repo, NegativeOutcome::Abstained));
        }
        // 3 negatives < demote threshold (5) → Unchanged.
        assert_eq!(
            promote_on_negative(&r, &PromotionRules::default()),
            PromotionOutcome::Unchanged
        );
    }

    #[test]
    fn seed_demotes_to_antipattern_after_five_negatives_and_zero_wins() {
        let mut r = base();
        r.promotion = PromotionState::Seed;
        for repo in ["a", "b", "c", "d", "e"] {
            r.negative_history
                .push(mk_neg(repo, NegativeOutcome::Abstained));
        }
        match promote_on_negative(&r, &PromotionRules::default()) {
            PromotionOutcome::Demote { from, to } => {
                assert_eq!(from, PromotionState::Seed);
                assert_eq!(to, PromotionState::AntiPattern);
            }
            other => panic!("expected Demote, got {other:?}"),
        }
    }

    #[test]
    fn a_single_success_protects_from_demotion() {
        let mut r = base();
        r.promotion = PromotionState::Seed;
        r.success_history
            .push(mk_success("won/here", 1.8, true, 1.6));
        for repo in ["a", "b", "c", "d", "e", "f", "g"] {
            r.negative_history
                .push(mk_neg(repo, NegativeOutcome::Abstained));
        }
        assert_eq!(
            promote_on_negative(&r, &PromotionRules::default()),
            PromotionOutcome::Unchanged
        );
    }

    #[test]
    fn corpus_tier_never_auto_changes() {
        let mut r = base();
        r.promotion = PromotionState::Corpus;
        for repo in ["a", "b", "c", "d", "e"] {
            r.negative_history
                .push(mk_neg(repo, NegativeOutcome::Abstained));
        }
        assert_eq!(
            promote_on_negative(&r, &PromotionRules::default()),
            PromotionOutcome::Unchanged
        );
    }
}
