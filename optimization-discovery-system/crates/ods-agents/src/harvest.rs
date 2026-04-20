//! Auto-harvest: build a `Recipe` from the winning specialist's transform
//! and persist it as `Candidate`. Repeat wins across different repos
//! promote it automatically via `promote_on_success`.

use crate::anthropic::{AnthropicClient, ToolUseLoop};
use crate::race::WinnerRecord;
use ods_core::TargetSig;
use ods_recipes::{
    promote::{promote_on_success, PromotionRules},
    schema::{
        NegativeRecord, PromotionState, Recipe, RecipeId, SuccessRecord, Transformation, Trigger,
        VerificationRecipe,
    },
    Store,
};

/// Outcome of a harvest: the specific recipe id and, when the Generalizer
/// ran, the linked generalized recipe id.
#[derive(Debug, Clone)]
pub struct HarvestOutcome {
    pub specific_id: RecipeId,
    pub generalized_id: Option<RecipeId>,
}

/// Build a candidate Recipe from a race winner and upsert it. Returns the
/// recipe id that was stored. This is the "Phase 1" narrow harvest - keeps
/// per-repo provenance.
pub fn harvest(
    winner: &WinnerRecord,
    target: &TargetSig,
    repo: &str,
    commit: &str,
    store: &Store,
) -> anyhow::Result<RecipeId> {
    harvest_full(winner, target, repo, commit, store, None).map(|o| o.specific_id)
}

/// Full harvest: Phase 1 narrow + optional Phase 2 generalizer LLM call.
/// The `client` is used only for Phase 2; when None, only the specific
/// recipe is written.
pub fn harvest_full(
    winner: &WinnerRecord,
    target: &TargetSig,
    repo: &str,
    commit: &str,
    store: &Store,
    client: Option<&AnthropicClient>,
) -> anyhow::Result<HarvestOutcome> {
    // Phase 1: specific recipe (provenance).
    let id = synthesize_id(&winner.outcome.kind, target);
    let now =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
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
            profile_signature: vec![format!("hot:{}::{}", target.module, target.symbol)],
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
            recorded_at: now.clone(),
        }],
        negative_history: vec![],
        generalized_from: None,
        generalized_as: None,
        source_patch_ref: Some(commit.to_string()),
        embedding: None,
    };
    // Prior candidate with the same id? Merge the new success record.
    if let Some(prior) = store.get(&recipe.id)? {
        recipe.success_history = {
            let mut h = prior.success_history;
            h.extend(recipe.success_history);
            h
        };
        recipe.negative_history = prior.negative_history;
        recipe.promotion = max_promotion(prior.promotion, PromotionState::Candidate);
        recipe.generalized_as = prior.generalized_as;
    }
    let _ = promote_on_success(&mut recipe, &PromotionRules::default());

    // Phase 2: optional Generalizer call.
    let mut generalized_id: Option<RecipeId> = None;
    if let Some(c) = client {
        if let Ok(Some(general)) = run_generalizer(c, winner, target, &recipe.id) {
            store.upsert(&general)?;
            generalized_id = Some(general.id.clone());
            recipe.generalized_as = Some(general.id.clone());
        }
    }

    store.upsert(&recipe)?;
    Ok(HarvestOutcome {
        specific_id: RecipeId(id),
        generalized_id,
    })
}

/// Record a negative outcome against each retrieved recipe involved in a
/// run. Keeps at most 200 entries per recipe (rolling-window cap).
pub fn record_negatives(
    recipe_ids: &[RecipeId],
    repo: &str,
    target: &TargetSig,
    outcome: ods_recipes::NegativeOutcome,
    store: &Store,
) -> anyhow::Result<()> {
    let now =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    for id in recipe_ids {
        let Some(mut recipe) = store.get(id)? else {
            continue;
        };
        recipe.negative_history.push(NegativeRecord {
            repo: repo.to_string(),
            target_symbol: target.symbol.clone(),
            outcome,
            recorded_at: now.clone(),
        });
        if recipe.negative_history.len() > 200 {
            let drop = recipe.negative_history.len() - 200;
            recipe.negative_history.drain(0..drop);
        }
        // Maybe retire.
        match ods_recipes::promote::promote_on_negative(&recipe, &PromotionRules::default()) {
            ods_recipes::promote::PromotionOutcome::Retire => {
                let _ = store.delete(id);
            }
            _ => {
                store.upsert(&recipe)?;
            }
        }
    }
    Ok(())
}

/// Phase 2: one LLM turn that asks the model to abstract the specific
/// patch into a reusable pattern recipe. Returns `Ok(None)` when the
/// model didn't produce a parseable recipe (we keep Phase 1 in that case).
fn run_generalizer(
    client: &AnthropicClient,
    winner: &WinnerRecord,
    target: &TargetSig,
    specific_id: &RecipeId,
) -> anyhow::Result<Option<Recipe>> {
    let system = "You are the Generalizer role in the ods product. Given a \
        concrete patch that sped up a specific function, you describe the \
        REUSABLE pattern (not this one change) in our Recipe JSON schema. \
        The output must reference no repo-specific identifiers (no crate \
        name, no module name, no function name); it must describe the AST \
        shape of the trigger as a tree-sitter S-expression query with at \
        least one named capture, the profile signature, and the ordered \
        transformation steps in pattern-level language.";
    let user = format!(
        "Target that was sped up: {}::{}::{}\n\
         Winning specialist: {:?}\n\
         Rationale from specialist:\n{}\n\n\
         Patch diff:\n{}\n\n\
         Produce a JSON object matching this schema (no commentary, no fences):\n\
         {{\n\
           \"id\": \"general-<short-slug-you-pick>\",\n\
           \"name\": \"<pattern name, no repo names>\",\n\
           \"category\": \"<one of: syscall-elimination, alloc-reduction, \
             fast-path-specialization, algorithmic, validation-removal, \
             caching, dependency-optimization>\",\n\
           \"language\": \"{}\",\n\
           \"ast_pattern\": \"<tree-sitter S-expression query; must include \
             at least one @capture; example for rust: (call_expression \
             function: (scoped_identifier path: (identifier) @p (#eq? @p \
             \\\"Vec\\\") name: (identifier) @m (#eq? @m \\\"new\\\"))) @match>\",\n\
           \"profile_signature\": [\"<e.g. hot:nested-for-over-tokens>\"],\n\
           \"steps\": [\"<ordered transformation steps, pattern-level>\"],\n\
           \"invariants\": [\"<semantic invariants to preserve>\"]\n\
         }}",
        target.language,
        target.module,
        target.symbol,
        winner.outcome.kind,
        truncate_to(&winner.outcome.rationale, 1500),
        truncate_to(&winner.patch.unified_diff, 2500),
        target.language,
    );
    let loop_ = ToolUseLoop::default();
    let runtime = tokio::runtime::Handle::try_current();
    let fut = async move { loop_.run(client, system, &user).await };
    let (_stats, text, _convo) = match runtime {
        Ok(h) => {
            // Called from inside tokio; we can't block_on. Use spawn_blocking
            // or assume caller is async-aware. The harvest path is always
            // async (called from orchestrator.run), so we can block on a
            // separate runtime only as a last resort. Here we use the
            // current runtime's block_in_place for the single await.
            tokio::task::block_in_place(|| h.block_on(fut))?
        }
        Err(_) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(fut)?
        }
    };

    let Some(json) = extract_json_object(&text) else {
        return Ok(None);
    };
    parse_generalized_recipe(&json, target, specific_id).map(Some)
}

fn truncate_to(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn extract_json_object(text: &str) -> Option<String> {
    // Tolerate optional ```json fences. Find the first { ... last }.
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    Some(text[start..=end].to_string())
}

fn parse_generalized_recipe(
    json: &str,
    target: &TargetSig,
    specific_id: &RecipeId,
) -> anyhow::Result<Recipe> {
    #[derive(serde::Deserialize)]
    struct G {
        id: String,
        name: String,
        category: String,
        language: String,
        ast_pattern: String,
        #[serde(default)]
        profile_signature: Vec<String>,
        #[serde(default)]
        steps: Vec<String>,
        #[serde(default)]
        invariants: Vec<String>,
    }
    let g: G = serde_json::from_str(json)?;
    let cat = match g.category.as_str() {
        "syscall-elimination" => ods_core::OptimizationCategory::SyscallElimination,
        "alloc-reduction" => ods_core::OptimizationCategory::AllocReduction,
        "fast-path-specialization" => ods_core::OptimizationCategory::FastPathSpecialization,
        "algorithmic" => ods_core::OptimizationCategory::Algorithmic,
        "validation-removal" => ods_core::OptimizationCategory::ValidationRemoval,
        "caching" => ods_core::OptimizationCategory::Caching,
        "dependency-optimization" => ods_core::OptimizationCategory::DependencyOptimization,
        other => anyhow::bail!("unknown category: {other}"),
    };
    let mut steps = g.steps;
    if !g.invariants.is_empty() {
        steps.push(format!("Invariants: {}", g.invariants.join("; ")));
    }
    let _ = target; // target is only used by the caller; the generalized recipe deliberately carries no repo-specific fields.
    Ok(Recipe {
        id: RecipeId(g.id.clone()),
        name: g.name,
        category: cat,
        language: g.language,
        promotion: PromotionState::Hypothesized,
        trigger: Trigger {
            ast_pattern: g.ast_pattern,
            profile_signature: g.profile_signature,
            naive_alt_ratio_min: None,
        },
        transformation: Transformation { steps },
        verification: VerificationRecipe {
            test_selectors: vec![],
            property_seeds: vec![],
            fuzz_minutes: 0,
            semver_check: false,
        },
        benchmark_template: String::new(),
        success_history: vec![],
        negative_history: vec![],
        generalized_from: Some(specific_id.clone()),
        generalized_as: None,
        source_patch_ref: None,
        embedding: None,
    })
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
        RuntimeConfigurator => "runtime",
        // Explorer never harvests, but keep the match exhaustive so new
        // SpecialistKind variants can't silently break the build.
        Explorer => "explorer",
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
            PromotionState::Hypothesized => 0,
            PromotionState::Seed => 1,
            PromotionState::Candidate => 2,
            PromotionState::Validated => 3,
            PromotionState::Corpus => 4,
            PromotionState::AntiPattern => 5,
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
