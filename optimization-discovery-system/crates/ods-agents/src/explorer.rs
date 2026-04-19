//! Explorer: read-only codebase survey that proposes new Hypothesized
//! recipes. Runs a single Anthropic conversation with the read-only
//! toolkit, extracts a JSON array of proposed patterns from the final
//! assistant turn, and returns them as `Recipe` structs ready for
//! `Store::upsert`.
//!
//! The Explorer never mutates the worktree and never runs tests or
//! benchmarks. It exists to grow the corpus, not to land patches.

use crate::anthropic::{AnthropicClient, ToolUseLoop};
use crate::specialist::{Specialist, SpecialistKind};
use crate::tools::{Sandbox, ToolHandlerMap};
use anyhow::Result;
use ods_core::OptimizationCategory;
use ods_recipes::schema::{
    PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe,
};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ExplorerOutcome {
    pub proposed_recipes: Vec<Recipe>,
    pub spent_usd: f64,
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub iterations: u32,
}

#[derive(Debug, Clone)]
pub struct ExplorerInput<'a> {
    pub repo: &'a Path,
    pub language: String,
    pub max_recipes: u32,
    pub max_iters: u32,
}

/// Run the Explorer. Reads `ANTHROPIC_API_KEY` from env. Returns proposed
/// recipes in `Hypothesized` state, not yet upserted (caller decides).
pub async fn run_explorer(input: ExplorerInput<'_>) -> Result<ExplorerOutcome> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| anyhow::anyhow!("ANTHROPIC_API_KEY must be set to run the Explorer"))?;
    let client = AnthropicClient::new(api_key)?;

    // Bind the sandbox to the repo root and register ONLY the read-only
    // toolkit - no apply_patch, no run_tests, no run_bench.
    let mut loop_ = ToolUseLoop::default();
    loop_.max_iters = input.max_iters;
    ToolHandlerMap::register_read_only(&mut loop_, Sandbox::new(input.repo.to_path_buf()));

    let spec = Specialist::new(SpecialistKind::Explorer);
    let system = spec.system_prompt();
    let user = format!(
        "Survey this {} codebase for performance-optimisation patterns that \
         could apply across many similar crates. Repo root is `.`. \
         Propose up to {} reusable patterns. For each, describe the \
         trigger as an AST/regex pattern (pattern-level, NOT a single \
         repo-specific identifier), the profile signature, the ordered \
         transformation steps, and the semantic invariants to preserve. \
         Finish your turn with a single fenced ```json block of the form:\n\
         {{\n  \"recipes\": [\n    {{\n      \"id\": \"hyp-<slug>\",\n      \
         \"name\": \"<pattern name>\",\n      \"category\": \"<one of: \
         syscall-elimination, alloc-reduction, fast-path-specialization, \
         algorithmic, validation-removal, caching, \
         dependency-optimization>\",\n      \"ast_pattern\": \"<regex>\",\n      \
         \"profile_signature\": [\"...\"],\n      \"steps\": [\"...\"],\n      \
         \"invariants\": [\"...\"]\n    }},\n    ...\n  ]\n}}",
        input.language, input.max_recipes
    );

    let (stats, text, _convo) = loop_.run(&client, system, &user).await?;
    let proposed = parse_explorer_output(&text, &input.language)?;

    Ok(ExplorerOutcome {
        proposed_recipes: proposed,
        spent_usd: stats.estimated_cost_usd(),
        tokens_in: stats.input_tokens,
        tokens_out: stats.output_tokens,
        iterations: stats.iterations,
    })
}

fn parse_explorer_output(text: &str, language: &str) -> Result<Vec<Recipe>> {
    // Tolerate optional ```json fences. Pull the first JSON object spanning
    // the first `{` to the last `}`.
    let start = text.find('{');
    let end = text.rfind('}');
    let Some((s, e)) = start.zip(end) else {
        return Ok(vec![]);
    };
    if e <= s {
        return Ok(vec![]);
    }
    let json = &text[s..=e];

    #[derive(serde::Deserialize)]
    struct Envelope {
        #[serde(default)]
        recipes: Vec<ProposedRecipe>,
    }
    #[derive(serde::Deserialize)]
    struct ProposedRecipe {
        id: String,
        name: String,
        category: String,
        ast_pattern: String,
        #[serde(default)]
        profile_signature: Vec<String>,
        #[serde(default)]
        steps: Vec<String>,
        #[serde(default)]
        invariants: Vec<String>,
    }

    let env: Envelope = match serde_json::from_str(json) {
        Ok(e) => e,
        Err(_) => return Ok(vec![]),
    };

    let mut out = Vec::new();
    for p in env.recipes {
        let cat = match p.category.as_str() {
            "syscall-elimination" => OptimizationCategory::SyscallElimination,
            "alloc-reduction" => OptimizationCategory::AllocReduction,
            "fast-path-specialization" => OptimizationCategory::FastPathSpecialization,
            "algorithmic" => OptimizationCategory::Algorithmic,
            "validation-removal" => OptimizationCategory::ValidationRemoval,
            "caching" => OptimizationCategory::Caching,
            "dependency-optimization" => OptimizationCategory::DependencyOptimization,
            // Unknown category → skip rather than fail the whole run.
            _ => continue,
        };
        let mut steps = p.steps;
        if !p.invariants.is_empty() {
            steps.push(format!("Invariants: {}", p.invariants.join("; ")));
        }
        out.push(Recipe {
            id: RecipeId(p.id),
            name: p.name,
            category: cat,
            language: language.to_string(),
            promotion: PromotionState::Hypothesized,
            trigger: Trigger {
                ast_pattern: p.ast_pattern,
                profile_signature: p.profile_signature,
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
            generalized_from: None,
            generalized_as: None,
            source_patch_ref: None,
            embedding: None,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_explorer_output() {
        let text = r#"Survey found 2 candidates.

```json
{
  "recipes": [
    {
      "id": "hyp-alloc-loop-vec",
      "name": "avoid rebuilding Vec in inner loop",
      "category": "alloc-reduction",
      "ast_pattern": "for\\s+.*\\{[^}]*Vec::new[^}]*\\}",
      "profile_signature": ["hot:loop-alloc"],
      "steps": ["hoist Vec allocation outside the loop"],
      "invariants": ["preserve element order"]
    },
    {
      "id": "hyp-early-exit-bound",
      "name": "early-exit when bound exceeded",
      "category": "algorithmic",
      "ast_pattern": "\\.count\\(\\)\\s*[<>!=]=?",
      "profile_signature": ["hot:bound-check"],
      "steps": ["replace count with bounded scan"],
      "invariants": ["same return value when within bound"]
    }
  ]
}
```"#;
        let got = parse_explorer_output(text, "rust").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].promotion, PromotionState::Hypothesized);
        assert_eq!(got[1].category, OptimizationCategory::Algorithmic);
    }

    #[test]
    fn tolerates_junk_text_before_json() {
        let text = "No pattern fit. Returning empty list.\n```json\n{\"recipes\":[]}\n```";
        assert!(parse_explorer_output(text, "rust").unwrap().is_empty());
    }

    #[test]
    fn ignores_unknown_category() {
        let text = r#"```json
{"recipes":[
  {"id":"hyp-bogus","name":"x","category":"made-up","ast_pattern":".","profile_signature":[],"steps":[]}
]}
```"#;
        assert!(parse_explorer_output(text, "rust").unwrap().is_empty());
    }
}
