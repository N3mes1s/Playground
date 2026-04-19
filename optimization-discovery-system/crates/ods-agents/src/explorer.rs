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
         Propose up to {} reusable patterns.\n\n\
         **Hard constraints on your final answer:**\n\
         1. Your LAST turn MUST contain a single fenced ```json block and \
         NOTHING ELSE outside it. No commentary, no prose.\n\
         2. Inside the block, emit exactly this shape (the parser ignores \
         everything else):\n\
         ```json\n\
         {{\n  \"recipes\": [\n    {{\n      \"id\": \"hyp-<slug>\",\n      \
         \"name\": \"<pattern name>\",\n      \"category\": \"<one of: \
         syscall-elimination, alloc-reduction, fast-path-specialization, \
         algorithmic, validation-removal, caching, \
         dependency-optimization>\",\n      \"ast_pattern\": \"<regex>\",\n      \
         \"profile_signature\": [\"...\"],\n      \"steps\": [\"...\"],\n      \
         \"invariants\": [\"...\"]\n    }}\n  ]\n}}\n```\n\
         3. If you find nothing worth proposing, emit the block with an \
         empty `recipes: []` and finish -- do not keep searching beyond \
         the iteration budget.\n\
         4. Patterns must describe a SHAPE (regex trigger + what to do), \
         not a one-off fix for a specific function in this repo.",
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
    // Try in order of specificity:
    //   1. every fenced ```json ... ``` block (parse each, collect all hits)
    //   2. every bracket-balanced {...} span at the top level (pick first
    //      that deserialises)
    //   3. a top-level [...] bare array
    //
    // The previous implementation grabbed `text[first_{..last_}]` which
    // over-consumed when the agent wrote prose like `{foo: bar}` before
    // emitting its final JSON. Budget-burning failure mode.
    let mut recipes: Vec<Recipe> = Vec::new();

    // (1) Fenced json blocks.
    for block in extract_fenced_blocks(text, "json") {
        append_from_json(&block, language, &mut recipes);
    }
    if !recipes.is_empty() {
        return Ok(recipes);
    }

    // (2) Bracket-balanced {} spans.
    for span in find_balanced_spans(text, '{', '}') {
        append_from_json(&span, language, &mut recipes);
    }
    if !recipes.is_empty() {
        return Ok(recipes);
    }

    // (3) Bare array.
    for span in find_balanced_spans(text, '[', ']') {
        // Synthesize an envelope so the Envelope::recipes path can reuse
        // downstream validation.
        let envelope = format!("{{\"recipes\":{span}}}");
        append_from_json(&envelope, language, &mut recipes);
    }

    Ok(recipes)
}

/// Extract the bodies of every fenced code block tagged with the given
/// language (e.g. ```json ... ```). Tolerates trailing whitespace on the
/// opening line and stops cleanly at the matching ```.
fn extract_fenced_blocks(text: &str, tag: &str) -> Vec<String> {
    let open = format!("```{tag}");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(idx) = rest.find(&open) {
        let after_open = &rest[idx + open.len()..];
        // Skip the rest of the opening line.
        let Some(nl) = after_open.find('\n') else {
            break;
        };
        let body_start = &after_open[nl + 1..];
        let Some(close) = body_start.find("```") else {
            break;
        };
        out.push(body_start[..close].to_string());
        rest = &body_start[close + 3..];
    }
    out
}

/// Walk `text` looking for top-level balanced spans between `open` and
/// `close` characters. Ignores `open`/`close` that sit inside `"..."` string
/// literals (so `{"foo": "bar}"}` doesn't confuse us). Returns each span's
/// contents including the outer delimiters.
fn find_balanced_spans(text: &str, open: char, close: char) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] as char == open {
            let start = i;
            let mut depth = 1;
            let mut in_str = false;
            let mut escaped = false;
            i += 1;
            while i < bytes.len() && depth > 0 {
                let c = bytes[i] as char;
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                } else if c == '"' {
                    in_str = true;
                } else if c == open {
                    depth += 1;
                } else if c == close {
                    depth -= 1;
                    if depth == 0 {
                        spans.push(text[start..=i].to_string());
                        break;
                    }
                }
                i += 1;
            }
        }
        i += 1;
    }
    spans
}

fn append_from_json(json: &str, language: &str, out: &mut Vec<Recipe>) {
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
        #[serde(default)]
        ast_pattern: String,
        #[serde(default)]
        profile_signature: Vec<String>,
        #[serde(default)]
        steps: Vec<String>,
        #[serde(default)]
        invariants: Vec<String>,
    }

    let env: Envelope = match serde_json::from_str::<Envelope>(json) {
        Ok(e) => e,
        Err(_) => {
            // Also tolerate a bare ProposedRecipe object (one recipe).
            if let Ok(single) = serde_json::from_str::<ProposedRecipe>(json) {
                Envelope {
                    recipes: vec![single],
                }
            } else {
                return;
            }
        }
    };

    for p in env.recipes {
        let cat = match p.category.as_str() {
            "syscall-elimination" => OptimizationCategory::SyscallElimination,
            "alloc-reduction" => OptimizationCategory::AllocReduction,
            "fast-path-specialization" => OptimizationCategory::FastPathSpecialization,
            "algorithmic" => OptimizationCategory::Algorithmic,
            "validation-removal" => OptimizationCategory::ValidationRemoval,
            "caching" => OptimizationCategory::Caching,
            "dependency-optimization" => OptimizationCategory::DependencyOptimization,
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
