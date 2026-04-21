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
    /// Raw final text from the assistant. Kept around so callers can
    /// diagnose parse failures without re-running the whole conversation.
    pub final_text: String,
}

#[derive(Debug, Clone)]
pub struct ExplorerInput<'a> {
    pub repo: &'a Path,
    pub language: String,
    pub max_recipes: u32,
    pub max_iters: u32,
    /// Shared spend tracker. When `Some`, the Explorer's internal ToolUseLoop
    /// respects the same per-call budget gate used by the race.
    pub budget_tracker: Option<ods_core::BudgetTracker>,
}

/// Run the Explorer. Reads `ANTHROPIC_API_KEY` from env. Returns proposed
/// recipes in `Hypothesized` state, not yet upserted (caller decides).
pub async fn run_explorer(input: ExplorerInput<'_>) -> Result<ExplorerOutcome> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| anyhow::anyhow!("ANTHROPIC_API_KEY must be set to run the Explorer"))?;
    let client = AnthropicClient::new(api_key)?;

    // Bind the sandbox to the repo root and register ONLY the read-only
    // toolkit - no edit_file, no write_file, no run_tests, no run_bench.
    let mut loop_ = ToolUseLoop::default();
    loop_.max_iters = input.max_iters;
    // Grammar-constrain the final text block so the model CANNOT return
    // prose, markdown fences that fail to parse, or out-of-schema fields.
    // See https://platform.claude.com/docs/en/build-with-claude/structured-outputs.
    // Works on Opus 4.7/4.6, Sonnet 4.6/4.5, Haiku 4.5. Composes with
    // tools: the model uses tools freely during intermediate turns, and
    // the final text response is schema-valid by construction.
    loop_.output_schema = Some(explorer_output_schema());
    ToolHandlerMap::register_read_only(&mut loop_, Sandbox::new(input.repo.to_path_buf()));
    if let Some(t) = input.budget_tracker.as_ref() {
        loop_ = loop_.with_budget_tracker(t.clone());
    }

    let spec = Specialist::new(SpecialistKind::Explorer);
    let system = spec.system_prompt();
    let user = format!(
        "Survey this {} codebase for reusable performance-optimisation \
         patterns. Repo root is `.`. Target up to {} proposals.\n\n\
         **Do the survey first.** Required before your final response:\n\
         - `list_dir` on `.` and on the primary source directory.\n\
         - `read_file` on >=3 files that look hot (parsers, core loops, \
         formatters, I/O, hashing, string-heavy code).\n\
         - >=2 `ast_query` calls with tree-sitter S-expression patterns \
         (NOT regex). Examples for rust: `(call_expression function: \
         (scoped_identifier path: (identifier) @p (#eq? @p \"Vec\") \
         name: (identifier) @m (#eq? @m \"new\"))) @match`, \
         `(for_expression body: (block (expression_statement \
         (call_expression function: (field_expression field: \
         (field_identifier) @m (#eq? @m \"clone\")))))) @match`. Every \
         pattern must include at least one `@capture` name.\n\
         - 1 `recipe_search` to avoid proposing duplicates of what's \
         already in the corpus.\n\n\
         Only THEN finalise. Skipping exploration and returning an empty \
         list on iteration 1 is the wrong move -- there are almost \
         always patterns worth proposing in a real codebase.\n\n\
         **Output format.** Your final text response is grammar-constrained \
         to a JSON object of shape `{{\"recipes\": [...]}}` where each item \
         has: id, name, category (one of syscall-elimination, \
         alloc-reduction, fast-path-specialization, algorithmic, \
         validation-removal, caching, dependency-optimization), \
         ast_pattern (tree-sitter S-expression query with at least one \
         @capture), profile_signature (string[]), steps \
         (string[]), invariants (string[]). Don't worry about fences or \
         commas -- the schema constrains generation.",
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
        final_text: text,
    })
}

/// JSON Schema we pass to Claude's `output_config.format.json_schema.schema`
/// so the final text block is grammar-constrained to match.
///
/// Anthropic's structured-outputs docs require `additionalProperties: false`
/// on every object. Recursive schemas, numeric bounds, and string-length
/// constraints are NOT supported -- we enumerate categories and leave
/// string fields unconstrained.
pub(crate) fn explorer_output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recipes"],
        "properties": {
            "recipes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "name", "category", "ast_pattern"],
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "category": {
                            "type": "string",
                            "enum": [
                                "syscall-elimination",
                                "alloc-reduction",
                                "fast-path-specialization",
                                "algorithmic",
                                "validation-removal",
                                "caching",
                                "dependency-optimization"
                            ]
                        },
                        "ast_pattern": {"type": "string"},
                        "profile_signature": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "steps": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "invariants": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    }
                }
            }
        }
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
