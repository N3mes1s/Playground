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
    //
    // The LLM produces a tree-sitter S-expression `ast_pattern` which
    // we NEVER upsert without first checking (a) that it compiles
    // against the grammar, and (b) that it actually matches at least
    // one file the winning patch modified. Without this gate every
    // hallucinated pattern would permanently pollute retrieval.
    // Rejections log at WARN with the truncated pattern so operators
    // can see the quality signal.
    let mut generalized_id: Option<RecipeId> = None;
    if let Some(c) = client {
        if let Ok(Some(general)) = run_generalizer(c, winner, target, &recipe.id) {
            match crate::recipe_validate::validate_pattern_compiles(
                &general.language,
                &general.trigger.ast_pattern,
            ) {
                Ok(()) => {
                    let matches_diff =
                        diff_pre_texts(&winner.patch.unified_diff)
                            .iter()
                            .any(|src| {
                                crate::recipe_validate::validate_pattern_matches_source(
                                    &general.language,
                                    &general.trigger.ast_pattern,
                                    src,
                                )
                                .unwrap_or(false)
                            });
                    if matches_diff {
                        store.upsert(&general)?;
                        generalized_id = Some(general.id.clone());
                        recipe.generalized_as = Some(general.id.clone());
                    } else {
                        tracing::warn!(
                            recipe_id = %general.id.0,
                            pattern = %truncate_to(&general.trigger.ast_pattern, 200),
                            "generalizer pattern compiled but did not match the winning diff; rejected"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        recipe_id = %general.id.0,
                        err = %e,
                        pattern = %truncate_to(&general.trigger.ast_pattern, 200),
                        "generalizer produced uncompilable pattern; rejected"
                    );
                }
            }
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
///
/// The prompt is grounded in the actual pre-patch source text: the
/// `ast_pattern` will be validated against exactly that text before
/// upsert, so we tell the model up-front and hand it the text directly.
/// Historical failure mode: ungrounded generalization produced patterns
/// like `(while_expression condition: (call_expression function:
/// (field_expression field: (field_identifier) @n (#match? @n
/// "next|peek"))) ...)` on a piece of code that used `loop { next!(…) }`
/// (a macro invocation, not a method call) — the pattern compiled but
/// matched nothing.
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
        transformation steps in pattern-level language.\n\n\
        CRITICAL: your ast_pattern will be compiled against the grammar \
        and then executed against the PRE-PATCH source text the user \
        hands you. If the query matches zero nodes in that exact text, \
        your recipe is rejected. Ground the pattern in the AST shapes \
        you can SEE in the text — do not invent shapes that sound \
        plausible. If you cannot find a shape that matches, output the \
        empty string `{}` and we keep only the specific recipe.";
    let pre_texts = diff_pre_texts(&winner.patch.unified_diff);
    let pre_source = if pre_texts.is_empty() {
        "(empty diff)".to_string()
    } else {
        // Prefer the largest pre-text block (usually the lib.rs file
        // the patch mutated) and truncate for prompt budget. The model
        // needs to see enough to pick a real AST shape without blowing
        // out context.
        let mut longest = pre_texts
            .iter()
            .max_by_key(|s| s.len())
            .cloned()
            .unwrap_or_default();
        longest = truncate_to(&longest, 6000);
        longest
    };
    let hints = tree_sitter_hints_for(&target.language);
    let user = format!(
        "Target that was sped up: {}::{}::{}\n\
         Winning specialist: {:?}\n\
         Rationale from specialist:\n{}\n\n\
         Patch diff (the `-` lines are what you must match against):\n{}\n\n\
         PRE-PATCH SOURCE of the main file the patch modifies — your \
         ast_pattern will be validated against THIS text verbatim:\n\
         ```{}\n{}\n```\n\n\
         {}\n\n\
         Produce a JSON object matching this schema (no commentary, no fences). \
         If no reusable pattern grounded in the source above exists, output \
         exactly `{{}}` and nothing else:\n\
         {{\n\
           \"id\": \"general-<short-slug-you-pick>\",\n\
           \"name\": \"<pattern name, no repo names>\",\n\
           \"category\": \"<one of: syscall-elimination, alloc-reduction, \
             fast-path-specialization, algorithmic, validation-removal, \
             caching, dependency-optimization>\",\n\
           \"language\": \"{}\",\n\
           \"ast_pattern\": \"<tree-sitter S-expression query that MATCHES \
             AT LEAST ONE NODE in the pre-patch source above; include at \
             least one @capture>\",\n\
           \"profile_signature\": [\"<e.g. hot:per-byte-dispatch>\"],\n\
           \"steps\": [\"<ordered transformation steps, pattern-level>\"],\n\
           \"invariants\": [\"<semantic invariants to preserve>\"]\n\
         }}",
        target.language,
        target.module,
        target.symbol,
        winner.outcome.kind,
        truncate_to(&winner.outcome.rationale, 1200),
        truncate_to(&winner.patch.unified_diff, 2000),
        target.language,
        pre_source,
        hints,
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
    // Empty-object escape: the prompt tells the model to return `{}`
    // when it can't find a pattern grounded in the pre-patch source.
    // Treat that as "no generalization" rather than a parse error.
    if json.trim() == "{}" {
        tracing::info!(
            specific = %specific_id.0,
            "generalizer returned empty object; keeping only the specific recipe"
        );
        return Ok(None);
    }
    parse_generalized_recipe(&json, target, specific_id).map(Some)
}

fn truncate_to(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Language-specific tree-sitter node-name cheatsheet handed to the
/// Generalizer. Grounds it in the actual grammar names so it doesn't
/// invent plausible-sounding nodes like `while_statement` (wrong for
/// rust) or `for_loop` (wrong for go). The list is minimal — just the
/// shapes most commonly seen in optimization patterns. The model has
/// the full pre-patch source to check against, so this is a nudge,
/// not a constraint.
fn tree_sitter_hints_for(language: &str) -> &'static str {
    match language {
        "rust" => "tree-sitter-rust node cheatsheet (names you may use):\n\
                   - Loops: `(loop_expression body: (block) @b)`, \
                   `(for_expression ...)`, `(while_expression ...)`\n\
                   - Control flow: `(match_expression value: (_) body: (match_block ...))`, \
                   `(if_expression ...)`, `(if_let_expression ...)`\n\
                   - Calls: `(call_expression function: (field_expression ...))` \
                   for method calls; `(call_expression function: (scoped_identifier \
                   path: (identifier) @p name: (identifier) @n))` for `Foo::bar(…)`\n\
                   - Macro calls: `(macro_invocation macro: (identifier) @m)` \
                   — this is what `next!()`, `vec![]`, `assert!()` look like, \
                   NOT a `call_expression`\n\
                   - Returns: `(return_expression value: (_) @v)`\n\
                   - Attributes: `(attribute_item (attribute (identifier) @attr))`, \
                   `(inner_attribute_item ...)`\n\
                   - Literals: `(integer_literal)`, `(string_literal)`, \
                   `(boolean_literal)`, `(char_literal)`\n\
                   - Types: `(generic_type type: (type_identifier) @t)`, \
                   `(reference_type)`, `(primitive_type)`\n\
                   - Patterns: `(match_arm pattern: (_) @p value: (_) @v)`, \
                   `(range_pattern)`\n\
                   - Function defs: `(function_item name: (identifier) @n \
                   parameters: (parameters) body: (block) @b)`\n\
                   - Common predicates: `(#eq? @cap \"literal\")`, \
                   `(#match? @cap \"regex\")`, `(#not-eq? @cap \"x\")`",
        "python" => "tree-sitter-python node cheatsheet:\n\
                     - Loops: `(for_statement body: (block) @b)`, \
                     `(while_statement body: (block))`\n\
                     - Functions: `(function_definition name: (identifier) @n \
                     body: (block))`\n\
                     - Calls: `(call function: (attribute) @a)` for method calls, \
                     `(call function: (identifier) @n)` for bare calls\n\
                     - Decorators: `(decorator (identifier) @dec)`\n\
                     - Class defs: `(class_definition name: (identifier) @n)`\n\
                     - Comprehensions: `(list_comprehension)`, \
                     `(dictionary_comprehension)`, `(generator_expression)`",
        "go" => "tree-sitter-go node cheatsheet:\n\
                 - Loops: `(for_statement)`, `(range_clause)`\n\
                 - Calls: `(call_expression function: (selector_expression) @sel)`, \
                 `(call_expression function: (identifier) @n)`\n\
                 - Defer: `(defer_statement)`\n\
                 - Goroutines: `(go_statement)`\n\
                 - Composite literals: `(composite_literal type: (_))` — \
                 `[]T{...}`, `map[K]V{...}` etc.\n\
                 - Short decl: `(short_var_declaration left: (expression_list) \
                 right: (expression_list))`",
        "ruby" => "tree-sitter-ruby node cheatsheet:\n\
                   - Methods: `(method name: (identifier) @n)`\n\
                   - Calls: `(call receiver: (_)? method: (identifier) @m)`\n\
                   - Blocks: `(block)`, `(do_block body: (body_statement))` — \
                   block uses `block_body`, do-block uses `body_statement`\n\
                   - Conditionals: `(if condition: (_) consequence: (then))`, \
                   `(while condition: (_))`\n\
                   - Array/hash literals: `(array)`, `(hash)`",
        _ => "(no language-specific cheatsheet; match only nodes you can see \
              in the pre-patch source block above)",
    }
}

/// Reconstruct the "before" text of every file touched by a unified
/// diff. Used by the Generalizer validation gate to confirm a proposed
/// pattern actually matches the source the diff describes — a tighter
/// bar than "the pattern compiles."
///
/// Walks hunks and stitches together each file's context + `-` lines
/// (the lines that existed PRE-patch). Skips `+++` lines. Returns one
/// String per file.
fn diff_pre_texts(diff: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for line in diff.lines() {
        if line.starts_with("--- ") {
            if let Some(s) = current.take() {
                out.push(s);
            }
            current = Some(String::new());
        } else if line.starts_with("+++ ")
            || line.starts_with("diff --git")
            || line.starts_with("index ")
        {
            // headers — ignore
        } else if line.starts_with("@@") {
            // hunk header — insert a blank separator so the
            // reconstructed text has consistent line boundaries
            // between hunks even if their ranges weren't contiguous.
            if let Some(s) = current.as_mut() {
                if !s.is_empty() && !s.ends_with('\n') {
                    s.push('\n');
                }
            }
        } else if let Some(body) = line.strip_prefix(' ') {
            if let Some(s) = current.as_mut() {
                s.push_str(body);
                s.push('\n');
            }
        } else if let Some(body) = line.strip_prefix('-') {
            // `-` (remove) lines existed PRE-patch, so they belong.
            if !body.starts_with("-- ") {
                if let Some(s) = current.as_mut() {
                    s.push_str(body);
                    s.push('\n');
                }
            }
        }
        // `+` (additions) are post-patch and get dropped.
    }
    if let Some(s) = current.take() {
        out.push(s);
    }
    out
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

    #[test]
    fn tree_sitter_hints_are_language_specific() {
        let rust_hints = tree_sitter_hints_for("rust");
        assert!(rust_hints.contains("macro_invocation"));
        assert!(rust_hints.contains("loop_expression"));
        let python_hints = tree_sitter_hints_for("python");
        assert!(python_hints.contains("function_definition"));
        let go_hints = tree_sitter_hints_for("go");
        assert!(go_hints.contains("defer_statement"));
        let ruby_hints = tree_sitter_hints_for("ruby");
        assert!(ruby_hints.contains("do_block"));
        let unknown = tree_sitter_hints_for("klingon");
        assert!(unknown.contains("no language-specific"));
    }

    #[test]
    fn diff_pre_texts_extracts_minus_and_context_lines() {
        // Minimal unified diff: one context line, one removed line,
        // one added line. Pre-text should contain context + removed
        // but NOT the added line.
        // NOTE: hand-built; line-continuations eat leading whitespace.
        let diff = concat!(
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -1,3 +1,3 @@\n",
            " keep_me\n",
            "-remove_me\n",
            "+add_me\n",
        );
        let pre = diff_pre_texts(diff);
        assert_eq!(pre.len(), 1);
        let text = &pre[0];
        assert!(text.contains("keep_me"), "expected context: got {text:?}");
        assert!(text.contains("remove_me"), "expected removed: got {text:?}");
        assert!(
            !text.contains("add_me"),
            "added line must not leak into pre-text: {text:?}"
        );
    }
}
