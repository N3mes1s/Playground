//! Pre-upsert validation gate for LLM-generated recipes.
//!
//! Both the Generalizer (harvest.rs Phase 2) and the Explorer
//! produce Recipe structs from LLM output. Without a gate, any
//! hallucinated `ast_pattern` ends up in the store forever —
//! polluting retrieval and wasting specialist cycles chasing
//! patterns that don't even compile against the language grammar.
//!
//! This module provides two pure helpers:
//!
//! - [`validate_pattern_compiles`] — attempts
//!   `tree_sitter::Query::new` against the grammar for the recipe's
//!   declared language. Cheap; the minimum bar.
//! - [`validate_pattern_matches_source`] — parses a source-file text
//!   with the same grammar and runs the query. Returns true iff the
//!   query produces ≥1 match. Used by the Generalizer path to
//!   confirm a proposed pattern actually fits the diff it claims to
//!   describe — a higher bar than "it compiles."
//!
//! Both are synchronous, do no I/O, and hold no state across calls.

use anyhow::{Context, Result};

/// Compile-check. Returns the tree-sitter error verbatim (useful for
/// logging) when the pattern is malformed, the language is unknown,
/// or the query itself is invalid (e.g. references a non-existent
/// node type). A recipe that fails this check must NEVER be upserted
/// — the whole store's retrieval depends on every pattern being
/// query-compilable.
pub fn validate_pattern_compiles(language: &str, pattern: &str) -> Result<()> {
    let (_, grammar) = crate::discover::language_for_recipe(language)
        .with_context(|| format!("no tree-sitter grammar for language `{language}`"))?;
    tree_sitter::Query::new(&grammar, pattern)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("tree-sitter compile error: {e}"))
}

/// Stricter check: compile + parse + match against `source_text`.
/// Returns `Ok(true)` when the query produces at least one match,
/// `Ok(false)` when it compiles + parses but matches nothing. Errors
/// propagate from the compile/parse path as with
/// [`validate_pattern_compiles`].
pub fn validate_pattern_matches_source(
    language: &str,
    pattern: &str,
    source_text: &str,
) -> Result<bool> {
    let (_, grammar) = crate::discover::language_for_recipe(language)
        .with_context(|| format!("no tree-sitter grammar for language `{language}`"))?;
    let query = tree_sitter::Query::new(&grammar, pattern)
        .map_err(|e| anyhow::anyhow!("tree-sitter compile error: {e}"))?;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&grammar)
        .map_err(|e| anyhow::anyhow!("set_language: {e}"))?;
    let Some(tree) = parser.parse(source_text, None) else {
        anyhow::bail!("tree-sitter failed to parse source text");
    };
    let mut cursor = tree_sitter::QueryCursor::new();
    let bytes = source_text.as_bytes();
    let found = cursor
        .matches(&query, tree.root_node(), bytes)
        .next()
        .is_some();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_accepts_valid_rust_pattern() {
        let ok = validate_pattern_compiles("rust", "(function_item name: (identifier) @n) @match");
        assert!(ok.is_ok(), "expected ok, got {ok:?}");
    }

    #[test]
    fn compile_rejects_malformed_pattern() {
        let err = validate_pattern_compiles("rust", "this is not a tree-sitter query").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("compile error"),
            "expected compile-error msg, got {msg}"
        );
    }

    #[test]
    fn compile_rejects_unknown_language() {
        let err = validate_pattern_compiles("klingon", "(function_item) @m").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no tree-sitter grammar"), "got {msg}");
    }

    #[test]
    fn matches_source_detects_real_hit() {
        let src = "fn foo() { let _ = 1; }\n";
        let hit = validate_pattern_matches_source(
            "rust",
            "(function_item name: (identifier) @n) @match",
            src,
        )
        .unwrap();
        assert!(hit);
    }

    #[test]
    fn matches_source_returns_false_for_no_hit() {
        // Query asks for `struct_item` but the source has only an fn.
        let src = "fn foo() {}\n";
        let hit = validate_pattern_matches_source(
            "rust",
            "(struct_item name: (type_identifier) @n) @match",
            src,
        )
        .unwrap();
        assert!(!hit);
    }

    #[test]
    fn matches_source_propagates_compile_error() {
        let err = validate_pattern_matches_source("rust", "((broken", "fn x() {}").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("compile error"), "got {msg}");
    }

    #[test]
    fn every_shipped_recipe_passes_validator() {
        // Sibling to the `every_shipped_recipe_compiles_as_tree_sitter_query`
        // discover test: guarantees a second, independent caller of the
        // validator stays in sync with the shipped corpus.
        use ods_recipes::schema::Recipe;
        let roots = [
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("recipes/seed"),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("recipes/antipatterns"),
        ];
        let mut checked = 0usize;
        for root in &roots {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let recipe: Recipe = serde_yaml::from_str(&text).unwrap();
                if recipe.trigger.ast_pattern.trim().is_empty() {
                    continue;
                }
                if crate::discover::language_for_recipe(&recipe.language).is_none() {
                    continue; // unsupported-language recipes are skipped
                }
                validate_pattern_compiles(&recipe.language, &recipe.trigger.ast_pattern)
                    .unwrap_or_else(|e| panic!("{}: {e:#}", path.display()));
                checked += 1;
            }
        }
        assert!(checked > 50);
    }
}
