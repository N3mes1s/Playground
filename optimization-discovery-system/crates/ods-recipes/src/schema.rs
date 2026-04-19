use ods_core::OptimizationCategory;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecipeId(pub String);

impl fmt::Display for RecipeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle of a recipe.
///
/// - `Hypothesized` — the Explorer proposed it, nothing has validated it yet.
/// - `Seed`         — hand-authored (or Explorer output that a human blessed).
/// - `Candidate`    — one gate-passing race win.
/// - `Validated`    — ≥3 independent-repo wins, zero rollbacks.
/// - `Corpus`       — shipped default.
/// - `AntiPattern`  — flagged as a target-surfacing signal, never auto-applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionState {
    Hypothesized,
    Seed,
    Candidate,
    Validated,
    Corpus,
    AntiPattern,
}

/// Signature that decides when a recipe applies to a candidate target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    /// Tree-sitter query describing the AST shape this recipe targets.
    pub ast_pattern: String,
    /// Free-form profile signature, e.g. `syscall:stat>N/call`,
    /// `alloc:intermediate-array`, `branch:validation-heavy`.
    pub profile_signature: Vec<String>,
    /// If set, only fire when a naive user alternative outperforms the
    /// primitive by at least this ratio.
    pub naive_alt_ratio_min: Option<f64>,
}

/// Declarative list of rewrite steps. The adapter implements the actual edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transformation {
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRecipe {
    pub test_selectors: Vec<String>,
    pub property_seeds: Vec<u64>,
    pub fuzz_minutes: u32,
    pub semver_check: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessRecord {
    pub repo: String,
    pub commit: String,
    pub speedup: f64,
    pub ci_lower_bound: f64,
    pub merged: bool,
    pub recorded_at: String,
}

/// Counter-evidence for a recipe: a specialist abstained against it, or the
/// race rejected its application, or the attempt timed out. Retrieval uses
/// the length of `negative_history` (optionally within a rolling window) to
/// down-weight recipes that keep failing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeRecord {
    pub repo: String,
    pub target_symbol: String,
    pub outcome: NegativeOutcome,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NegativeOutcome {
    Abstained,
    RejectedByGate,
    NoMeasuredSpeedup,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub id: RecipeId,
    pub name: String,
    pub category: OptimizationCategory,
    pub language: String,
    pub promotion: PromotionState,
    pub trigger: Trigger,
    pub transformation: Transformation,
    pub verification: VerificationRecipe,
    pub benchmark_template: String,
    #[serde(default)]
    pub success_history: Vec<SuccessRecord>,
    /// Counter-evidence accumulated from abstains / rejects. Used by the
    /// retrieval ranker to down-weight recipes that keep failing.
    #[serde(default)]
    pub negative_history: Vec<NegativeRecord>,
    /// If this recipe is the generalized form of another, the id of the
    /// specific recipe it was distilled from.
    #[serde(default)]
    pub generalized_from: Option<RecipeId>,
    /// If this specific recipe has an abstracted / generalized sibling, the
    /// id of that generalized recipe.
    #[serde(default)]
    pub generalized_as: Option<RecipeId>,
    /// Provenance: the run id whose patch produced this (specific) recipe.
    #[serde(default)]
    pub source_patch_ref: Option<String>,
    /// Semantic embedding of (name + trigger + transformation). Populated on
    /// insert; `None` for freshly-authored YAML.
    #[serde(default)]
    pub embedding: Option<Vec<f32>>,
}
