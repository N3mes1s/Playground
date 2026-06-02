//! Core data model shared across the `carve` pipeline.
//!
//! Three artifacts matter:
//!  - [`UsageGraph`]   — the Dependency Functional Usage Graph (DFUG): what code of
//!    each dependency our product actually touches, and from where.
//!  - [`CarveLock`]    — the provenance ledger linking every vendored byte back to the
//!    exact upstream crate/version/file it was transcribed from.
//!  - [`MinimizationPlan`] — the agent's proposal of which dependency items to keep,
//!    derived from the DFUG, before anything is written to `vendor/`.

use serde::{Deserialize, Serialize};

/// The kind of reference a product makes into a dependency. Used to classify
/// edges in the usage graph (a value/fn call vs a type vs a macro invocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefKind {
    /// Value-position path: function call, constant, `Enum::Variant`, etc.
    Value,
    /// Type-position path: a struct/enum/trait used as a type.
    Type,
    /// Macro invocation: `dep::some_macro!(...)`.
    Macro,
    /// Brought into scope via a `use` statement.
    Import,
}

/// A single place in *our* source code that references a dependency item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    /// Path relative to the analyzed crate root, e.g. `src/analyze/scanner.rs`.
    pub file: String,
    pub line: usize,
    pub kind: RefKind,
}

/// One distinct dependency item (a fully-qualified path) and everywhere we use it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemUsage {
    /// Fully-qualified path into the dependency, e.g. `serde_json::to_string`.
    pub path: String,
    /// All product call/reference sites for this item.
    pub references: Vec<SourceRef>,
}

impl ItemUsage {
    pub fn ref_count(&self) -> usize {
        self.references.len()
    }
}

/// All the ways our product touches a single dependency crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateUsage {
    /// Package name as it appears in `Cargo.toml` (may contain hyphens).
    pub name: String,
    /// Resolved version from the lockfile/metadata, if known.
    pub version: Option<String>,
    /// Whether this dependency is reachable from a non-dev target.
    pub is_normal: bool,
    /// Distinct items used, sorted by descending reference count.
    pub items: Vec<ItemUsage>,
}

impl CrateUsage {
    pub fn total_refs(&self) -> usize {
        self.items.iter().map(ItemUsage::ref_count).sum()
    }
}

/// The Dependency Functional Usage Graph for a whole product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageGraph {
    /// The analyzed package name.
    pub package: String,
    /// Absolute path that source references are relative to.
    pub root: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// One entry per dependency crate that is actually referenced.
    pub crates: Vec<CrateUsage>,
    /// Dependency crates declared but with zero observed references — prime
    /// candidates for removal entirely (the cheapest attack-surface win).
    pub unused_declared: Vec<String>,
}

impl UsageGraph {
    pub fn used_crate(&self, name: &str) -> Option<&CrateUsage> {
        self.crates.iter().find(|c| c.name == name)
    }
}

// ---------------------------------------------------------------------------
// Transitive (deep) usage graph — dependencies of dependencies
// ---------------------------------------------------------------------------

/// One crate in the transitive closure, with its distance from the product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TgNode {
    pub name: String,
    pub version: String,
    /// 0 = the product, 1 = a direct dependency, 2+ = dependency-of-dependency.
    pub depth: usize,
}

/// A functional edge: `from` crate references `to` crate, with how much.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepEdge {
    pub from: String,
    pub to: String,
    /// Distinct dependency items the `from` crate references.
    pub items: usize,
    /// Total reference sites.
    pub refs: usize,
}

/// The deep Dependency Functional Usage Graph: usage edges across every level
/// of the dependency tree, not just the product's direct dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitiveGraph {
    pub package: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub nodes: Vec<TgNode>,
    pub edges: Vec<DepEdge>,
    /// How many crates we actually scanned source for.
    pub scanned_crates: usize,
    pub max_depth: usize,
}

// ---------------------------------------------------------------------------
// Provenance ledger
// ---------------------------------------------------------------------------

/// A single transcribed file, hashed so an upgrade can be proof-read as a diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendoredFile {
    /// Path of the vendored copy, relative to the product root.
    pub vendored_path: String,
    /// Original path inside the upstream crate, e.g. `src/lib.rs`.
    pub upstream_path: String,
    /// SHA-256 of the vendored bytes. Must equal the upstream bytes verbatim:
    /// carve copies, it never invents.
    pub sha256: String,
}

/// Everything needed to (a) trust a vendored crate and (b) reverse it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorEntry {
    pub crate_name: String,
    pub version: String,
    /// Upstream source location we transcribed from (registry cache path).
    pub upstream_src: String,
    /// The functional-usage items that justified keeping this crate.
    pub kept_items: Vec<String>,
    pub files: Vec<VendoredFile>,
    pub vendored_at: chrono::DateTime<chrono::Utc>,
    /// Human/agent note recorded at proof-read time.
    pub note: Option<String>,
    /// Upstream modules the slicer proved unneeded and carved away (verified by
    /// compiling the real consumer). Empty until `carve slice` runs.
    #[serde(default)]
    pub removed_modules: Vec<String>,
}

/// The `carve.lock` ledger: the durable link between product and vendored deps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CarveLock {
    pub version: u32,
    pub entries: Vec<VendorEntry>,
}

impl CarveLock {
    pub fn new() -> Self {
        CarveLock {
            version: 1,
            entries: Vec::new(),
        }
    }

    pub fn entry(&self, crate_name: &str) -> Option<&VendorEntry> {
        self.entries.iter().find(|e| e.crate_name == crate_name)
    }

    pub fn upsert(&mut self, entry: VendorEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.crate_name == entry.crate_name)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn remove(&mut self, crate_name: &str) -> Option<VendorEntry> {
        let idx = self.entries.iter().position(|e| e.crate_name == crate_name)?;
        Some(self.entries.remove(idx))
    }
}

// ---------------------------------------------------------------------------
// Agent minimization plan
// ---------------------------------------------------------------------------

/// The agent's proposal for one crate: which items to keep and why. Produced
/// *before* any transcription so a human (or a verification pass) can approve it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateMinimization {
    pub crate_name: String,
    pub version: Option<String>,
    /// Directly-used items (from the DFUG).
    pub entrypoints: Vec<String>,
    /// Estimated transitive intra-crate symbols that must come along for the
    /// entrypoints to compile. Best-effort; verified later by `cargo check`.
    pub transitive_estimate: usize,
    /// Confidence in the slice being complete & compilable without invention.
    pub confidence: Confidence,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Tiny, leaf-like surface — safe to slice at item level.
    High,
    /// Moderate surface — slice but require a verification build.
    Medium,
    /// Heavy macro/generic surface — vendor the whole crate verbatim for now.
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizationPlan {
    pub package: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub crates: Vec<CrateMinimization>,
}

/// Outcome of an agent slicing run over one vendored crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceReport {
    pub crate_name: String,
    pub files_before: usize,
    pub files_after: usize,
    pub loc_before: usize,
    pub loc_after: usize,
    /// Modules the agent carved away (consumer still compiled without them).
    pub removed: Vec<String>,
    /// Modules tried but kept (removing them broke the consumer build).
    pub kept_needed: Vec<String>,
    /// Final `cargo check` of the consumer was green after slicing.
    pub verified: bool,
}

impl SliceReport {
    pub fn loc_reduction_pct(&self) -> f64 {
        if self.loc_before == 0 {
            0.0
        } else {
            100.0 * (self.loc_before - self.loc_after) as f64 / self.loc_before as f64
        }
    }
}

/// A snapshot of a vendored crate's attack surface. Reductions in these are the
/// concrete security payoff of carving.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AttackSurface {
    pub files: usize,
    pub loc: usize,
    pub bytes: u64,
    /// Top-level items (fn/struct/enum/impl/…) — the reachable API+impl surface.
    pub items: usize,
    /// Occurrences of the `unsafe` keyword — memory-safety-relevant surface.
    pub unsafe_blocks: usize,
}

fn pct(before: usize, after: usize) -> f64 {
    if before == 0 {
        0.0
    } else {
        100.0 * (before.saturating_sub(after)) as f64 / before as f64
    }
}

impl AttackSurface {
    pub fn files_pct(&self, after: &AttackSurface) -> f64 {
        pct(self.files, after.files)
    }
    pub fn loc_pct(&self, after: &AttackSurface) -> f64 {
        pct(self.loc, after.loc)
    }
    pub fn bytes_pct(&self, after: &AttackSurface) -> f64 {
        pct(self.bytes as usize, after.bytes as usize)
    }
    pub fn items_pct(&self, after: &AttackSurface) -> f64 {
        pct(self.items, after.items)
    }
    pub fn unsafe_pct(&self, after: &AttackSurface) -> f64 {
        pct(self.unsafe_blocks, after.unsafe_blocks)
    }
}

/// Outcome of an agent *item-level* slicing run (finer than whole modules).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemSliceReport {
    pub crate_name: String,
    pub items_before: usize,
    pub items_removed: usize,
    pub loc_before: usize,
    pub loc_after: usize,
    /// Number of `cargo check` verifications the agent ran.
    pub checks_used: usize,
    pub budget_exhausted: bool,
    pub verified: bool,
}

impl ItemSliceReport {
    pub fn loc_reduction_pct(&self) -> f64 {
        if self.loc_before == 0 {
            0.0
        } else {
            100.0 * (self.loc_before - self.loc_after) as f64 / self.loc_before as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Update-impact analysis ("does this upstream release touch us?")
// ---------------------------------------------------------------------------

/// A vendored-slice file that changed in the target upstream version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedSliceFile {
    pub upstream_path: String,
    /// Top-level item idents whose definition changed/added/removed upstream.
    pub items_changed: Vec<String>,
    /// Of those, the ones that match an item our product actually uses.
    pub affects_used: Vec<String>,
}

/// The answer to "should I take this dependency update?" framed by *our* usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactReport {
    pub crate_name: String,
    pub from_version: String,
    pub to_version: String,
    /// Files that differ across the whole upstream crate, A -> B.
    pub total_changed_files: usize,
    /// Changed files that fall *outside* our vendored slice — these cannot
    /// affect us, which is the whole point of carving.
    pub changed_outside_slice: usize,
    /// Changed files that are inside our slice — the proof-read surface.
    pub changed_in_slice: Vec<ChangedSliceFile>,
    /// Slice files that the target version deleted entirely (API drift).
    pub removed_from_slice: Vec<String>,
    /// Union of used items the update affects.
    pub used_items_affected: Vec<String>,
}

impl ImpactReport {
    /// True if the update changes code we vendored (i.e. requires a proof-read).
    pub fn touches_us(&self) -> bool {
        !self.changed_in_slice.is_empty() || !self.removed_from_slice.is_empty()
    }

    /// True if the update changes code we actually *call*.
    pub fn touches_used_api(&self) -> bool {
        !self.used_items_affected.is_empty()
    }
}
