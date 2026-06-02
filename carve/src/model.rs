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
