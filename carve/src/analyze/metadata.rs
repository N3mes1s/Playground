//! Thin wrapper over `cargo metadata` to enumerate a product's declared
//! dependencies and resolve their versions.

use anyhow::{Context, Result};
use cargo_metadata::{DependencyKind, MetadataCommand};
use std::collections::BTreeMap;
use std::path::Path;

/// A declared dependency, with the identifier it is referenced by in source.
#[derive(Debug, Clone)]
pub struct DepInfo {
    /// `Cargo.toml` package name (may contain hyphens).
    pub package: String,
    /// Identifier used in Rust source: rename if any, else package name with
    /// hyphens normalized to underscores. This is what the scanner matches on.
    pub code_ident: String,
    pub version: Option<String>,
    /// True if reachable from a normal (non dev/build) target.
    pub is_normal: bool,
}

/// Result of inspecting a product's manifest.
pub struct ProductMetadata {
    pub package_name: String,
    /// Absolute path to the crate root directory (manifest's parent).
    pub root_dir: String,
    /// Keyed by `code_ident` for fast scanner lookups.
    pub deps: BTreeMap<String, DepInfo>,
}

pub fn normalize_ident(name: &str) -> String {
    name.replace('-', "_")
}

#[tracing::instrument(skip_all, fields(manifest = %manifest_path.as_ref().display()))]
pub fn load(manifest_path: impl AsRef<Path>) -> Result<ProductMetadata> {
    let manifest_path = manifest_path.as_ref();
    // Canonicalize so a bare `Cargo.toml` yields a real parent directory.
    let manifest_path = std::fs::canonicalize(manifest_path)
        .with_context(|| format!("resolving manifest path {}", manifest_path.display()))?;
    let manifest_path = manifest_path.as_path();
    let metadata = MetadataCommand::new()
        .manifest_path(manifest_path)
        .exec()
        .context("running `cargo metadata` (is this a Cargo project?)")?;

    let root = metadata
        .root_package()
        .context("no root package found; point --manifest-path at a crate, not a virtual workspace")?;

    // Build a name -> version lookup from the resolved package set.
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for pkg in &metadata.packages {
        versions
            .entry(pkg.name.clone())
            .or_insert_with(|| pkg.version.to_string());
    }

    let mut deps = BTreeMap::new();
    for dep in &root.dependencies {
        let is_normal = matches!(dep.kind, DependencyKind::Normal);
        let code_ident = dep
            .rename
            .clone()
            .map(|r| normalize_ident(&r))
            .unwrap_or_else(|| normalize_ident(&dep.name));
        let info = DepInfo {
            package: dep.name.clone(),
            code_ident,
            version: versions.get(&dep.name).cloned(),
            is_normal,
        };
        // A package can appear as both a normal and dev dep; prefer the normal flag.
        deps.entry(info.code_ident.clone())
            .and_modify(|e: &mut DepInfo| e.is_normal |= is_normal)
            .or_insert(info);
    }

    let root_dir = manifest_path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());

    tracing::info!(deps = deps.len(), "loaded product metadata");
    Ok(ProductMetadata {
        package_name: root.name.clone(),
        root_dir,
        deps,
    })
}
