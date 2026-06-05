//! Thin wrapper over `cargo metadata` to enumerate a product's declared
//! dependencies, resolve versions, and walk the transitive resolve graph
//! (dependencies of dependencies).

use anyhow::{Context, Result};
use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package, PackageId};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};

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

/// One crate in the transitive closure, with its distance from the product.
#[derive(Debug, Clone)]
pub struct ClosureNode {
    pub name: String,
    pub version: String,
    /// Shortest dependency distance from the root (1 = direct dep).
    pub depth: usize,
    /// Source directory (registry cache) if it is a crates-io package.
    pub src_dir: Option<PathBuf>,
    /// `links` key set — the crate compiles/links a native library, so its build
    /// can't be reproduced by copying Rust source. We leave these on the registry.
    pub native_link: bool,
}

pub fn normalize_ident(name: &str) -> String {
    name.replace('-', "_")
}

/// Run `cargo metadata` and return the raw result (canonicalizing the manifest).
pub fn load_metadata(manifest_path: impl AsRef<Path>) -> Result<Metadata> {
    let manifest_path = manifest_path.as_ref();
    let manifest_path = std::fs::canonicalize(manifest_path)
        .with_context(|| format!("resolving manifest path {}", manifest_path.display()))?;
    MetadataCommand::new()
        .manifest_path(&manifest_path)
        .exec()
        .context("running `cargo metadata` (is this a Cargo project?)")
}

/// Map a package's declared dependencies to their `code_ident` -> [`DepInfo`].
pub fn deps_of(meta: &Metadata, pkg: &Package) -> BTreeMap<String, DepInfo> {
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for p in &meta.packages {
        versions
            .entry(p.name.clone())
            .or_insert_with(|| p.version.to_string());
    }
    let mut deps = BTreeMap::new();
    for dep in &pkg.dependencies {
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
        deps.entry(info.code_ident.clone())
            .and_modify(|e: &mut DepInfo| e.is_normal |= is_normal)
            .or_insert(info);
    }
    deps
}

#[tracing::instrument(skip_all, fields(manifest = %manifest_path.as_ref().display()))]
pub fn load(manifest_path: impl AsRef<Path>) -> Result<ProductMetadata> {
    let manifest_path = manifest_path.as_ref();
    let metadata = load_metadata(manifest_path)?;
    let root = metadata.root_package().context(
        "no root package found; point --manifest-path at a crate, not a virtual workspace",
    )?;

    let deps = deps_of(&metadata, root);

    let root_dir = std::fs::canonicalize(manifest_path)
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_string_lossy().to_string()))
        .unwrap_or_else(|| ".".to_string());

    tracing::info!(deps = deps.len(), "loaded product metadata");
    Ok(ProductMetadata {
        package_name: root.name.clone(),
        root_dir,
        deps,
    })
}

/// Walk the resolve graph from the root, following normal+build edges only, and
/// return every crates-io package in the closure with its depth. This is the
/// "dependencies of dependencies" set we vendor for full supply-chain isolation.
#[tracing::instrument(skip_all)]
pub fn build_closure(meta: &Metadata) -> Result<Vec<ClosureNode>> {
    let resolve = meta
        .resolve
        .as_ref()
        .context("no resolve graph; run on a real project with a lockfile")?;
    let root = resolve
        .root
        .clone()
        .or_else(|| meta.root_package().map(|p| p.id.clone()))
        .context("no root package in resolve graph")?;

    let nodes: HashMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|n| (&n.id, n)).collect();
    let pkgs: HashMap<&PackageId, &Package> = meta.packages.iter().map(|p| (&p.id, p)).collect();
    let workspace: BTreeSet<&PackageId> = meta.workspace_members.iter().collect();

    // BFS, recording the shallowest depth at which each package is reached.
    let mut depth: HashMap<PackageId, usize> = HashMap::new();
    let mut queue: VecDeque<(PackageId, usize)> = VecDeque::new();
    queue.push_back((root.clone(), 0));
    depth.insert(root.clone(), 0);

    while let Some((id, d)) = queue.pop_front() {
        let Some(node) = nodes.get(&id) else { continue };
        for dep in &node.deps {
            let follow = dep
                .dep_kinds
                .iter()
                .any(|k| matches!(k.kind, DependencyKind::Normal | DependencyKind::Build));
            if !follow {
                continue; // skip dev-dependency subtrees
            }
            let nd = d + 1;
            let entry = depth.entry(dep.pkg.clone()).or_insert(usize::MAX);
            if nd < *entry {
                *entry = nd;
                queue.push_back((dep.pkg.clone(), nd));
            }
        }
    }

    let mut out = Vec::new();
    for (id, d) in depth {
        if d == 0 || workspace.contains(&id) {
            continue; // skip the root and local workspace members
        }
        let Some(pkg) = pkgs.get(&id) else { continue };
        let is_crates_io = pkg
            .source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false);
        if !is_crates_io {
            continue; // only registry packages are vendored from the cache
        }
        out.push(ClosureNode {
            name: pkg.name.clone(),
            version: pkg.version.to_string(),
            depth: d,
            src_dir: crate::vendor::find_registry_src(&pkg.name, &pkg.version.to_string()).ok(),
            native_link: pkg.links.is_some(),
        });
    }
    out.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.name.cmp(&b.name)));
    tracing::info!(packages = out.len(), "computed transitive closure");
    Ok(out)
}
