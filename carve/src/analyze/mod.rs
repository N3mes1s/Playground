//! Analysis pipeline: metadata + source scan -> [`UsageGraph`].

pub mod metadata;
pub mod scanner;

use crate::model::{
    CrateUsage, DepEdge, ItemUsage, SourceRef, TgNode, TransitiveGraph, UsageGraph,
};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use walkdir::WalkDir;

/// Build the Dependency Functional Usage Graph for the crate at `manifest_path`.
#[tracing::instrument(skip_all)]
pub fn build_usage_graph(manifest_path: impl AsRef<Path>) -> Result<UsageGraph> {
    let meta = metadata::load(&manifest_path)?;
    let root = Path::new(&meta.root_dir);

    // Aggregate per-dependency-path references across the whole source tree.
    // Map: code_ident -> (fully-qualified path -> refs)
    let mut per_crate: BTreeMap<String, BTreeMap<String, Vec<SourceRef>>> = BTreeMap::new();

    let mut scanned = 0usize;
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| is_rust_source(e.path()))
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(file = %rel, error = %e, "skipping unreadable file");
                continue;
            }
        };
        let result = match scanner::scan_file(&src, &rel, &meta.deps) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(file = %rel, error = %e, "skipping unparseable file");
                continue;
            }
        };
        scanned += 1;

        for (path_str, hits) in result.hits {
            let code_ident = path_str.split("::").next().unwrap_or("").to_string();
            per_crate
                .entry(code_ident)
                .or_default()
                .entry(path_str)
                .or_default()
                .extend(hits.refs);
        }
    }
    tracing::info!(files = scanned, "scanned source tree");

    // Assemble CrateUsage entries, sorted by reference volume.
    let mut crates = Vec::new();
    for (code_ident, paths) in per_crate {
        let dep = meta.deps.get(&code_ident);
        let mut items: Vec<ItemUsage> = paths
            .into_iter()
            .map(|(path, references)| ItemUsage { path, references })
            .collect();
        items.sort_by(|a, b| b.ref_count().cmp(&a.ref_count()).then(a.path.cmp(&b.path)));

        crates.push(CrateUsage {
            name: dep.map(|d| d.package.clone()).unwrap_or(code_ident),
            version: dep.and_then(|d| d.version.clone()),
            is_normal: dep.map(|d| d.is_normal).unwrap_or(true),
            items,
        });
    }
    crates.sort_by(|a, b| {
        b.total_refs()
            .cmp(&a.total_refs())
            .then(a.name.cmp(&b.name))
    });

    // Declared-but-unreferenced deps: the cheapest attack-surface reduction.
    let used_idents: std::collections::HashSet<String> = crates
        .iter()
        .map(|c| metadata::normalize_ident(&c.name))
        .collect();
    let mut unused_declared: Vec<String> = meta
        .deps
        .values()
        .filter(|d| !used_idents.contains(&d.code_ident))
        .map(|d| d.package.clone())
        .collect();
    unused_declared.sort();
    unused_declared.dedup();

    Ok(UsageGraph {
        package: meta.package_name,
        root: meta.root_dir,
        generated_at: chrono::Utc::now(),
        crates,
        unused_declared,
    })
}

/// Build the **deep** usage graph: scan the product *and every crate in its
/// transitive closure* for how each one uses its own dependencies. This exposes
/// the dependencies-of-dependencies structure with real functional edges.
#[tracing::instrument(skip_all)]
pub fn build_transitive_usage(manifest_path: impl AsRef<Path>) -> Result<TransitiveGraph> {
    let manifest_path = manifest_path.as_ref();
    let meta = metadata::load_metadata(manifest_path)?;
    let root = meta
        .root_package()
        .context("no root package; point at a crate, not a virtual workspace")?;
    let closure = metadata::build_closure(&meta)?;
    let runtime = metadata::runtime_closure(&meta)?;

    let mut nodes = vec![TgNode {
        name: root.name.clone(),
        version: root.version.to_string(),
        depth: 0,
        runtime: true,
    }];
    let mut edges = Vec::new();
    let mut scanned = 0usize;

    // Level 0: the product itself.
    let root_dir = std::fs::canonicalize(manifest_path)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    edges.extend(scan_crate_edges(
        &root.name,
        &root_dir,
        &metadata::deps_of(&meta, root),
    ));
    scanned += 1;

    // Levels 1..n: each crate in the closure, scanned against its own deps.
    for node in &closure {
        nodes.push(TgNode {
            name: node.name.clone(),
            version: node.version.clone(),
            depth: node.depth,
            runtime: runtime.contains(&node.name),
        });
        let Some(src) = &node.src_dir else { continue };
        let Some(pkg) = meta
            .packages
            .iter()
            .find(|p| p.name == node.name && p.version.to_string() == node.version)
        else {
            continue;
        };
        edges.extend(scan_crate_edges(
            &node.name,
            src,
            &metadata::deps_of(&meta, pkg),
        ));
        scanned += 1;
    }

    let max_depth = nodes.iter().map(|n| n.depth).max().unwrap_or(0);
    tracing::info!(
        nodes = nodes.len(),
        edges = edges.len(),
        max_depth,
        "built transitive graph"
    );
    Ok(TransitiveGraph {
        package: root.name.clone(),
        generated_at: chrono::Utc::now(),
        nodes,
        edges,
        scanned_crates: scanned,
        max_depth,
    })
}

/// Scan one crate's source directory and emit one [`DepEdge`] per dependency it
/// actually references.
fn scan_crate_edges(
    from: &str,
    src_dir: &Path,
    deps: &BTreeMap<String, metadata::DepInfo>,
) -> Vec<DepEdge> {
    // to-crate package name -> (distinct item paths, total refs)
    let mut agg: BTreeMap<String, (BTreeSet<String>, usize)> = BTreeMap::new();
    for entry in WalkDir::new(src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| is_rust_source(e.path()))
    {
        let Ok(src) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(result) = scanner::scan_file(&src, "", deps) else {
            continue;
        };
        for (path_str, hits) in result.hits {
            let code_ident = path_str.split("::").next().unwrap_or("").to_string();
            let to = deps
                .get(&code_ident)
                .map(|d| d.package.clone())
                .unwrap_or(code_ident);
            let e = agg.entry(to).or_default();
            e.0.insert(path_str);
            e.1 += hits.refs.len();
        }
    }
    agg.into_iter()
        .map(|(to, (items, refs))| DepEdge {
            from: from.to_string(),
            to,
            items: items.len(),
            refs,
            item_paths: items.into_iter().collect(),
        })
        .collect()
}

fn is_rust_source(path: &Path) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return false;
    }
    // Skip anything already vendored or in build output.
    let s = path.to_string_lossy();
    !s.contains("/target/") && !s.contains("/vendor/")
}
