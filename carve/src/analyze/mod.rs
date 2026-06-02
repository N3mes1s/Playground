//! Analysis pipeline: metadata + source scan -> [`UsageGraph`].

pub mod metadata;
pub mod scanner;

use crate::model::{CrateUsage, ItemUsage, SourceRef, UsageGraph};
use anyhow::Result;
use std::collections::BTreeMap;
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
            let code_ident = path_str
                .split("::")
                .next()
                .unwrap_or("")
                .to_string();
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
    crates.sort_by(|a, b| b.total_refs().cmp(&a.total_refs()).then(a.name.cmp(&b.name)));

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

fn is_rust_source(path: &Path) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return false;
    }
    // Skip anything already vendored or in build output.
    let s = path.to_string_lossy();
    !s.contains("/target/") && !s.contains("/vendor/")
}
