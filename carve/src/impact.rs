//! Update-impact analysis.
//!
//! The supply-chain payoff of carving: when an upstream release drops, most of
//! its diff lands in code you never vendored. This module diffs the target
//! version against the version we vendored and answers, framed by *our* usage:
//!  - how many files changed across the whole crate,
//!  - how many of those are inside our slice (the only ones that can touch us),
//!  - and which of *those* changes hit items our product actually calls.
//!
//! A release that changes 40 files but none in your slice is safe to bump; one
//! that touches a file you call demands a proof-read of a bounded diff.

use crate::model::{ChangedSliceFile, ImpactReport, VendorEntry};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Ensure the extracted source for `<crate>-<version>` exists in the registry
/// cache, fetching it through a throwaway project if necessary.
#[tracing::instrument]
pub fn ensure_src(crate_name: &str, version: &str) -> Result<PathBuf> {
    if let Ok(p) = crate::vendor::find_registry_src(crate_name, version) {
        return Ok(p);
    }
    tracing::info!("source not cached; fetching via a scratch project");
    let dir = std::env::temp_dir().join(format!("carve-fetch-{crate_name}-{version}"));
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"carve_fetch\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{crate_name} = \"={version}\"\n"
        ),
    )?;
    std::fs::write(dir.join("src/lib.rs"), "")?;
    let out = Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .output()
        .context("spawning cargo build to fetch source")?;
    if !out.status.success() {
        anyhow::bail!(
            "could not fetch {crate_name} v{version}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    crate::vendor::find_registry_src(crate_name, version)
}

/// Map each top-level item ident in a Rust file to a fingerprint of its
/// definition (structural Debug, so whitespace/comments are ignored).
fn item_fingerprints(src: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    let Ok(ast) = syn::parse_file(src) else {
        return map;
    };
    for item in &ast.items {
        if let Some(name) = item_name(item) {
            let fp = fnv(&format!("{item:?}"));
            // Multiple items can share a name (e.g. impls); fold them together.
            let e = map.entry(name).or_insert(0u64);
            *e ^= fp;
        }
    }
    map
}

fn item_name(item: &syn::Item) -> Option<String> {
    use syn::Item::*;
    Some(match item {
        Fn(i) => i.sig.ident.to_string(),
        Struct(i) => i.ident.to_string(),
        Enum(i) => i.ident.to_string(),
        Trait(i) => i.ident.to_string(),
        Type(i) => i.ident.to_string(),
        Const(i) => i.ident.to_string(),
        Static(i) => i.ident.to_string(),
        Mod(i) => i.ident.to_string(),
        Union(i) => i.ident.to_string(),
        Macro(i) => i.ident.as_ref()?.to_string(),
        Impl(i) => format!("impl::{}", type_ident(&i.self_ty)),
        _ => return None,
    })
}

fn type_ident(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        _ => "_".to_string(),
    }
}

fn fnv(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Compute the impact of moving `entry` (our vendored slice) to `to_version`.
#[tracing::instrument(skip(entry), fields(crate_name = %entry.crate_name))]
pub fn analyze(entry: &VendorEntry, to_version: &str) -> Result<ImpactReport> {
    let from_version = entry.version.clone();
    let from_src = crate::vendor::find_registry_src(&entry.crate_name, &from_version)
        .context("locating the from-version source (the version we vendored)")?;
    let to_src = ensure_src(&entry.crate_name, to_version)?;

    // The set of upstream paths we actually vendored (post-slice).
    let slice: BTreeSet<String> = entry
        .files
        .iter()
        .map(|f| f.upstream_path.clone())
        .collect();

    // Leaf + intermediate segments of the items we use, for API-impact matching.
    let used_segments: BTreeSet<String> = entry
        .kept_items
        .iter()
        .flat_map(|p| p.split("::").skip(1).map(|s| s.to_string()))
        .collect();

    // Index .rs files on both sides by their crate-relative path.
    let from_files = index_rs(&from_src);
    let to_files = index_rs(&to_src);

    let mut total_changed_files = 0usize;
    let mut changed_outside_slice = 0usize;
    let mut changed_in_slice = Vec::new();
    let mut removed_from_slice = Vec::new();
    let mut used_items_affected: BTreeSet<String> = BTreeSet::new();

    let all_paths: BTreeSet<&String> = from_files.keys().chain(to_files.keys()).collect();
    for path in all_paths {
        let before = from_files.get(path);
        let after = to_files.get(path);
        let changed = match (before, after) {
            (Some(a), Some(b)) => fnv(a) != fnv(b),
            _ => true, // added or removed file
        };
        if !changed {
            continue;
        }
        total_changed_files += 1;

        if !slice.contains(path) {
            changed_outside_slice += 1;
            continue; // outside our slice — cannot affect us
        }

        // In-slice change: pinpoint which items moved and whether we call them.
        if after.is_none() {
            removed_from_slice.push(path.clone());
            continue;
        }
        let fa = item_fingerprints(before.map(String::as_str).unwrap_or(""));
        let fb = item_fingerprints(after.map(String::as_str).unwrap_or(""));
        let mut items_changed = Vec::new();
        let names: BTreeSet<&String> = fa.keys().chain(fb.keys()).collect();
        for name in names {
            if fa.get(name) != fb.get(name) {
                items_changed.push(name.clone());
            }
        }
        let affects_used: Vec<String> = items_changed
            .iter()
            .filter(|n| used_segments.contains(n.as_str()))
            .cloned()
            .collect();
        for a in &affects_used {
            used_items_affected.insert(a.clone());
        }
        changed_in_slice.push(ChangedSliceFile {
            upstream_path: path.clone(),
            items_changed,
            affects_used,
        });
    }

    Ok(ImpactReport {
        crate_name: entry.crate_name.clone(),
        from_version,
        to_version: to_version.to_string(),
        total_changed_files,
        changed_outside_slice,
        changed_in_slice,
        removed_from_slice,
        used_items_affected: used_items_affected.into_iter().collect(),
    })
}

fn index_rs(root: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
    {
        if let Ok(rel) = entry.path().strip_prefix(root) {
            if let Ok(src) = std::fs::read_to_string(entry.path()) {
                map.insert(rel.to_string_lossy().to_string(), src);
            }
        }
    }
    map
}

/// Produce a unified diff (via system `diff -u`) of each in-slice file that the
/// target version changes — the exact, bounded code to proof-read before a bump.
pub fn unified_diffs(
    entry: &VendorEntry,
    to_version: &str,
    report: &ImpactReport,
) -> Result<Vec<(String, String)>> {
    let from_src = crate::vendor::find_registry_src(&entry.crate_name, &entry.version)?;
    let to_src = ensure_src(&entry.crate_name, to_version)?;
    let mut out = Vec::new();
    for f in &report.changed_in_slice {
        let a = from_src.join(&f.upstream_path);
        let b = to_src.join(&f.upstream_path);
        let text = std::process::Command::new("diff")
            .arg("-u")
            .arg(&a)
            .arg(&b)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        out.push((f.upstream_path.clone(), text));
    }
    Ok(out)
}
