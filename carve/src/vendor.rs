//! Vendoring, provenance, and reversibility.
//!
//! The reversible mechanism is Cargo's own `[patch.crates-io]`: vendoring adds a
//! `crate = { path = "vendor/<crate>" }` patch; restoring removes it. No source
//! edits to the rest of the manifest, so the round-trip is lossless.
//!
//! Stage 1 transcribes the **whole crate verbatim** (byte-identical copy with a
//! SHA-256 ledger). Item-level minimization is the agent's job (see `agent.rs`)
//! and is layered on top of this same provenance machinery — the invariant
//! "every vendored byte traces to an upstream byte" never changes.

use crate::model::{CarveLock, VendorEntry, VendoredFile};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use toml_edit::{value, DocumentMut, Item, Table};
use walkdir::WalkDir;

const LOCK_FILE: &str = "carve.lock";
const VENDOR_DIR: &str = "vendor";

pub fn lock_path(root: &Path) -> PathBuf {
    root.join(LOCK_FILE)
}

pub fn load_lock(root: &Path) -> Result<CarveLock> {
    let p = lock_path(root);
    if !p.exists() {
        return Ok(CarveLock::new());
    }
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    let lock: CarveLock = serde_json::from_str(&text).context("parsing carve.lock")?;
    Ok(lock)
}

pub fn save_lock(root: &Path, lock: &CarveLock) -> Result<()> {
    let p = lock_path(root);
    let text = serde_json::to_string_pretty(lock)?;
    std::fs::write(&p, text).with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Locate the upstream source of `<crate>-<version>` in the local cargo registry
/// cache. Returns the first matching extracted-source directory.
#[tracing::instrument]
pub fn find_registry_src(crate_name: &str, version: &str) -> Result<PathBuf> {
    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs_home().map(|h| h.join(".cargo")))
        .ok_or_else(|| anyhow!("could not determine CARGO_HOME"))?;
    let src_root = cargo_home.join("registry").join("src");
    if !src_root.exists() {
        bail!(
            "registry source cache not found at {} (run `cargo fetch` first)",
            src_root.display()
        );
    }
    let target = format!("{crate_name}-{version}");
    for index_dir in std::fs::read_dir(&src_root)? {
        let index_dir = index_dir?.path();
        let candidate = index_dir.join(&target);
        if candidate.is_dir() {
            tracing::info!(path = %candidate.display(), "found upstream source");
            return Ok(candidate);
        }
    }
    bail!(
        "no extracted source for {target} under {} — run `cargo fetch` to populate it",
        src_root.display()
    )
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Copy the whole crate source verbatim into `vendor/<crate>-<version>/`,
/// building a provenance ledger as we go.
#[tracing::instrument(skip(kept_items, note))]
pub fn vendor_crate(
    root: &Path,
    crate_name: &str,
    version: &str,
    kept_items: Vec<String>,
    note: Option<String>,
) -> Result<VendorEntry> {
    let upstream = find_registry_src(crate_name, version)?;
    let dest_rel = format!("{VENDOR_DIR}/{crate_name}-{version}");
    let dest = root.join(&dest_rel);
    if dest.exists() {
        std::fs::remove_dir_all(&dest).ok();
    }
    std::fs::create_dir_all(&dest)?;

    let mut files = Vec::new();
    for entry in WalkDir::new(&upstream).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let rel = path.strip_prefix(&upstream)?;
        let dest_file = dest.join(rel);
        if let Some(parent) = dest_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = std::fs::read(path)?;
        let sha = sha256_bytes(&bytes);
        std::fs::write(&dest_file, &bytes)?;
        files.push(VendoredFile {
            vendored_path: format!("{dest_rel}/{}", rel.to_string_lossy()),
            upstream_path: rel.to_string_lossy().to_string(),
            sha256: sha,
        });
    }
    tracing::info!(files = files.len(), "transcribed crate verbatim");

    Ok(VendorEntry {
        crate_name: crate_name.to_string(),
        version: version.to_string(),
        upstream_src: upstream.to_string_lossy().to_string(),
        kept_items,
        files,
        vendored_at: chrono::Utc::now(),
        note,
        removed_modules: Vec::new(),
    })
}

/// Re-walk a vendored tree and rebuild its file/hash ledger (used after the
/// agent slices modules away, so `carve verify` keeps matching reality).
pub fn reindex_files(root: &Path, crate_name: &str, version: &str) -> Result<Vec<VendoredFile>> {
    let dest_rel = vendor_rel_path(crate_name, version);
    let dest = root.join(&dest_rel);
    let mut files = Vec::new();
    for entry in WalkDir::new(&dest).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() || path.to_string_lossy().contains("/.carve-trash/") {
            continue;
        }
        let rel = path.strip_prefix(&dest)?;
        let bytes = std::fs::read(path)?;
        files.push(VendoredFile {
            vendored_path: format!("{dest_rel}/{}", rel.to_string_lossy()),
            upstream_path: rel.to_string_lossy().to_string(),
            sha256: sha256_bytes(&bytes),
        });
    }
    Ok(files)
}

/// Re-hash vendored files and confirm they still match the ledger. This is the
/// "proof-read" guarantee: vendored bytes are exactly what we recorded.
pub fn verify_entry(root: &Path, entry: &VendorEntry) -> Vec<String> {
    let mut problems = Vec::new();
    for f in &entry.files {
        let p = root.join(&f.vendored_path);
        match std::fs::read(&p) {
            Ok(bytes) => {
                let sha = sha256_bytes(&bytes);
                if sha != f.sha256 {
                    problems.push(format!("hash mismatch: {}", f.vendored_path));
                }
            }
            Err(_) => problems.push(format!("missing: {}", f.vendored_path)),
        }
    }
    problems
}

// ---------------------------------------------------------------------------
// Reversible Cargo patch management
// ---------------------------------------------------------------------------

fn read_manifest(root: &Path) -> Result<(PathBuf, DocumentMut)> {
    let manifest = root.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let doc = text.parse::<DocumentMut>().context("parsing Cargo.toml")?;
    Ok((manifest, doc))
}

/// Add `[patch.crates-io] <crate> = { path = "vendor/<crate>-<version>" }`.
pub fn apply_patch(root: &Path, crate_name: &str, vendor_rel: &str) -> Result<()> {
    let (manifest, mut doc) = read_manifest(root)?;

    let patch = doc
        .entry("patch")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("[patch] is not a table"))?;
    patch.set_implicit(true);

    let crates_io = patch
        .entry("crates-io")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("[patch.crates-io] is not a table"))?;
    crates_io.set_implicit(true);

    let mut entry = Table::new();
    entry["path"] = value(vendor_rel);
    crates_io.insert(crate_name, Item::Table(entry));

    std::fs::write(&manifest, doc.to_string())?;
    Ok(())
}

/// Remove the patch entry for `crate_name`, restoring the registry dependency.
pub fn remove_patch(root: &Path, crate_name: &str) -> Result<bool> {
    let (manifest, mut doc) = read_manifest(root)?;
    let mut removed = false;
    if let Some(patch) = doc.get_mut("patch").and_then(Item::as_table_mut) {
        if let Some(crates_io) = patch.get_mut("crates-io").and_then(Item::as_table_mut) {
            removed = crates_io.remove(crate_name).is_some();
            if crates_io.is_empty() {
                patch.remove("crates-io");
            }
        }
        if patch.is_empty() {
            doc.as_table_mut().remove("patch");
        }
    }
    if removed {
        std::fs::write(&manifest, doc.to_string())?;
    }
    Ok(removed)
}

/// Reverse a vendored crate completely: remove the patch, delete the vendored
/// tree, and drop the lock entry.
#[tracing::instrument]
pub fn restore_crate(root: &Path, crate_name: &str) -> Result<()> {
    let mut lock = load_lock(root)?;
    let entry = lock
        .remove(crate_name)
        .ok_or_else(|| anyhow!("{crate_name} is not vendored (no carve.lock entry)"))?;

    remove_patch(root, crate_name)?;

    let dest_rel = format!("{VENDOR_DIR}/{}-{}", entry.crate_name, entry.version);
    let dest = root.join(&dest_rel);
    if dest.exists() {
        std::fs::remove_dir_all(&dest)
            .with_context(|| format!("removing {}", dest.display()))?;
    }
    save_lock(root, &lock)?;
    tracing::info!(crate_name, "restored to upstream dependency");
    Ok(())
}

pub fn vendor_rel_path(crate_name: &str, version: &str) -> String {
    format!("{VENDOR_DIR}/{crate_name}-{version}")
}
