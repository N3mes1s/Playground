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
use toml_edit::{value, Array, DocumentMut, Item, Table};
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
        // Preserve the original mode bits. This matters for native/sys crates
        // whose build scripts run shipped `configure`/`*.sh` scripts — losing the
        // executable bit silently breaks their C build.
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = std::fs::set_permissions(&dest_file, meta.permissions());
        }
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
        patches: Vec::new(),
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
    use std::collections::HashMap;
    // Files recorded as intentional patches: accept their patched hash instead.
    let patched: HashMap<&str, &str> = entry
        .patches
        .iter()
        .map(|p| (p.vendored_path.as_str(), p.patched_sha256.as_str()))
        .collect();

    let mut problems = Vec::new();
    for f in &entry.files {
        let p = root.join(&f.vendored_path);
        match std::fs::read(&p) {
            Ok(bytes) => {
                let sha = sha256_bytes(&bytes);
                let ok =
                    sha == f.sha256 || patched.get(f.vendored_path.as_str()) == Some(&sha.as_str());
                if !ok {
                    let how = if patched.contains_key(f.vendored_path.as_str()) {
                        "patched file no longer matches its recorded patch"
                    } else {
                        "hash mismatch (undeclared change — run `carve patch` if intentional)"
                    };
                    problems.push(format!("{how}: {}", f.vendored_path));
                }
            }
            Err(_) => problems.push(format!("missing: {}", f.vendored_path)),
        }
    }
    problems
}

/// Scan a vendored crate for files whose bytes differ from the verbatim ledger
/// and record them as intentional patches (CVE hotfix, hardening). Returns the
/// recorded patches; after this, `verify` treats them as deliberate deltas.
pub fn record_patches(
    root: &Path,
    entry: &mut VendorEntry,
    note: Option<String>,
) -> Result<Vec<String>> {
    let mut recorded = Vec::new();
    let known: std::collections::HashMap<String, String> = entry
        .files
        .iter()
        .map(|f| (f.vendored_path.clone(), f.sha256.clone()))
        .collect();
    for (vendored_path, upstream_sha) in &known {
        let p = root.join(vendored_path);
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        let cur = sha256_bytes(&bytes);
        if &cur == upstream_sha {
            continue; // still verbatim
        }
        // Upsert the patch record.
        if let Some(existing) = entry
            .patches
            .iter_mut()
            .find(|x| &x.vendored_path == vendored_path)
        {
            existing.patched_sha256 = cur.clone();
            existing.note = note.clone();
            existing.patched_at = chrono::Utc::now();
        } else {
            entry.patches.push(crate::model::PatchedFile {
                vendored_path: vendored_path.clone(),
                upstream_sha256: upstream_sha.clone(),
                patched_sha256: cur.clone(),
                note: note.clone(),
                patched_at: chrono::Utc::now(),
            });
        }
        recorded.push(vendored_path.clone());
    }
    recorded.sort();
    Ok(recorded)
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

/// A `[patch.crates-io]` entry is keyed by the patch *name*. For a crate present
/// once that name is the crate name; for a crate present at multiple versions we
/// need a distinct key per version (plus `package = "<crate>"` so Cargo still
/// maps it back to the original). This builds that per-version key.
pub fn patch_key(crate_name: &str, version: &str) -> String {
    format!("{crate_name}-{}", version.replace(['.', '+'], "_"))
}

/// Add `[patch.crates-io] <crate> = { path = "vendor/<crate>-<version>" }`.
pub fn apply_patch(root: &Path, crate_name: &str, vendor_rel: &str) -> Result<()> {
    apply_patch_keyed(root, crate_name, crate_name, vendor_rel)
}

/// Add a (possibly renamed) patch entry. When `key == package` this emits the
/// plain `<crate> = { path }` form; otherwise it emits
/// `<key> = { path, package = "<package>" }`, which lets two versions of one
/// crate be patched side by side — Cargo selects the path whose own version
/// satisfies each dependency requirement.
pub fn apply_patch_keyed(root: &Path, key: &str, package: &str, vendor_rel: &str) -> Result<()> {
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
    if key != package {
        entry["package"] = value(package);
    }
    crates_io.insert(key, Item::Table(entry));

    std::fs::write(&manifest, doc.to_string())?;
    Ok(())
}

/// Remove the patch entry for `crate_name`, restoring the registry dependency.
pub fn remove_patch(root: &Path, crate_name: &str) -> Result<bool> {
    let (manifest, mut doc) = read_manifest(root)?;
    let mut removed = false;
    if let Some(patch) = doc.get_mut("patch").and_then(Item::as_table_mut) {
        if let Some(crates_io) = patch.get_mut("crates-io").and_then(Item::as_table_mut) {
            // Drop both the plain entry (key == crate_name) and any renamed
            // per-version entries whose `package` resolves to this crate.
            let to_remove: Vec<String> = crates_io
                .iter()
                .filter(|(k, v)| {
                    *k == crate_name
                        || v.as_table_like()
                            .and_then(|t| t.get("package"))
                            .and_then(Item::as_str)
                            == Some(crate_name)
                })
                .map(|(k, _)| k.to_string())
                .collect();
            for k in &to_remove {
                crates_io.remove(k);
            }
            removed = !to_remove.is_empty();
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

const CARGO_CONFIG: &str = ".cargo/config.toml";

/// Vendoring patches crates to local *paths*, which makes Cargo treat them as
/// first-party code and drop the `--cap-lints=allow` it applies to registry
/// dependencies — so their lints (e.g. `unexpected_cfgs`) fire as errors. We
/// restore registry-dep semantics by adding `--cap-lints=allow` to the project's
/// `.cargo/config.toml`. Reversible via [`clear_cap_lints`].
pub fn ensure_cap_lints(root: &Path) -> Result<()> {
    let p = root.join(CARGO_CONFIG);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut doc = if p.exists() {
        std::fs::read_to_string(&p)?
            .parse::<DocumentMut>()
            .context("parsing .cargo/config.toml")?
    } else {
        DocumentMut::new()
    };
    let build = doc
        .entry("build")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("[build] is not a table"))?;
    let flags = build.entry("rustflags").or_insert(value(Array::new()));
    if let Some(arr) = flags.as_array_mut() {
        let present = arr.iter().any(|v| v.as_str() == Some("--cap-lints"));
        if !present {
            arr.push("--cap-lints");
            arr.push("allow");
        }
    }
    std::fs::write(&p, doc.to_string())?;
    Ok(())
}

/// Remove the `--cap-lints allow` flags carve added (and tidy empty tables/file).
pub fn clear_cap_lints(root: &Path) -> Result<()> {
    let p = root.join(CARGO_CONFIG);
    if !p.exists() {
        return Ok(());
    }
    let mut doc = std::fs::read_to_string(&p)?.parse::<DocumentMut>()?;
    if let Some(build) = doc.get_mut("build").and_then(Item::as_table_mut) {
        if let Some(arr) = build.get_mut("rustflags").and_then(Item::as_array_mut) {
            let kept: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|s| *s != "--cap-lints" && *s != "allow")
                .map(|s| s.to_string())
                .collect();
            if kept.is_empty() {
                build.remove("rustflags");
            } else {
                let mut new = Array::new();
                for s in kept {
                    new.push(s);
                }
                build["rustflags"] = value(new);
            }
        }
        if build.is_empty() {
            doc.as_table_mut().remove("build");
        }
    }
    if doc.as_table().is_empty() {
        std::fs::remove_file(&p).ok();
        // remove now-empty .cargo dir if we own it
        let _ = std::fs::remove_dir(root.join(".cargo"));
    } else {
        std::fs::write(&p, doc.to_string())?;
    }
    Ok(())
}

/// Reverse a vendored crate completely: remove the patch, delete the vendored
/// tree, and drop the lock entry.
#[tracing::instrument]
pub fn restore_crate(root: &Path, crate_name: &str) -> Result<()> {
    let mut lock = load_lock(root)?;
    let dropped = lock.remove_all(crate_name);
    if dropped.is_empty() {
        anyhow::bail!("{crate_name} is not vendored (no carve.lock entry)");
    }

    // Removes the plain entry and every renamed per-version entry for this crate.
    remove_patch(root, crate_name)?;

    for entry in &dropped {
        let dest_rel = format!("{VENDOR_DIR}/{}-{}", entry.crate_name, entry.version);
        let dest = root.join(&dest_rel);
        if dest.exists() {
            std::fs::remove_dir_all(&dest)
                .with_context(|| format!("removing {}", dest.display()))?;
        }
    }
    save_lock(root, &lock)?;
    // Once nothing is vendored, drop the cap-lints shim too.
    if lock.entries.is_empty() {
        clear_cap_lints(root).ok();
    }
    tracing::info!(crate_name, "restored to upstream dependency");
    Ok(())
}

pub fn vendor_rel_path(crate_name: &str, version: &str) -> String {
    format!("{VENDOR_DIR}/{crate_name}-{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch project dir with a minimal manifest, cleaned on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "carve-vendor-test-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("Cargo.toml"),
                "[package]\nname = \"host\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
            )
            .unwrap();
            Scratch(dir)
        }
        fn manifest(&self) -> String {
            std::fs::read_to_string(self.0.join("Cargo.toml")).unwrap()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn patch_key_is_unique_per_version() {
        assert_eq!(patch_key("thiserror", "1.0.69"), "thiserror-1_0_69");
        assert_ne!(
            patch_key("thiserror", "1.0.69"),
            patch_key("thiserror", "2.0.17")
        );
    }

    #[test]
    fn single_version_patch_has_no_package_field() {
        let s = Scratch::new("single");
        apply_patch(&s.0, "itoa", "vendor/itoa-1.0.11").unwrap();
        let m = s.manifest();
        assert!(m.contains("patch.crates-io"));
        assert!(m.contains("itoa"));
        assert!(m.contains("vendor/itoa-1.0.11"));
        assert!(!m.contains("package ="), "plain patch must not be renamed");
    }

    #[test]
    fn two_versions_patch_side_by_side_then_restore_clears_both() {
        let s = Scratch::new("multi");
        apply_patch_keyed(
            &s.0,
            &patch_key("thiserror", "1.0.69"),
            "thiserror",
            "vendor/thiserror-1.0.69",
        )
        .unwrap();
        apply_patch_keyed(
            &s.0,
            &patch_key("thiserror", "2.0.17"),
            "thiserror",
            "vendor/thiserror-2.0.17",
        )
        .unwrap();

        let m = s.manifest();
        assert!(m.contains("thiserror-1_0_69"));
        assert!(m.contains("thiserror-2_0_17"));
        // Both renamed entries map back to the real crate via `package`.
        assert_eq!(m.matches("package = \"thiserror\"").count(), 2);

        // Restore (remove_patch) must drop every per-version entry for the crate.
        let removed = remove_patch(&s.0, "thiserror").unwrap();
        assert!(removed);
        let m = s.manifest();
        assert!(!m.contains("thiserror"));
        assert!(!m.contains("[patch.crates-io]"));
    }
}
