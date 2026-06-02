//! Mechanical helpers for module-level slicing.
//!
//! These are *pure mechanics*: find file-backed `mod` declarations, resolve the
//! file/dir they point at, and delete a declaration verbatim (attributes
//! included). The *decisions* — what to try removing and whether to keep a
//! removal — belong to the agent (see `agent.rs`), which gates every cut on a
//! real `cargo check` of the consuming product. Nothing here invents code; it
//! only removes whole upstream modules and reverts anything that doesn't compile.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use walkdir::WalkDir;

const TRASH: &str = ".carve-trash";

/// A removable file-backed module: where it is declared and what it points at.
#[derive(Debug, Clone)]
pub struct ModCandidate {
    /// The `.rs` file containing the `mod <name>;` declaration.
    pub decl_file: PathBuf,
    pub name: String,
    /// The file or directory that *is* the module (deleted on a successful cut).
    pub target: PathBuf,
    /// Display name relative to the vendor root, e.g. `src/arch/aarch64`.
    pub rel_name: String,
    /// Path depth, so the agent can try shallow (bigger) subtrees first.
    pub depth: usize,
}

fn is_rust(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("rs")
        && !path.to_string_lossy().contains(TRASH)
}

/// Discover every file-backed module declaration under `vendor_dir`.
pub fn discover(vendor_dir: &Path) -> Result<Vec<ModCandidate>> {
    let mut out = Vec::new();
    for entry in WalkDir::new(vendor_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| is_rust(e.path()))
    {
        let decl_file = entry.path().to_path_buf();
        let src = std::fs::read_to_string(&decl_file)?;
        let ast = match syn::parse_file(&src) {
            Ok(a) => a,
            Err(_) => continue,
        };
        for item in &ast.items {
            if let syn::Item::Mod(m) = item {
                if m.content.is_some() || m.semi.is_none() {
                    continue; // inline module, nothing to delete from disk
                }
                if m.attrs.iter().any(|a| a.path().is_ident("path")) {
                    continue; // custom #[path] — out of scope, leave it
                }
                let name = m.ident.to_string();
                if let Some(target) = resolve_target(&decl_file, &name) {
                    let rel = target.strip_prefix(vendor_dir).unwrap_or(&target);
                    let rel_name = rel.with_extension("").to_string_lossy().to_string();
                    let depth = rel.components().count();
                    out.push(ModCandidate {
                        decl_file: decl_file.clone(),
                        name,
                        target,
                        rel_name,
                        depth,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Resolve `mod <name>;` declared in `decl_file` to its file or directory.
fn resolve_target(decl_file: &Path, name: &str) -> Option<PathBuf> {
    let stem = decl_file.file_stem()?.to_str()?;
    let parent = decl_file.parent()?;
    let base = if matches!(stem, "lib" | "main" | "mod") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    let file_mod = base.join(format!("{name}.rs"));
    if file_mod.is_file() {
        return Some(file_mod);
    }
    let dir_mod = base.join(name);
    if dir_mod.join("mod.rs").is_file() {
        return Some(dir_mod); // remove the whole directory
    }
    None
}

/// Delete the `mod <name>;` declaration (and its attributes) from `decl_file`,
/// verbatim and in place. Returns the prior file contents for rollback.
pub fn remove_mod_decl(decl_file: &Path, name: &str) -> Result<String> {
    let original = std::fs::read_to_string(decl_file)
        .with_context(|| format!("reading {}", decl_file.display()))?;
    let ast = syn::parse_file(&original).context("parsing for mod removal")?;

    let mut span = None;
    for item in &ast.items {
        if let syn::Item::Mod(m) = item {
            if m.ident == name && m.semi.is_some() && m.content.is_none() {
                let start = m
                    .attrs
                    .iter()
                    .map(|a| a.span().start().line)
                    .min()
                    .unwrap_or_else(|| m.mod_token.span.start().line)
                    .min(m.mod_token.span.start().line);
                let end = m
                    .semi
                    .as_ref()
                    .map(|s| s.span.end().line)
                    .unwrap_or_else(|| m.mod_token.span.end().line);
                span = Some((start, end));
                break;
            }
        }
    }
    let (start, end) = span.context("mod declaration not found for removal")?;

    let kept: Vec<&str> = original
        .lines()
        .enumerate()
        .filter(|(i, _)| {
            let ln = i + 1;
            ln < start || ln > end
        })
        .map(|(_, l)| l)
        .collect();
    let mut out = kept.join("\n");
    out.push('\n');
    std::fs::write(decl_file, out)?;
    Ok(original)
}

// --- snapshot / restore of a module's files via a trash dir ----------------

/// Move `target` aside so a cut can be tried, returning its parked location.
pub fn park(vendor_dir: &Path, target: &Path) -> Result<PathBuf> {
    let trash = vendor_dir.join(TRASH);
    std::fs::create_dir_all(&trash)?;
    let stamp = format!(
        "{}-{}",
        target.file_name().and_then(|s| s.to_str()).unwrap_or("mod"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let parked = trash.join(stamp);
    std::fs::rename(target, &parked)
        .with_context(|| format!("parking {}", target.display()))?;
    Ok(parked)
}

/// Move a parked module back to its original location (rollback).
pub fn unpark(parked: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(parked, target)
        .with_context(|| format!("restoring {}", target.display()))?;
    Ok(())
}

pub fn cleanup_trash(vendor_dir: &Path) {
    let trash = vendor_dir.join(TRASH);
    let _ = std::fs::remove_dir_all(trash);
}

pub fn count_rs_files(vendor_dir: &Path) -> usize {
    WalkDir::new(vendor_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| is_rust(e.path()))
        .count()
}

pub fn count_loc(vendor_dir: &Path) -> usize {
    WalkDir::new(vendor_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| is_rust(e.path()))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .map(|s| s.lines().count())
        .sum()
}
