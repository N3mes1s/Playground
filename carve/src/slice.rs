//! Mechanical helpers for module-level slicing.
//!
//! These are *pure mechanics*: find file-backed `mod` declarations, resolve the
//! file/dir they point at, and delete a declaration verbatim (attributes
//! included). The *decisions* — what to try removing and whether to keep a
//! removal — belong to the agent (see `agent.rs`), which gates every cut on a
//! real `cargo check` of the consuming product. Nothing here invents code; it
//! only removes whole upstream modules and reverts anything that doesn't compile.

use anyhow::{Context, Result};
use std::collections::HashSet;
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

// --- item-level slicing mechanics ------------------------------------------

/// A removable top-level item inside a single source file.
#[derive(Debug, Clone)]
pub struct ItemRef {
    pub label: String,
    /// Bare identifier used to match compiler "cannot find `name`" errors
    /// (for impls, the Self type's name). Empty when not name-resolvable.
    pub name: String,
    /// Whether this item can be removed and restored-by-name. `use` items and
    /// impls on non-path types are kept (false) since we can't restore them.
    pub removable: bool,
    /// For `impl` blocks: the method/assoc-fn names it defines (to match
    /// "no method named `m`" errors).
    pub methods: Vec<String>,
    /// For trait impls: the trait name (to match "trait `T` is not implemented").
    pub trait_name: Option<String>,
    pub start: usize,
    pub end: usize,
    /// Hash of the item's own source text — a stable id even as siblings shift.
    pub text_hash: u64,
}

fn fnv(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    use syn::Item::*;
    match item {
        Fn(i) => &i.attrs,
        Struct(i) => &i.attrs,
        Enum(i) => &i.attrs,
        Trait(i) => &i.attrs,
        TraitAlias(i) => &i.attrs,
        Type(i) => &i.attrs,
        Const(i) => &i.attrs,
        Static(i) => &i.attrs,
        Union(i) => &i.attrs,
        Impl(i) => &i.attrs,
        Macro(i) => &i.attrs,
        Use(i) => &i.attrs,
        ForeignMod(i) => &i.attrs,
        ExternCrate(i) => &i.attrs,
        _ => &[],
    }
}

/// Returns `(label, bare_name, removable)` for a top-level item.
fn classify_item(item: &syn::Item) -> Option<(String, String, bool)> {
    use syn::Item::*;
    let (label, name) = match item {
        Fn(i) => (format!("fn {}", i.sig.ident), i.sig.ident.to_string()),
        Struct(i) => (format!("struct {}", i.ident), i.ident.to_string()),
        Enum(i) => (format!("enum {}", i.ident), i.ident.to_string()),
        Trait(i) => (format!("trait {}", i.ident), i.ident.to_string()),
        Type(i) => (format!("type {}", i.ident), i.ident.to_string()),
        Const(i) => (format!("const {}", i.ident), i.ident.to_string()),
        Static(i) => (format!("static {}", i.ident), i.ident.to_string()),
        Union(i) => (format!("union {}", i.ident), i.ident.to_string()),
        Impl(i) => (
            format!("impl {}", type_name(&i.self_ty)),
            type_name(&i.self_ty),
        ),
        Macro(i) => {
            let n = i.ident.as_ref().map(|x| x.to_string()).unwrap_or_default();
            (format!("macro {n}"), n)
        }
        Use(_) => ("use".to_string(), String::new()),
        _ => return None,
    };
    // Removable iff we can later restore it by matching a compiler error to its
    // name. `use` (no name) and impls on non-path types ("_") are kept.
    let removable = !name.is_empty() && name != "_";
    Some((label, name, removable))
}

fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        _ => "_".into(),
    }
}

/// List the removable top-level items in a file, with stable text hashes.
pub fn list_items(file: &Path) -> Result<Vec<ItemRef>> {
    let src =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let ast = match syn::parse_file(&src) {
        Ok(a) => a,
        Err(_) => return Ok(Vec::new()),
    };
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for item in &ast.items {
        let Some((label, name, removable)) = classify_item(item) else {
            continue;
        };
        let body_start = item.span().start().line;
        let start = item_attrs(item)
            .iter()
            .map(|a| a.span().start().line)
            .min()
            .map(|x| x.min(body_start))
            .unwrap_or(body_start);
        let end = item.span().end().line;
        if start == 0 || end < start || end > lines.len() {
            continue;
        }
        let text = lines[start - 1..end].join("\n");
        let (methods, trait_name) = match item {
            syn::Item::Impl(i) => {
                let methods = i
                    .items
                    .iter()
                    .filter_map(|ii| match ii {
                        syn::ImplItem::Fn(f) => Some(f.sig.ident.to_string()),
                        syn::ImplItem::Const(c) => Some(c.ident.to_string()),
                        _ => None,
                    })
                    .collect();
                let trait_name = i
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| path.segments.last())
                    .map(|s| s.ident.to_string());
                (methods, trait_name)
            }
            _ => (Vec::new(), None),
        };
        out.push(ItemRef {
            label,
            name,
            removable,
            methods,
            trait_name,
            start,
            end,
            text_hash: fnv(&text),
        });
    }
    Ok(out)
}

/// Render a file from its ORIGINAL source with the given items removed (by text
/// hash). Rendering from the original keeps item spans stable no matter how many
/// items are removed, so we can add/restore removals freely and re-render.
pub fn render_without(original: &str, items: &[ItemRef], removed: &HashSet<u64>) -> String {
    let lines: Vec<&str> = original.lines().collect();
    // Mark removed line ranges.
    let mut drop = vec![false; lines.len() + 1];
    for it in items {
        if removed.contains(&it.text_hash) {
            let end = it.end.min(lines.len());
            if it.start <= end {
                drop[it.start..=end].fill(true);
            }
        }
    }
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if !drop[i + 1] {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// All back-ticked path-segment identifiers appearing on `error` lines. Used as
/// a loose fallback when precise parsing can't map an error to a definition.
pub fn error_idents(stderr: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in stderr.lines() {
        if !line.contains(": error") && !line.contains("error[") && !line.contains("error:") {
            continue;
        }
        for tok in backticked(line) {
            for seg in tok.split("::") {
                let id: String = seg
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !id.is_empty() {
                    out.insert(id);
                }
            }
        }
    }
    out
}

/// The module path a source file defines, e.g. `src/arch/all/memchr.rs` →
/// `["arch","all","memchr"]`, `src/lib.rs` → `[]`, `src/x/mod.rs` → `["x"]`.
pub fn module_of_path(path: &str) -> Vec<String> {
    let rel = if let Some(i) = path.find("/src/") {
        &path[i + 5..]
    } else if let Some(r) = path.strip_prefix("src/") {
        r
    } else {
        path
    };
    let rel = rel.split(':').next().unwrap_or(rel); // drop any :line:col
    let rel = rel.strip_suffix(".rs").unwrap_or(rel);
    let mut segs: Vec<String> = rel
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if segs.last().map(|s| s == "mod").unwrap_or(false) {
        segs.pop();
    }
    if segs.len() == 1 && (segs[0] == "lib" || segs[0] == "main") {
        segs.clear();
    }
    segs
}

/// A symbol the live code still needs, with the module context it was looked up
/// in — so we restore the *right* definition when a bare name exists in several
/// modules (e.g. one `memchr_raw` per CPU backend).
#[derive(Debug, Clone)]
pub struct Wanted {
    pub name: String,
    pub context: Vec<String>,
}

fn ident_prefix(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

fn is_path_root(seg: &str) -> bool {
    matches!(
        seg,
        "crate" | "self" | "super" | "std" | "core" | "alloc" | ""
    )
}

fn path_segments(token: &str) -> Vec<String> {
    token
        .split("::")
        .map(ident_prefix)
        .filter(|s| !is_path_root(s))
        .collect()
}

fn backticked(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(s) = line[i..].find('`') {
        let start = i + s + 1;
        if let Some(e) = line[start..].find('`') {
            out.push(line[start..start + e].to_string());
            i = start + e + 1;
        } else {
            break;
        }
    }
    out
}

/// Parse rustc errors into `(name, context-module)` wants. Uses the module named
/// in the error ("in module `crate::a::b`", "unresolved import `crate::a::b::C`")
/// when present, else the error's own source file module.
pub fn extract_wanted(stderr: &str) -> Vec<Wanted> {
    let mut out = Vec::new();
    for line in stderr.lines() {
        if !line.contains(": error") && !line.contains("error[") && !line.contains("error:") {
            continue;
        }
        let ctx_file = module_of_path(line);
        let toks = backticked(line);

        if let Some(pos) = line.find("in module `") {
            let modstr = &line[pos + "in module `".len()..];
            let modtok = modstr.split('`').next().unwrap_or("");
            let context = path_segments(modtok);
            if let Some(name) = toks.iter().map(|t| ident_prefix(t)).find(|t| !t.is_empty()) {
                out.push(Wanted { name, context });
                continue;
            }
        }
        if line.contains("unresolved import") || line.contains("failed to resolve") {
            if let Some(t) = toks.iter().find(|t| t.contains("::")) {
                let segs = path_segments(t);
                if let Some((name, ctx)) = segs.split_last() {
                    out.push(Wanted {
                        name: name.clone(),
                        context: ctx.to_vec(),
                    });
                    continue;
                }
            }
        }
        for t in &toks {
            if t.contains("::") {
                let segs = path_segments(t);
                if let Some((name, ctx)) = segs.split_last() {
                    if !name.is_empty() {
                        out.push(Wanted {
                            name: name.clone(),
                            context: ctx.to_vec(),
                        });
                    }
                }
            } else {
                let name = ident_prefix(t);
                if !name.is_empty() && !is_path_root(&name) {
                    out.push(Wanted {
                        name,
                        context: ctx_file.clone(),
                    });
                }
            }
        }
    }
    out
}

/// An `impl` the live code still needs, identified by the method/trait the
/// compiler complained about rather than by the type name alone.
#[derive(Debug, Clone)]
pub struct ImplWant {
    pub type_name: String,
    /// A method/assoc-fn the live code calls but can't find.
    pub method: Option<String>,
    /// A trait the live code needs implemented for `type_name`.
    pub trait_name: Option<String>,
    pub context: Vec<String>,
}

/// Raw back-ticked token immediately after a keyword (not identifier-trimmed).
fn raw_backtick_after<'a>(line: &'a str, kw: &str) -> Option<&'a str> {
    let pos = line.find(kw)? + kw.len();
    let rest = &line[pos..];
    let s = rest.find('`')? + 1;
    let e = rest[s..].find('`')?;
    Some(&rest[s..s + e])
}

/// From a printed type like `&mut generic::memchr::Iter<'h>` extract the type's
/// bare name (`Iter`) and the module context before it (`["generic","memchr"]`).
fn type_name_and_context(token: &str) -> (String, Vec<String>) {
    let t = token.trim();
    let t = t.trim_start_matches('&').trim();
    let t = t.strip_prefix("mut ").unwrap_or(t).trim();
    let t = t.split('<').next().unwrap_or(t); // drop generics
    let segs: Vec<String> = t
        .split("::")
        .map(ident_prefix)
        .filter(|s| !s.is_empty() && !is_path_root(s))
        .collect();
    match segs.split_last() {
        Some((name, ctx)) => (name.clone(), ctx.to_vec()),
        None => (String::new(), Vec::new()),
    }
}

/// Parse the method/trait-resolution errors that reveal which `impl` blocks the
/// live code still needs (E0599 "no method named …", E0277 "trait … not
/// implemented for …" / "… doesn't implement …").
pub fn extract_impl_wanted(stderr: &str) -> Vec<ImplWant> {
    let mut out = Vec::new();
    for line in stderr.lines() {
        if !line.contains(": error") && !line.contains("error[") && !line.contains("error:") {
            continue;
        }

        // "no method named `m` found for <kind> `TYPE`" /
        // "no [function or] associated item named `m` found for <kind> `TYPE`"
        if line.contains(" named `") && line.contains(" found for ") {
            let method = raw_backtick_after(line, "named ").map(ident_prefix);
            let type_tok = raw_backtick_after(line, "found for ");
            if let (Some(method), Some(type_tok)) = (method, type_tok) {
                let (type_name, context) = type_name_and_context(type_tok);
                if !type_name.is_empty() && !method.is_empty() {
                    out.push(ImplWant {
                        type_name,
                        method: Some(method),
                        trait_name: None,
                        context,
                    });
                    continue;
                }
            }
        }

        // "the trait `Tr` is not implemented for `TYPE`"
        if line.contains("is not implemented for") {
            let trait_name = raw_backtick_after(line, "the trait ").map(ident_prefix);
            let type_tok = raw_backtick_after(line, "implemented for ");
            if let (Some(trait_name), Some(type_tok)) = (trait_name, type_tok) {
                let (type_name, context) = type_name_and_context(type_tok);
                if !type_name.is_empty() {
                    out.push(ImplWant {
                        type_name,
                        method: None,
                        trait_name: Some(trait_name),
                        context,
                    });
                    continue;
                }
            }
        }

        // "`TYPE` doesn't implement `Tr`"
        if line.contains("doesn't implement") {
            let type_tok = backticked(line).into_iter().next();
            let trait_name = raw_backtick_after(line, "doesn't implement ").map(ident_prefix);
            if let Some(type_tok) = type_tok {
                let (type_name, context) = type_name_and_context(&type_tok);
                if !type_name.is_empty() {
                    out.push(ImplWant {
                        type_name,
                        method: None,
                        trait_name,
                        context,
                    });
                    continue;
                }
            }
        }

        // "the trait bound `TYPE: Tr` is not satisfied"
        if line.contains("the trait bound") {
            if let Some(tok) = raw_backtick_after(line, "the trait bound ") {
                if let Some((lhs, rhs)) = tok.split_once(':') {
                    let (type_name, context) = type_name_and_context(lhs);
                    let trait_name = ident_prefix(rhs.trim().trim_start_matches(':').trim());
                    if !type_name.is_empty() {
                        out.push(ImplWant {
                            type_name,
                            method: None,
                            trait_name: (!trait_name.is_empty()).then_some(trait_name),
                            context,
                        });
                        continue;
                    }
                }
            }
        }

        // "`TYPE` is not an iterator" → needs `impl Iterator for TYPE`
        if line.contains("is not an iterator") {
            if let Some(type_tok) = backticked(line).into_iter().next() {
                let (type_name, context) = type_name_and_context(&type_tok);
                if !type_name.is_empty() {
                    out.push(ImplWant {
                        type_name,
                        method: None,
                        trait_name: Some("Iterator".to_string()),
                        context,
                    });
                    continue;
                }
            }
        }
    }
    out
}

/// Score how well an item's module matches a lookup context, suffix-aware
/// (compiler-printed type paths often omit leading modules, e.g. `arch::`).
pub fn module_match(item_module: &[String], context: &[String]) -> i64 {
    if context.is_empty() {
        return 0;
    }
    let mut score = context.iter().filter(|c| item_module.contains(c)).count() as i64;
    if item_module.last() == context.last() {
        score += 10; // same leaf module is a strong signal
    }
    score
}

/// Count matching leading segments between an item's module and a lookup context.
pub fn prefix_overlap(item_module: &[String], context: &[String]) -> usize {
    item_module
        .iter()
        .zip(context.iter())
        .take_while(|(a, b)| a == b)
        .count()
}

/// Every vendored `.rs` file under a crate (skipping the trash dir).
pub fn rust_files(vendor_dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(vendor_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| is_rust(e.path()))
        .map(|e| e.path().to_path_buf())
        .collect()
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
    std::fs::rename(target, &parked).with_context(|| format!("parking {}", target.display()))?;
    Ok(parked)
}

/// Move a parked module back to its original location (rollback).
pub fn unpark(parked: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(parked, target).with_context(|| format!("restoring {}", target.display()))?;
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

/// Count whole-word occurrences of `word` in `text`.
fn count_word(text: &str, word: &str) -> usize {
    let bytes = text.as_bytes();
    let w = word.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut count = 0;
    let mut i = 0;
    while let Some(pos) = text[i..].find(word) {
        let s = i + pos;
        let before_ok = s == 0 || !is_ident(bytes[s - 1]);
        let after = s + w.len();
        let after_ok = after >= bytes.len() || !is_ident(bytes[after]);
        if before_ok && after_ok {
            count += 1;
        }
        i = s + w.len();
    }
    count
}

/// Measure a vendored crate's attack surface across several dimensions.
pub fn measure_surface(vendor_dir: &Path) -> crate::model::AttackSurface {
    let mut files = 0;
    let mut loc = 0;
    let mut bytes = 0u64;
    let mut items = 0;
    let mut unsafe_blocks = 0;
    for path in rust_files(vendor_dir) {
        if let Ok(src) = std::fs::read_to_string(&path) {
            files += 1;
            loc += src.lines().count();
            bytes += src.len() as u64;
            unsafe_blocks += count_word(&src, "unsafe");
            items += list_items(&path).map(|v| v.len()).unwrap_or(0);
        }
    }
    crate::model::AttackSurface {
        files,
        loc,
        bytes,
        items,
        unsafe_blocks,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- module path mapping -------------------------------------------------
    #[test]
    fn module_of_path_cases() {
        assert_eq!(
            module_of_path("w/vendor/memchr-2.8.1/src/arch/all/memchr.rs:26:5"),
            vec!["arch", "all", "memchr"]
        );
        assert!(module_of_path("x/src/lib.rs").is_empty());
        assert_eq!(module_of_path("x/src/memmem/mod.rs"), vec!["memmem"]);
        assert_eq!(module_of_path("x/src/memchr.rs"), vec!["memchr"]);
    }

    // --- value/type "cannot find" parsing (extract_wanted) -------------------
    #[test]
    fn wanted_unresolved_import_path() {
        let e = "x/src/lib.rs:203:16: error[E0432]: unresolved import `crate::memchr`";
        let w = extract_wanted(e);
        assert!(w.iter().any(|x| x.name == "memchr"));
    }

    #[test]
    fn wanted_cannot_find_in_module_uses_that_module_as_context() {
        let e = "x/src/d.rs:5:9: error[E0425]: cannot find function `memchr_raw` in module `crate::arch::all`";
        let w = extract_wanted(e);
        let m = w
            .iter()
            .find(|x| x.name == "memchr_raw")
            .expect("found memchr_raw");
        assert_eq!(m.context, vec!["arch", "all"]);
    }

    #[test]
    fn wanted_bare_name_uses_error_file_module() {
        let e = "x/vendor/c/src/arch/x86_64/memchr.rs:9:1: error[E0412]: cannot find type `One` in this scope";
        let w = extract_wanted(e);
        let m = w.iter().find(|x| x.name == "One").expect("found One");
        assert_eq!(m.context, vec!["arch", "x86_64", "memchr"]);
    }

    // --- impl method/trait parsing (extract_impl_wanted) ---------------------
    #[test]
    fn impl_wanted_no_method_takes_type_last_segment() {
        let e = "x:1:1: error[E0599]: no method named `find` found for struct `rabinkarp::Finder` in the current scope";
        let m = extract_impl_wanted(e)
            .into_iter()
            .find(|x| x.type_name == "Finder")
            .unwrap();
        assert_eq!(m.method.as_deref(), Some("find"));
        assert_eq!(m.context, vec!["rabinkarp"]);
    }

    #[test]
    fn impl_wanted_strips_ref_and_generics() {
        let e = "x:1:1: error[E0599]: no method named `min_haystack_len` found for reference `&sse2::packedpair::Finder` in the current scope";
        let m = extract_impl_wanted(e)
            .into_iter()
            .find(|x| x.method.as_deref() == Some("min_haystack_len"))
            .unwrap();
        assert_eq!(m.type_name, "Finder");
        assert_eq!(m.context, vec!["sse2", "packedpair"]);

        let g = "x:1:1: error[E0599]: no function or associated item named `new` found for struct `generic::memchr::Iter<'h>`";
        let m = extract_impl_wanted(g)
            .into_iter()
            .find(|x| x.type_name == "Iter")
            .unwrap();
        assert_eq!(m.method.as_deref(), Some("new"));
        assert_eq!(m.context, vec!["generic", "memchr"]);
    }

    #[test]
    fn impl_wanted_trait_bound_and_not_iterator() {
        let b = "x:1:1: error[E0277]: the trait bound `DefaultFrequencyRank: HeuristicFrequencyRank` is not satisfied";
        let m = extract_impl_wanted(b)
            .into_iter()
            .find(|x| x.type_name == "DefaultFrequencyRank")
            .unwrap();
        assert_eq!(m.trait_name.as_deref(), Some("HeuristicFrequencyRank"));

        let i = "x:1:1: error[E0599]: `SuffixKind` is not an iterator";
        let m = extract_impl_wanted(i)
            .into_iter()
            .find(|x| x.type_name == "SuffixKind")
            .unwrap();
        assert_eq!(m.trait_name.as_deref(), Some("Iterator"));

        let t = "x:1:1: error[E0277]: the trait `Iterator` is not implemented for `OneIter`";
        let m = extract_impl_wanted(t)
            .into_iter()
            .find(|x| x.type_name == "OneIter")
            .unwrap();
        assert_eq!(m.trait_name.as_deref(), Some("Iterator"));
    }

    // --- module disambiguation -----------------------------------------------
    #[test]
    fn module_match_prefers_the_right_backend() {
        let rabinkarp = vec![
            "arch".to_string(),
            "all".to_string(),
            "rabinkarp".to_string(),
        ];
        let twoway = vec!["arch".to_string(), "all".to_string(), "twoway".to_string()];
        let ctx = vec!["rabinkarp".to_string()];
        assert!(module_match(&rabinkarp, &ctx) > module_match(&twoway, &ctx));
    }

    // --- unsafe / word counting ----------------------------------------------
    #[test]
    fn count_word_is_boundary_aware() {
        assert_eq!(
            count_word("unsafe { } // unsafe_x not_unsafe value", "unsafe"),
            1
        );
        assert_eq!(count_word("a unsafe b unsafe", "unsafe"), 2);
    }

    // --- render-from-original is stable across removals ----------------------
    #[test]
    fn render_without_removes_only_targeted_items() {
        let src = "pub fn a() {}\npub fn b() {}\npub fn c() {}\n";
        let items = list_items(std::path::Path::new("/dev/null")).unwrap_or_default();
        let _ = items; // list_items needs a real file; exercise render directly
                       // Build a minimal ItemRef set by hand to test render_without line logic.
        let it_b = ItemRef {
            label: "fn b".into(),
            name: "b".into(),
            removable: true,
            methods: vec![],
            trait_name: None,
            start: 2,
            end: 2,
            text_hash: 42,
        };
        let mut removed = std::collections::HashSet::new();
        removed.insert(42u64);
        let out = render_without(src, std::slice::from_ref(&it_b), &removed);
        assert!(out.contains("fn a"));
        assert!(!out.contains("fn b"));
        assert!(out.contains("fn c"));
    }
}
