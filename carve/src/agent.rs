//! The autonomous agent layer.
//!
//! The agent is defined by a **tool surface** (the [`Tool`] trait) and a driver.
//! Two drivers are intended:
//!  - [`RuleBasedAgent`] — deterministic, no LLM, ships today. It reads the DFUG
//!    and proposes a [`MinimizationPlan`] using conservative heuristics, then can
//!    drive the verbatim-vendor + verification loop.
//!  - `LlmAgent` (roadmap) — the same tool surface handed to a model that
//!    proposes item-level slices; every proposal is checked by `CargoCheck` so
//!    the agent can *select* code but never *invent* it.
//!
//! Observability: every tool call is a `tracing` span carrying the tool name and
//! a structured outcome, so a full run can be replayed from the JSON log.

use crate::model::{
    Confidence, CrateMinimization, ItemSliceReport, MinimizationPlan, SliceReport, UsageGraph,
};
use crate::slice;
use std::collections::HashSet;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// A capability the agent can invoke. Inputs/outputs are JSON so the same
/// surface works for a deterministic driver or an LLM tool-call loop.
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn invoke(&self, input: &Value) -> Result<Value>;
}

/// Registry of tools available to the agent, with observability baked in.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn with_defaults() -> Self {
        let mut r = ToolRegistry::default();
        r.register(Box::new(ReadFileTool));
        r.register(Box::new(Sha256Tool));
        r.register(Box::new(ParseItemsTool));
        r.register(Box::new(CargoCheckTool));
        r
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name(), tool);
    }

    /// `(name, description)` for every registered tool — the surface an LLM
    /// driver would be handed as its tool schema.
    pub fn describe(&self) -> Vec<(&'static str, &'static str)> {
        self.tools
            .values()
            .map(|t| (t.name(), t.description()))
            .collect()
    }

    /// Invoke a tool by name, recording a span for observability.
    #[tracing::instrument(skip(self, input), fields(tool = name))]
    pub fn call(&self, name: &str, input: &Value) -> Result<Value> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| anyhow!("unknown tool: {name}"))?;
        tracing::debug!(?input, "tool call");
        let out = tool.invoke(input);
        match &out {
            Ok(v) => tracing::info!(outcome = "ok", result = %compact(v), "tool done"),
            Err(e) => tracing::warn!(outcome = "err", error = %e, "tool failed"),
        }
        out
    }
}

fn compact(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 200 {
        format!("{}…", &s[..200])
    } else {
        s
    }
}

// ---------------------------------------------------------------------------
// Concrete tools
// ---------------------------------------------------------------------------

struct ReadFileTool;
impl Tool for ReadFileTool {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn description(&self) -> &'static str {
        "Read a UTF-8 file. input: {path}. output: {content, bytes}"
    }
    fn invoke(&self, input: &Value) -> Result<Value> {
        let path = str_field(input, "path")?;
        let content = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        Ok(json!({ "bytes": content.len(), "content": content }))
    }
}

struct Sha256Tool;
impl Tool for Sha256Tool {
    fn name(&self) -> &'static str {
        "sha256"
    }
    fn description(&self) -> &'static str {
        "Hash a file's bytes. input: {path}. output: {sha256}"
    }
    fn invoke(&self, input: &Value) -> Result<Value> {
        let path = str_field(input, "path")?;
        let bytes = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
        Ok(json!({ "sha256": crate::vendor::sha256_bytes(&bytes) }))
    }
}

/// Parse a Rust file and list its top-level item identifiers. The agent uses
/// this to map a used path to the upstream definition site it must transcribe.
struct ParseItemsTool;
impl Tool for ParseItemsTool {
    fn name(&self) -> &'static str {
        "parse_items"
    }
    fn description(&self) -> &'static str {
        "List top-level item names in a Rust file. input: {path}. output: {items:[{name,kind}]}"
    }
    fn invoke(&self, input: &Value) -> Result<Value> {
        let path = str_field(input, "path")?;
        let src = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        let ast = syn::parse_file(&src).context("parsing Rust file")?;
        let mut items = Vec::new();
        for item in &ast.items {
            if let Some((name, kind)) = item_ident(item) {
                items.push(json!({ "name": name, "kind": kind }));
            }
        }
        Ok(json!({ "items": items }))
    }
}

fn item_ident(item: &syn::Item) -> Option<(String, &'static str)> {
    use syn::Item::*;
    match item {
        Fn(i) => Some((i.sig.ident.to_string(), "fn")),
        Struct(i) => Some((i.ident.to_string(), "struct")),
        Enum(i) => Some((i.ident.to_string(), "enum")),
        Trait(i) => Some((i.ident.to_string(), "trait")),
        Type(i) => Some((i.ident.to_string(), "type")),
        Const(i) => Some((i.ident.to_string(), "const")),
        Static(i) => Some((i.ident.to_string(), "static")),
        Mod(i) => Some((i.ident.to_string(), "mod")),
        Macro(i) => i.ident.as_ref().map(|id| (id.to_string(), "macro")),
        Union(i) => Some((i.ident.to_string(), "union")),
        _ => None,
    }
}

/// Run `cargo check` to prove a vendored slice compiles. This is the gate that
/// makes "select but never invent" enforceable.
struct CargoCheckTool;
impl Tool for CargoCheckTool {
    fn name(&self) -> &'static str {
        "cargo_check"
    }
    fn description(&self) -> &'static str {
        "Run `cargo check`. input: {manifest_path}. output: {success, stderr}"
    }
    fn invoke(&self, input: &Value) -> Result<Value> {
        let manifest = str_field(input, "manifest_path")?;
        // `profile`: "debug" | "release" | absent (=both). Code cfg-gates on
        // `debug_assertions`, so a cut fine in one profile can break the other —
        // the slicer converges on fast "debug" then reconciles against "release".
        let profile = input.get("profile").and_then(Value::as_str);
        // Run cargo IN the project directory so it reads the project's
        // .cargo/config.toml (the cap-lints shim). Invoking via --manifest-path
        // from elsewhere would ignore it and dependency lints would fail builds.
        let workdir = std::path::Path::new(&manifest)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let run = |release: bool| -> Result<(bool, String)> {
            let mut args = vec!["check", "--manifest-path", &manifest, "--message-format=short"];
            if release {
                args.push("--release");
            }
            let out = Command::new("cargo")
                .current_dir(&workdir)
                .args(&args)
                .output()
                .context("spawning cargo check")?;
            Ok((out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned()))
        };
        match profile {
            Some("debug") => {
                let (ok, err) = run(false)?;
                Ok(json!({ "success": ok, "stderr": err }))
            }
            Some("release") => {
                let (ok, err) = run(true)?;
                Ok(json!({ "success": ok, "stderr": err }))
            }
            _ => {
                let (dbg_ok, dbg_err) = run(false)?;
                if !dbg_ok {
                    return Ok(json!({ "success": false, "stderr": dbg_err }));
                }
                let (rel_ok, rel_err) = run(true)?;
                Ok(json!({ "success": rel_ok, "stderr": format!("{dbg_err}\n{rel_err}") }))
            }
        }
    }
}

fn str_field(input: &Value, key: &str) -> Result<String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing string field `{key}`"))
}

// ---------------------------------------------------------------------------
// Rule-based agent
// ---------------------------------------------------------------------------

/// Deterministic minimization planner. Reads the DFUG and decides, per crate,
/// whether item-level slicing is safe or whether to vendor verbatim for now.
pub struct RuleBasedAgent {
    pub registry: ToolRegistry,
}

impl RuleBasedAgent {
    pub fn new() -> Self {
        RuleBasedAgent {
            registry: ToolRegistry::with_defaults(),
        }
    }

    /// Produce a minimization plan from the usage graph.
    #[tracing::instrument(skip_all, fields(package = %graph.package))]
    pub fn plan(&self, graph: &UsageGraph) -> MinimizationPlan {
        let mut crates = Vec::new();
        for c in &graph.crates {
            let entrypoints: Vec<String> = c.items.iter().map(|i| i.path.clone()).collect();
            let has_macro = c.items.iter().any(|i| {
                i.references
                    .iter()
                    .any(|r| matches!(r.kind, crate::model::RefKind::Macro))
            });
            let surface = entrypoints.len();

            // Conservative heuristics. Macro-heavy or wide surfaces are risky to
            // slice syntactically, so we defer to verbatim vendoring.
            let (confidence, rationale) = if has_macro {
                (
                    Confidence::Low,
                    format!(
                        "{} uses macro(s); macros expand to unknown surface — vendor verbatim, slice later under a verification build",
                        c.name
                    ),
                )
            } else if surface <= 5 {
                (
                    Confidence::High,
                    format!("narrow surface ({surface} item(s)), value/type paths only — item-level slice is safe"),
                )
            } else {
                (
                    Confidence::Medium,
                    format!("{surface} items used — slice candidate, gate on `cargo check`"),
                )
            };

            // Heuristic transitive estimate: each entrypoint tends to drag a small
            // constellation of private helpers. Refined later by reading upstream.
            let transitive_estimate = surface * 3;

            tracing::info!(
                crate_name = %c.name,
                surface,
                ?confidence,
                "planned crate minimization"
            );

            crates.push(CrateMinimization {
                crate_name: c.name.clone(),
                version: c.version.clone(),
                entrypoints,
                transitive_estimate,
                confidence,
                rationale,
            });
        }

        MinimizationPlan {
            package: graph.package.clone(),
            generated_at: chrono::Utc::now(),
            crates,
        }
    }

    /// Autonomously slice a vendored crate down to "only the part we need".
    ///
    /// This is the agent's core loop: greedily try to carve away each upstream
    /// module, and after every cut drive the `cargo_check` tool against the real
    /// consuming product. A cut is kept only if the consumer still compiles;
    /// otherwise it is rolled back verbatim. The compiler is the oracle, so the
    /// agent removes code but can never break or invent it.
    #[tracing::instrument(skip(self, vendor_dir), fields(crate_name = crate_name))]
    pub fn slice_crate(
        &self,
        crate_name: &str,
        project_manifest: &Path,
        vendor_dir: &Path,
        prioritized: &[String],
    ) -> Result<SliceReport> {
        let manifest = json!({ "manifest_path": project_manifest.to_string_lossy() });

        // The consumer must compile before we touch anything.
        let baseline = self.registry.call("cargo_check", &manifest)?;
        if !baseline["success"].as_bool().unwrap_or(false) {
            return Err(anyhow!(
                "baseline `cargo check` failed; apply the patch and ensure the project builds before slicing"
            ));
        }

        let files_before = slice::count_rs_files(vendor_dir);
        let loc_before = slice::count_loc(vendor_dir);

        // Shallow modules first: removing a whole subtree skips its children.
        let mut candidates = slice::discover(vendor_dir)?;
        candidates.sort_by_key(|c| c.depth);
        // If a planner (e.g. the LLM agent) prioritized certain modules, try those
        // first — the cargo_check gate still guarantees safety either way.
        if !prioritized.is_empty() {
            let rank = |name: &str| {
                prioritized
                    .iter()
                    .position(|p| p == name)
                    .unwrap_or(usize::MAX)
            };
            candidates.sort_by_key(|c| (rank(&c.rel_name), c.depth));
            tracing::info!(prioritized = prioritized.len(), "using planner-prioritized order");
        }
        tracing::info!(candidates = candidates.len(), "discovered removable modules");

        let mut removed = Vec::new();
        let mut kept_needed = Vec::new();

        for c in &candidates {
            if !c.decl_file.exists() || !c.target.exists() {
                continue; // already gone with a parent subtree
            }
            let span = tracing::info_span!("carve_attempt", module = %c.rel_name);
            let _enter = span.enter();

            let decl_backup = slice::remove_mod_decl(&c.decl_file, &c.name)?;
            let parked = slice::park(vendor_dir, &c.target)?;

            let check = self.registry.call("cargo_check", &manifest)?;
            if check["success"].as_bool().unwrap_or(false) {
                std::fs::remove_dir_all(&parked).ok();
                std::fs::remove_file(&parked).ok();
                tracing::info!(module = %c.rel_name, "carved away — consumer still compiles");
                removed.push(c.rel_name.clone());
            } else {
                std::fs::write(&c.decl_file, decl_backup)?;
                slice::unpark(&parked, &c.target)?;
                tracing::debug!(module = %c.rel_name, "kept — needed to compile");
                kept_needed.push(c.rel_name.clone());
            }
        }

        slice::cleanup_trash(vendor_dir);
        let final_check = self.registry.call("cargo_check", &manifest)?;
        let verified = final_check["success"].as_bool().unwrap_or(false);

        let files_after = slice::count_rs_files(vendor_dir);
        let loc_after = slice::count_loc(vendor_dir);
        removed.sort();
        kept_needed.sort();

        Ok(SliceReport {
            crate_name: crate_name.to_string(),
            files_before,
            files_after,
            loc_before,
            loc_after,
            removed,
            kept_needed,
            verified,
        })
    }

    /// Autonomously slice at the **item level**: greedily try to delete each
    /// individual top-level item (fn/struct/impl/…) and verify with `cargo_check`
    /// against the real consumer, keeping only removals that still compile. Runs
    /// in passes to fixpoint (removing a caller can free its private helper),
    /// bounded by a verification `budget`. Verbatim and compiler-gated, like the
    /// module slicer — just finer.
    #[tracing::instrument(skip(self, vendor_dir), fields(crate_name = crate_name))]
    pub fn slice_items(
        &self,
        crate_name: &str,
        project_manifest: &Path,
        vendor_dir: &Path,
        budget: usize,
    ) -> Result<ItemSliceReport> {
        // `manifest` verifies both profiles (final gate); `dbg`/`rel` are the
        // fast single-profile checks used during the loops. Converging on debug
        // and reconciling against release once is far cheaper than running a
        // release check on every cut.
        let manifest = json!({ "manifest_path": project_manifest.to_string_lossy() });
        let dbg = json!({ "manifest_path": project_manifest.to_string_lossy(), "profile": "debug" });
        let rel = json!({ "manifest_path": project_manifest.to_string_lossy(), "profile": "release" });
        let baseline = self.registry.call("cargo_check", &manifest)?;
        if !baseline["success"].as_bool().unwrap_or(false) {
            return Err(anyhow!("baseline `cargo check` failed; fix the build before item-slicing"));
        }

        let loc_before = slice::count_loc(vendor_dir);

        // Snapshot every file's ORIGINAL source + item table; we always render
        // file content from the original minus the current `removed` set, so item
        // spans stay valid no matter how many items we remove or restore.
        struct FileState {
            path: std::path::PathBuf,
            original: String,
            items: Vec<slice::ItemRef>,
            /// Module path this file defines, for precise error-guided restores.
            module: Vec<String>,
        }
        let mut files: Vec<FileState> = Vec::new();
        for path in slice::rust_files(vendor_dir) {
            let original = std::fs::read_to_string(&path).unwrap_or_default();
            let items = slice::list_items(&path).unwrap_or_default();
            let module = slice::module_of_path(&path.to_string_lossy());
            files.push(FileState { path, original, items, module });
        }
        let items_before: usize = files.iter().map(|f| f.items.len()).sum();

        let write_all = |removed: &HashSet<u64>| -> Result<()> {
            for f in &files {
                std::fs::write(&f.path, slice::render_without(&f.original, &f.items, removed))?;
            }
            Ok(())
        };

        // Start by removing EVERYTHING removable, then let the compiler tell us
        // what the live code still needs and restore exactly those — converging
        // in O(reference-depth) checks instead of one check per item.
        let mut removed: HashSet<u64> = files
            .iter()
            .flat_map(|f| f.items.iter().filter(|i| i.removable).map(|i| i.text_hash))
            .collect();
        write_all(&removed)?;

        let mut checks = 0usize;
        let mut converged = false;
        let mut budget_exhausted = false;
        // Convergence is cheap (~O(reference-depth)); it is not charged against
        // the refinement budget. 64 rounds is far more than any real depth.
        for round in 0..64 {
            let res = self.registry.call("cargo_check", &dbg)?;
            checks += 1;
            if res["success"].as_bool().unwrap_or(false) {
                converged = true;
                break;
            }
            let stderr = res["stderr"].as_str().unwrap_or("");
            // Precise restore: for each symbol the compiler says is missing,
            // bring back only the definition in the module the lookup pointed at
            // (longest module-prefix match). This avoids restoring a same-named
            // item in every CPU backend, so convergence reaches the maximal set.
            let wanted = slice::extract_wanted(stderr);
            let mut restored = 0usize;
            for w in &wanted {
                let mut best_ov: i64 = -1;
                let mut best: Vec<u64> = Vec::new();
                for f in &files {
                    let ov = slice::prefix_overlap(&f.module, &w.context) as i64;
                    for it in &f.items {
                        if it.removable && it.name == w.name && removed.contains(&it.text_hash) {
                            if ov > best_ov {
                                best_ov = ov;
                                best = vec![it.text_hash];
                            } else if ov == best_ov {
                                best.push(it.text_hash);
                            }
                        }
                    }
                }
                for h in best {
                    if removed.remove(&h) {
                        restored += 1;
                    }
                }
            }
            tracing::info!(round, restored, still_removed = removed.len(), checks, "error-guided round");
            if restored == 0 {
                break; // stuck: no error names a removed item
            }
            write_all(&removed)?;
        }

        let after_fast = removed.len();
        let fast_checks = checks;

        // Phase 1 (above) converges value/type symbols but over-keeps `impl`
        // blocks: each was restored merely because its *type* was mentioned, not
        // because a method was called. Phase 2 is a second error-guided
        // convergence over impls only — remove them all, then restore by the
        // method/trait the compiler actually complains about. Also ~O(depth),
        // so the impl tail is now cheap too (no per-item sweep needed).
        if converged {
            let converged_removed = removed.clone();
            for f in &files {
                for it in &f.items {
                    if it.removable && it.label.starts_with("impl ") && !removed.contains(&it.text_hash) {
                        removed.insert(it.text_hash);
                    }
                }
            }
            write_all(&removed)?;

            let mut p2_converged = false;
            for round in 0..64 {
                let res = self.registry.call("cargo_check", &dbg)?;
                checks += 1;
                if res["success"].as_bool().unwrap_or(false) {
                    p2_converged = true;
                    break;
                }
                let wants = slice::extract_impl_wanted(res["stderr"].as_str().unwrap_or(""));
                let mut restored = 0usize;
                for w in &wants {
                    let mut best_ov: i64 = -1;
                    let mut best: Vec<u64> = Vec::new();
                    for f in &files {
                        let ov = slice::module_match(&f.module, &w.context);
                        for it in &f.items {
                            if !it.label.starts_with("impl ")
                                || !it.removable
                                || it.name != w.type_name
                                || !removed.contains(&it.text_hash)
                            {
                                continue;
                            }
                            let matches = match (&w.method, &w.trait_name) {
                                (Some(m), _) => it.methods.iter().any(|x| x == m) || it.trait_name.is_some(),
                                (None, Some(tr)) => it.trait_name.as_deref() == Some(tr.as_str()),
                                (None, None) => true,
                            };
                            if matches {
                                if ov > best_ov {
                                    best_ov = ov;
                                    best = vec![it.text_hash];
                                } else if ov == best_ov {
                                    best.push(it.text_hash);
                                }
                            }
                        }
                    }
                    for h in best {
                        if removed.remove(&h) {
                            restored += 1;
                        }
                    }
                }
                // Loose fallback for error phrasings the precise parser misses:
                // restore impls whose *type* is mentioned in the remaining errors.
                // Only types the compiler actually complained about are touched;
                // dead impls on unmentioned types stay removed.
                if restored == 0 {
                    let idents = slice::error_idents(res["stderr"].as_str().unwrap_or(""));
                    for f in &files {
                        for it in &f.items {
                            if it.label.starts_with("impl ")
                                && it.removable
                                && removed.contains(&it.text_hash)
                                && idents.contains(&it.name)
                            {
                                removed.remove(&it.text_hash);
                                restored += 1;
                            }
                        }
                    }
                    tracing::info!(round, loose_restored = restored, "impl-convergence loose fallback");
                }
                if restored == 0 {
                    break; // truly stuck
                }
                write_all(&removed)?;
            }
            if !p2_converged {
                // Couldn't pin the needed impls precisely — restore Phase 1 state.
                removed = converged_removed;
                write_all(&removed)?;
            }

            // Optional catch-all: spend --budget on a greedy sweep of whatever
            // removable items remain (e.g. odd duplicates the phases missed).
            if budget > 0 {
                let mut refine_checks = 0usize;
                'refine2: for f in &files {
                    for it in f.items.iter().filter(|i| i.removable) {
                        if removed.contains(&it.text_hash) {
                            continue;
                        }
                        if refine_checks >= budget {
                            budget_exhausted = true;
                            break 'refine2;
                        }
                        refine_checks += 1;
                        removed.insert(it.text_hash);
                        std::fs::write(&f.path, slice::render_without(&f.original, &f.items, &removed))?;
                        let res = self.registry.call("cargo_check", &dbg)?;
                        checks += 1;
                        if !res["success"].as_bool().unwrap_or(false) {
                            removed.remove(&it.text_hash);
                            std::fs::write(&f.path, slice::render_without(&f.original, &f.items, &removed))?;
                        }
                    }
                }
            }
        } else {
            removed.clear();
            write_all(&removed)?;
            let mut refine_checks = 0usize;
            'refine: for f in &files {
                for it in f.items.iter().filter(|i| i.removable) {
                    if refine_checks >= budget {
                        budget_exhausted = true;
                        break 'refine;
                    }
                    refine_checks += 1;
                    removed.insert(it.text_hash);
                    std::fs::write(&f.path, slice::render_without(&f.original, &f.items, &removed))?;
                    let res = self.registry.call("cargo_check", &dbg)?;
                    checks += 1;
                    if !res["success"].as_bool().unwrap_or(false) {
                        removed.remove(&it.text_hash);
                        std::fs::write(&f.path, slice::render_without(&f.original, &f.items, &removed))?;
                    }
                }
            }
        }
        tracing::info!(after_fast, after_refine = removed.len(), checks, "item-slice (debug) done");

        // Release reconciliation: everything above verified the cheap debug
        // profile; now make the result satisfy --release too. Code gated on
        // `cfg(not(debug_assertions))` is dead in debug but live in release, so
        // the release build may demand items we removed. Restore exactly those
        // (by the same precise name/module + method/trait matching), iterating
        // until release compiles. This runs release checks only a handful of
        // times per crate instead of on every cut.
        for _ in 0..48 {
            let rc = self.registry.call("cargo_check", &rel)?;
            checks += 1;
            if rc["success"].as_bool().unwrap_or(false) {
                break;
            }
            let stderr = rc["stderr"].as_str().unwrap_or("");
            let mut restored = 0usize;
            // value/type items
            for w in slice::extract_wanted(stderr) {
                let mut best_ov: i64 = -1;
                let mut best: Vec<u64> = Vec::new();
                for f in &files {
                    let ov = slice::prefix_overlap(&f.module, &w.context) as i64;
                    for it in &f.items {
                        if it.removable && it.name == w.name && removed.contains(&it.text_hash) {
                            if ov > best_ov { best_ov = ov; best = vec![it.text_hash]; }
                            else if ov == best_ov { best.push(it.text_hash); }
                        }
                    }
                }
                for h in best { if removed.remove(&h) { restored += 1; } }
            }
            // impl blocks
            for w in slice::extract_impl_wanted(stderr) {
                let mut best_ov: i64 = -1;
                let mut best: Vec<u64> = Vec::new();
                for f in &files {
                    let ov = slice::module_match(&f.module, &w.context);
                    for it in &f.items {
                        if it.label.starts_with("impl ") && it.removable && it.name == w.type_name && removed.contains(&it.text_hash) {
                            let m = match (&w.method, &w.trait_name) {
                                (Some(mm), _) => it.methods.iter().any(|x| x == mm) || it.trait_name.is_some(),
                                (None, Some(tr)) => it.trait_name.as_deref() == Some(tr.as_str()),
                                (None, None) => true,
                            };
                            if m {
                                if ov > best_ov { best_ov = ov; best = vec![it.text_hash]; }
                                else if ov == best_ov { best.push(it.text_hash); }
                            }
                        }
                    }
                }
                for h in best { if removed.remove(&h) { restored += 1; } }
            }
            if restored == 0 {
                // Can't pinpoint what release needs — unslice this crate (its
                // verbatim original passed release at baseline). Rare, safe.
                removed.clear();
                break;
            }
            write_all(&removed)?;
        }
        tracing::info!(after_release_reconcile = removed.len(), checks, "item-slice done");

        let final_check = self.registry.call("cargo_check", &manifest)?;
        let verified = final_check["success"].as_bool().unwrap_or(false);
        if !verified {
            // Never leave the tree broken.
            removed.clear();
            write_all(&removed)?;
        }
        let loc_after = slice::count_loc(vendor_dir);

        // Observability: record a sample of what was carved.
        let carved: Vec<&str> = files
            .iter()
            .flat_map(|f| f.items.iter())
            .filter(|it| removed.contains(&it.text_hash))
            .map(|it| it.label.as_str())
            .collect();
        tracing::info!(removed = carved.len(), checks, sample = ?carved.iter().take(12).collect::<Vec<_>>(), "item-slice complete");

        Ok(ItemSliceReport {
            crate_name: crate_name.to_string(),
            items_before,
            items_removed: removed.len(),
            loc_before,
            loc_after,
            fast_removed: after_fast,
            fast_checks,
            checks_used: checks,
            budget_exhausted,
            verified,
        })
    }

    /// Locate the upstream definition site for a used path by scanning the
    /// crate's source files for a matching top-level item. Best-effort; returns
    /// the file path and item kind when found. Demonstrates tool-driven lookup.
    pub fn locate_definition(&self, upstream_src: &Path, item_path: &str) -> Result<Option<Value>> {
        let target = item_path
            .rsplit("::")
            .next()
            .unwrap_or(item_path)
            .to_string();
        for entry in walkdir::WalkDir::new(upstream_src)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
        {
            let path = entry.path().to_string_lossy().to_string();
            let out = self.registry.call("parse_items", &json!({ "path": path }))?;
            if let Some(items) = out.get("items").and_then(Value::as_array) {
                for it in items {
                    if it.get("name").and_then(Value::as_str) == Some(target.as_str()) {
                        return Ok(Some(json!({
                            "file": path,
                            "name": target,
                            "kind": it.get("kind").cloned().unwrap_or(Value::Null),
                        })));
                    }
                }
            }
        }
        Ok(None)
    }
}

impl Default for RuleBasedAgent {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LLM agent — same tool surface, driven by a model
// ---------------------------------------------------------------------------

const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// An agent driven by the Anthropic Messages API over the *same* [`ToolRegistry`]
/// the rule-based agent uses. The model proposes which upstream modules a slice
/// can drop; every proposal is still gated by `cargo_check`, so the model selects
/// but never invents or breaks code.
pub struct LlmAgent {
    registry: ToolRegistry,
    api_key: String,
    model: String,
    /// Tool-call budget per planning session.
    max_steps: usize,
}

impl LlmAgent {
    /// Build from `ANTHROPIC_API_KEY` (model overridable via `CARVE_LLM_MODEL`).
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow!("ANTHROPIC_API_KEY is not set; the LLM agent needs an API key"))?;
        let model =
            std::env::var("CARVE_LLM_MODEL").unwrap_or_else(|_| "claude-sonnet-4-6".to_string());
        Ok(LlmAgent {
            registry: ToolRegistry::with_defaults(),
            api_key,
            model,
            max_steps: 16,
        })
    }

    /// Tool schemas advertised to the model (a subset of the registry that is
    /// safe and useful for read-only planning).
    fn tool_schemas() -> Value {
        json!([
            {
                "name": "read_file",
                "description": "Read a UTF-8 source file to understand what a module does.",
                "input_schema": {
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                }
            },
            {
                "name": "parse_items",
                "description": "List the top-level item names/kinds defined in a Rust file.",
                "input_schema": {
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                }
            }
        ])
    }

    /// Single round-trip to the API. Returns the parsed JSON response.
    #[tracing::instrument(skip(self, body), fields(model = %self.model))]
    fn call_api(&self, body: &Value) -> Result<Value> {
        let resp = ureq::post(ANTHROPIC_URL)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", ANTHROPIC_VERSION)
            .set("content-type", "application/json")
            .send_json(body.clone());
        match resp {
            Ok(r) => Ok(r.into_json::<Value>()?),
            Err(ureq::Error::Status(code, r)) => {
                let text = r.into_string().unwrap_or_default();
                Err(anyhow!("Anthropic API error {code}: {text}"))
            }
            Err(e) => Err(anyhow!("HTTP error calling Anthropic API: {e}")),
        }
    }

    /// Lightweight connectivity check; returns the model's short reply.
    pub fn ping(&self) -> Result<String> {
        let body = json!({
            "model": self.model,
            "max_tokens": 64,
            "messages": [{ "role": "user", "content": "Reply with exactly: carve-llm-ok" }]
        });
        let resp = self.call_api(&body)?;
        Ok(extract_text(&resp))
    }

    /// Ask the model which upstream modules a slice can drop, letting it read the
    /// source via tools. Returns module rel-names (e.g. `src/arch/aarch64`) in
    /// the order it recommends attempting them.
    #[tracing::instrument(skip(self, used_items, modules), fields(crate_name = crate_name, model = %self.model))]
    pub fn propose_removals(
        &self,
        crate_name: &str,
        used_items: &[String],
        modules: &[String],
        vendor_dir: &str,
    ) -> Result<Vec<String>> {
        let system = "You are carve's dependency-slicing agent. The product vendors an exact, \
verbatim copy of a dependency and wants to delete whole modules it does not need, to shrink the \
supply-chain attack surface. You NEVER write or invent code — you only decide which existing \
modules are safe to remove. A compiler check will verify every choice, so propose removals that \
are plausibly unused by the listed entrypoints (e.g. CPU backends for other architectures, unused \
algorithms, test-only modules). Use the tools to inspect files when unsure. When done, output ONLY \
a JSON object: {\"remove\": [\"src/...\", ...]} ordered most-confident first.";

        let user = format!(
            "Crate: {crate_name}\nVendored at: {vendor_dir}\n\nItems the product actually uses:\n{}\n\n\
Removable module candidates (rel paths under the vendored crate):\n{}\n\n\
Decide which modules to remove. Read files if helpful, then return the JSON.",
            used_items.join("\n"),
            modules.join("\n"),
        );

        let mut messages = vec![json!({ "role": "user", "content": user })];

        for step in 0..self.max_steps {
            let body = json!({
                "model": self.model,
                "max_tokens": 2048,
                "system": system,
                "tools": Self::tool_schemas(),
                "messages": messages,
            });
            let resp = self.call_api(&body)?;
            let content = resp.get("content").cloned().unwrap_or(json!([]));
            let stop = resp.get("stop_reason").and_then(Value::as_str).unwrap_or("");
            tracing::info!(step, stop, "llm turn");

            // Record the assistant turn verbatim so tool_use ids line up.
            messages.push(json!({ "role": "assistant", "content": content.clone() }));

            if stop == "tool_use" {
                let mut tool_results = Vec::new();
                for block in content.as_array().into_iter().flatten() {
                    if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                        let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                        let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                        let input = block.get("input").cloned().unwrap_or(json!({}));
                        let out = self
                            .registry
                            .call(name, &input)
                            .map(|v| v.to_string())
                            .unwrap_or_else(|e| format!("error: {e}"));
                        tool_results.push(json!({
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": truncate(&out, 6000),
                        }));
                    }
                }
                messages.push(json!({ "role": "user", "content": tool_results }));
                continue;
            }

            // Final turn: parse the JSON the model emitted.
            let text = extract_text(&resp);
            return Ok(parse_remove_list(&text));
        }
        Err(anyhow!("LLM agent exceeded its {}-step tool budget", self.max_steps))
    }
}

fn extract_text(resp: &Value) -> String {
    resp.get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| {
                    if b.get("type").and_then(Value::as_str) == Some("text") {
                        b.get("text").and_then(Value::as_str)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…[truncated]", &s[..max])
    } else {
        s.to_string()
    }
}

/// Pull the `remove` array out of the model's reply (tolerant of prose around it).
fn parse_remove_list(text: &str) -> Vec<String> {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            if let Ok(v) = serde_json::from_str::<Value>(&text[start..=end]) {
                if let Some(arr) = v.get("remove").and_then(Value::as_array) {
                    return arr
                        .iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect();
                }
            }
        }
    }
    Vec::new()
}
