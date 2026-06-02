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

use crate::model::{Confidence, CrateMinimization, MinimizationPlan, SliceReport, UsageGraph};
use crate::slice;
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
        let out = Command::new("cargo")
            .args(["check", "--manifest-path", &manifest, "--message-format=short"])
            .output()
            .context("spawning cargo check")?;
        Ok(json!({
            "success": out.status.success(),
            "stderr": String::from_utf8_lossy(&out.stderr),
        }))
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
