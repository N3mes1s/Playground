//! syn-based source scanner that extracts the Dependency Functional Usage Graph.
//!
//! Resolution strategy (deliberately syntactic, not a full type resolver):
//!  1. From every `use` item rooted at a known dependency, record the local
//!     name -> fully-qualified dependency path mapping.
//!  2. For every value/type/macro path reference, resolve its leading segment:
//!       - if it is a dependency crate ident   -> a fully-qualified reference;
//!       - else if it matches an import alias   -> expand to the dep path;
//!       - else                                 -> local/std, ignored.
//!
//! This is intentionally conservative: it under-reports (e.g. method calls whose
//! receiver type we can't resolve) rather than inventing edges. The agent's
//! verification build is what ultimately proves a slice is complete.

use super::metadata::DepInfo;
use crate::model::{RefKind, SourceRef};
use proc_macro2::LineColumn;
use std::collections::{BTreeMap, HashMap};
use syn::visit::Visit;
use syn::UseTree;

/// Collected references for one resolved dependency path.
#[derive(Default)]
pub struct PathHits {
    pub refs: Vec<SourceRef>,
}

/// Per-file scan results, keyed by fully-qualified dependency path.
pub struct ScanResult {
    pub hits: BTreeMap<String, PathHits>,
}

struct Visitor<'a> {
    /// code_ident -> DepInfo, for recognizing dependency roots.
    deps: &'a BTreeMap<String, DepInfo>,
    /// Local alias -> fully-qualified dependency path segments.
    imports: HashMap<String, Vec<String>>,
    file: String,
    hits: BTreeMap<String, PathHits>,
}

impl<'a> Visitor<'a> {
    fn new(deps: &'a BTreeMap<String, DepInfo>, file: String) -> Self {
        Visitor {
            deps,
            imports: HashMap::new(),
            file,
            hits: BTreeMap::new(),
        }
    }

    fn record(&mut self, path: String, line: usize, kind: RefKind) {
        self.hits.entry(path).or_default().refs.push(SourceRef {
            file: self.file.clone(),
            line,
            kind,
        });
    }

    /// Flatten a `use` tree into (full segments, local name) pairs and remember
    /// any that are rooted at a dependency crate.
    fn collect_use(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.collect_use(&p.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(n) => {
                let mut full = prefix.clone();
                full.push(n.ident.to_string());
                self.remember_import(n.ident.to_string(), full);
            }
            UseTree::Rename(r) => {
                let mut full = prefix.clone();
                full.push(r.ident.to_string());
                self.remember_import(r.rename.to_string(), full);
            }
            UseTree::Glob(_) => {
                // `use dep::module::*;` — we can't enumerate names, but record the
                // module itself as a (coarse) used item so it isn't dropped.
                if self.root_is_dep(prefix) && !prefix.is_empty() {
                    let path = prefix.join("::");
                    self.record(path, 0, RefKind::Import);
                }
            }
            UseTree::Group(g) => {
                for item in &g.items {
                    self.collect_use(item, prefix);
                }
            }
        }
    }

    fn root_is_dep(&self, segments: &[String]) -> bool {
        segments
            .first()
            .map(|root| self.deps.contains_key(root))
            .unwrap_or(false)
    }

    fn remember_import(&mut self, local: String, full: Vec<String>) {
        if self.root_is_dep(&full) {
            let line = 0; // use-site line is recorded when the alias is referenced
            self.record(full.join("::"), line.max(1), RefKind::Import);
            self.imports.insert(local, full);
        }
    }

    /// Resolve a referenced path's leading segment to a dependency path, if any.
    fn resolve(&self, segments: &[String]) -> Option<String> {
        let first = segments.first()?;
        if self.deps.contains_key(first) {
            // Fully-qualified `dep::a::b`.
            Some(segments.join("::"))
        } else if let Some(base) = self.imports.get(first) {
            // Imported alias: expand `Foo` (from `use dep::x::Foo`) plus any tail.
            let mut full = base.clone();
            full.extend(segments[1..].iter().cloned());
            Some(full.join("::"))
        } else {
            None
        }
    }

    fn handle_path(&mut self, path: &syn::Path, kind: RefKind) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segments.is_empty() {
            return;
        }
        if let Some(resolved) = self.resolve(&segments) {
            let line = line_of(path.segments[0].ident.span().start());
            self.record(resolved, line, kind);
        }
    }
}

fn line_of(lc: LineColumn) -> usize {
    lc.line.max(1)
}

impl<'ast, 'a> Visit<'ast> for Visitor<'a> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        self.collect_use(&node.tree, &mut prefix);
        // Do not recurse: a use tree contains no expressions to analyze.
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.handle_path(&node.path, RefKind::Value);
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        self.handle_path(&node.path, RefKind::Type);
        syn::visit::visit_type_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.handle_path(&node.path, RefKind::Macro);
        syn::visit::visit_macro(self, node);
    }
}

/// Scan one Rust source file's text into a [`ScanResult`].
pub fn scan_file(
    src: &str,
    rel_path: &str,
    deps: &BTreeMap<String, DepInfo>,
) -> syn::Result<ScanResult> {
    let ast = syn::parse_file(src)?;
    let mut visitor = Visitor::new(deps, rel_path.to_string());
    visitor.visit_file(&ast);
    Ok(ScanResult { hits: visitor.hits })
}
