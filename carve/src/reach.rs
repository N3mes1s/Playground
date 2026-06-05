//! CVE reachability triage — the highest-value use of the DFUG.
//!
//! Given an advisory ("crate `foo` is vulnerable, in function `bar`"), answer
//! the question every security team asks: *are we actually affected?* — and emit
//! an auditable [VEX](https://openvex.dev) statement.
//!
//! The analysis is **recall-biased on purpose**. The DFUG resolver is syntactic
//! (it can't see method-call receivers, macro-expanded code, or re-exports), so
//! a *false "not affected"* would be dangerous. We therefore only assert
//! `not_affected` when it follows from the dependency *structure* — which is
//! sound regardless of the scanner's blind spots:
//!
//!  - the crate is absent from the resolved tree  → `component_not_present`;
//!  - the crate is present but not in the runtime closure (pulled only via
//!    dev/build/target-gated edges, so it never ships in the binary)
//!    → `vulnerable_code_not_in_execute_path`.
//!
//! For a crate that *does* ship, item-level evidence can only ever *raise*
//! suspicion (an explicit reference to the vulnerable symbol → `affected`) or
//! leave it `under_investigation` (reached, but the symbol wasn't seen — which
//! we never downgrade to "safe"). That asymmetry is the whole point.

use crate::model::TransitiveGraph;
use serde::Serialize;
use std::collections::BTreeSet;

/// VEX status, mirroring the OpenVEX / CSAF vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    NotAffected,
    Affected,
    UnderInvestigation,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::NotAffected => "not_affected",
            Status::Affected => "affected",
            Status::UnderInvestigation => "under_investigation",
        }
    }
}

/// VEX justification (only meaningful for `not_affected`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Justification {
    ComponentNotPresent,
    VulnerableCodeNotInExecutePath,
}

impl Justification {
    pub fn as_str(self) -> &'static str {
        match self {
            Justification::ComponentNotPresent => "component_not_present",
            Justification::VulnerableCodeNotInExecutePath => "vulnerable_code_not_in_execute_path",
        }
    }
}

/// One crate that functionally reaches the vulnerable crate, and via which items.
#[derive(Debug, Clone, Serialize)]
pub struct ReachedBy {
    pub from: String,
    pub items: Vec<String>,
}

/// The full reachability verdict for one (product, advisory) pair.
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub product: String,
    pub crate_name: String,
    /// The advisory's vulnerable symbol, if one was supplied.
    pub symbol: Option<String>,
    pub status: Status,
    pub justification: Option<Justification>,
    /// Present anywhere in the resolved tree (incl. dev/build).
    pub present: bool,
    /// Reachable through normal edges only — i.e. ships in the binary.
    pub runtime: bool,
    /// Crates whose source functionally references the vulnerable crate.
    pub reached_by: Vec<ReachedBy>,
    /// Item paths into the vulnerable crate that match the advisory symbol.
    pub matched_items: Vec<String>,
    /// Plain-language explanation of the verdict.
    pub rationale: String,
}

/// Does an observed item path plausibly reach `symbol`? Recall-biased: a match
/// on any path segment counts, and a referenced *module* that could contain the
/// symbol counts too (we can't see inside it syntactically).
fn path_reaches_symbol(item_path: &str, symbol: &str) -> bool {
    // `foo::buffer::read_to_end` -> ["foo","buffer","read_to_end"]; the leading
    // segment is the crate ident, so any later segment matching the symbol — or
    // the symbol matching the path's leaf — is a hit.
    item_path.split("::").skip(1).any(|seg| seg == symbol)
        || symbol.split("::").last() == item_path.split("::").last()
}

/// Assess whether `crate_name` (optionally narrowed to `symbol`) is reachable.
///
/// - `present`: every package name in the resolved tree.
/// - `runtime`: package names reachable via normal-only edges (the binary).
/// - `graph`: the transitive DFUG, for the item-level evidence trail.
pub fn assess(
    product: &str,
    crate_name: &str,
    symbol: Option<&str>,
    present_set: &BTreeSet<String>,
    runtime_set: &BTreeSet<String>,
    graph: &TransitiveGraph,
) -> Assessment {
    let present = present_set.contains(crate_name);
    let runtime = runtime_set.contains(crate_name);

    // Evidence: every functional edge into the vulnerable crate.
    let mut reached_by: Vec<ReachedBy> = graph
        .edges
        .iter()
        .filter(|e| e.to == crate_name)
        .map(|e| ReachedBy {
            from: e.from.clone(),
            items: e.item_paths.clone(),
        })
        .collect();
    reached_by.sort_by(|a, b| a.from.cmp(&b.from));

    let matched_items: Vec<String> = match symbol {
        Some(sym) => {
            let mut m: BTreeSet<String> = BTreeSet::new();
            for r in &reached_by {
                for it in &r.items {
                    if path_reaches_symbol(it, sym) {
                        m.insert(it.clone());
                    }
                }
            }
            m.into_iter().collect()
        }
        None => Vec::new(),
    };

    let (status, justification, rationale) = if !present {
        (
            Status::NotAffected,
            Some(Justification::ComponentNotPresent),
            format!("`{crate_name}` is not in {product}'s resolved dependency tree at all."),
        )
    } else if !runtime {
        (
            Status::NotAffected,
            Some(Justification::VulnerableCodeNotInExecutePath),
            format!(
                "`{crate_name}` is present only via dev/build/target-gated edges — it is not \
                 reachable through normal dependencies, so it does not ship in {product}'s \
                 production binary."
            ),
        )
    } else if symbol.is_some() && !matched_items.is_empty() {
        (
            Status::Affected,
            None,
            format!(
                "`{crate_name}` ships in the binary and {} crate(s) reference the vulnerable \
                 symbol on a resolved path ({}).",
                reached_by.len(),
                matched_items.join(", ")
            ),
        )
    } else if symbol.is_some() {
        (
            Status::UnderInvestigation,
            None,
            format!(
                "`{crate_name}` ships in the binary and is reached by {} crate(s), but no \
                 syntactic reference to `{}` was observed. The DFUG cannot rule out method-call, \
                 macro, or re-export paths — manual review required (treat as reachable).",
                reached_by.len(),
                symbol.unwrap_or("")
            ),
        )
    } else {
        (
            Status::Affected,
            None,
            format!(
                "`{crate_name}` ships in {product}'s production binary (reached by {} crate(s)); \
                 with no specific symbol to narrow to, the whole crate is in scope.",
                reached_by.len()
            ),
        )
    };

    Assessment {
        product: product.to_string(),
        crate_name: crate_name.to_string(),
        symbol: symbol.map(str::to_string),
        status,
        justification,
        present,
        runtime,
        reached_by,
        matched_items,
        rationale,
    }
}

/// Render an [`Assessment`] as a single-statement OpenVEX document.
pub fn to_vex(a: &Assessment, vuln_id: &str, crate_version: Option<&str>) -> serde_json::Value {
    use serde_json::json;
    let purl = match crate_version {
        Some(v) => format!("pkg:cargo/{}@{}", a.crate_name, v),
        None => format!("pkg:cargo/{}", a.crate_name),
    };
    let mut statement = json!({
        "vulnerability": { "name": vuln_id },
        "products": [ format!("pkg:cargo/{}", a.product) ],
        "subcomponents": [ { "@id": purl } ],
        "status": a.status.as_str(),
        "impact_statement": a.rationale,
    });
    if let Some(j) = a.justification {
        statement["justification"] = json!(j.as_str());
    }
    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("https://openvex.dev/docs/carve/{}-{}", a.crate_name, vuln_id),
        "author": "carve",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": 1,
        "statements": [ statement ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DepEdge, TgNode, TransitiveGraph};

    fn graph(edges: Vec<DepEdge>) -> TransitiveGraph {
        TransitiveGraph {
            package: "app".into(),
            generated_at: chrono::Utc::now(),
            nodes: vec![TgNode {
                name: "app".into(),
                version: "0.1.0".into(),
                depth: 0,
                runtime: true,
            }],
            edges,
            scanned_crates: 1,
            max_depth: 1,
        }
    }

    fn edge(from: &str, to: &str, items: &[&str]) -> DepEdge {
        DepEdge {
            from: from.into(),
            to: to.into(),
            items: items.len(),
            refs: items.len(),
            item_paths: items.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn absent_crate_is_not_affected_component_not_present() {
        let g = graph(vec![]);
        let a = assess("app", "foo", None, &set(&[]), &set(&[]), &g);
        assert_eq!(a.status, Status::NotAffected);
        assert_eq!(a.justification, Some(Justification::ComponentNotPresent));
    }

    #[test]
    fn dev_only_crate_is_not_in_execute_path() {
        // present in the tree, but NOT in the runtime (normal-only) set.
        let g = graph(vec![]);
        let a = assess("app", "foo", None, &set(&["foo"]), &set(&[]), &g);
        assert_eq!(a.status, Status::NotAffected);
        assert_eq!(
            a.justification,
            Some(Justification::VulnerableCodeNotInExecutePath)
        );
    }

    #[test]
    fn shipped_crate_with_symbol_reference_is_affected() {
        let g = graph(vec![edge("app", "foo", &["foo::buffer::read_to_end"])]);
        let a = assess(
            "app",
            "foo",
            Some("read_to_end"),
            &set(&["foo"]),
            &set(&["foo"]),
            &g,
        );
        assert_eq!(a.status, Status::Affected);
        assert_eq!(a.matched_items, vec!["foo::buffer::read_to_end"]);
    }

    #[test]
    fn shipped_crate_without_symbol_reference_needs_review_not_safe() {
        // foo ships and is reached, but only via an unrelated item — the vulnerable
        // symbol is never seen. Must NOT be downgraded to not_affected.
        let g = graph(vec![edge("mid", "foo", &["foo::Encoder"])]);
        let a = assess(
            "app",
            "foo",
            Some("decode_header"),
            &set(&["foo"]),
            &set(&["foo"]),
            &g,
        );
        assert_eq!(a.status, Status::UnderInvestigation);
        assert!(a.matched_items.is_empty());
    }

    #[test]
    fn vex_carries_status_and_justification() {
        let g = graph(vec![]);
        let a = assess("app", "foo", None, &set(&[]), &set(&[]), &g);
        let v = to_vex(&a, "RUSTSEC-2024-0001", Some("1.2.3"));
        assert_eq!(v["statements"][0]["status"], "not_affected");
        assert_eq!(v["statements"][0]["justification"], "component_not_present");
        assert_eq!(
            v["statements"][0]["subcomponents"][0]["@id"],
            "pkg:cargo/foo@1.2.3"
        );
    }
}
