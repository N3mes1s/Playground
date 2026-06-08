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
    /// The vulnerable code is gated to OS/arch we don't target, so it isn't
    /// compiled into our binary (e.g. a Windows-only bug on a Linux build).
    VulnerableCodeNotPresent,
}

impl Justification {
    pub fn as_str(self) -> &'static str {
        match self {
            Justification::ComponentNotPresent => "component_not_present",
            Justification::VulnerableCodeNotInExecutePath => "vulnerable_code_not_in_execute_path",
            Justification::VulnerableCodeNotPresent => "vulnerable_code_not_present",
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

/// A build-positioned `*-src` crate (the vendored-native-source convention,
/// e.g. `openssl-src`) compiles C/C++ that its `*-sys` sibling statically links
/// **into the shipped binary** — so even though the *Rust crate* runs only at
/// build time, its output is in the execute path. If the sibling `<base>-sys`
/// ships at runtime, we must not clear the `-src` crate as "not in execute path".
fn compiles_into_binary(crate_name: &str, runtime_set: &BTreeSet<String>) -> bool {
    crate_name
        .strip_suffix("-src")
        .map(|base| runtime_set.contains(&format!("{base}-sys")))
        .unwrap_or(false)
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
    } else if !runtime && compiles_into_binary(crate_name, runtime_set) {
        (
            Status::UnderInvestigation,
            None,
            format!(
                "`{crate_name}` runs at build time, but it compiles native code that its `{}-sys` \
                 sibling statically links into {product}'s binary — so the vulnerable code can \
                 still ship. Build-position does not clear it; manual review required.",
                crate_name.strip_suffix("-src").unwrap_or(crate_name)
            ),
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

/// Build a single OpenVEX statement (not a full document) for one assessment.
pub fn vex_statement(
    a: &Assessment,
    vuln_id: &str,
    crate_version: Option<&str>,
) -> serde_json::Value {
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
    statement
}

/// Wrap one or more VEX statements in an OpenVEX document.
pub fn vex_document(statements: Vec<serde_json::Value>) -> serde_json::Value {
    use serde_json::json;
    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("https://openvex.dev/docs/carve/{}", uuid_like()),
        "author": "carve",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": 1,
        "statements": statements,
    })
}

/// A cheap, dependency-free document id (timestamp-based; VEX only needs it
/// stable within the doc, not globally unique).
fn uuid_like() -> String {
    format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0))
}

/// Render an [`Assessment`] as a single-statement OpenVEX document.
pub fn to_vex(a: &Assessment, vuln_id: &str, crate_version: Option<&str>) -> serde_json::Value {
    vex_document(vec![vex_statement(a, vuln_id, crate_version)])
}

/// One finding pulled out of a `cargo audit --json` report.
#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub id: String,
    pub crate_name: String,
    pub version: Option<String>,
    /// "vulnerability", "unmaintained", "unsound", "yanked", …
    pub kind: String,
    /// Affected function paths the advisory names, if any (e.g. `atty::is`).
    pub functions: Vec<String>,
    /// OS values the advisory is gated to (`windows`, `linux`, …). Empty = all.
    pub os: Vec<String>,
    /// Arch values the advisory is gated to (`x86_64`, `aarch64`, …). Empty = all.
    pub arch: Vec<String>,
    pub title: String,
}

/// Extract findings from a `cargo audit --json` document, tolerant of schema
/// drift: real vulnerabilities (`vulnerabilities.list`) and every warning
/// category (`warnings.{unmaintained,unsound,yanked,…}`).
pub fn parse_audit_report(v: &serde_json::Value) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    let mut push = |entry: &serde_json::Value, kind: &str| {
        let adv = &entry["advisory"];
        let id = adv["id"].as_str().unwrap_or("UNKNOWN").to_string();
        let title = adv["title"].as_str().unwrap_or("").to_string();
        let crate_name = entry["package"]["name"]
            .as_str()
            .or_else(|| adv["package"].as_str())
            .unwrap_or("")
            .to_string();
        let version = entry["package"]["version"].as_str().map(str::to_string);
        let functions = entry["affected"]["functions"]
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let str_list = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let os = str_list(&entry["affected"]["os"]);
        let arch = str_list(&entry["affected"]["arch"]);
        if !crate_name.is_empty() {
            out.push(AuditFinding {
                id,
                crate_name,
                version,
                kind: kind.to_string(),
                functions,
                os,
                arch,
                title,
            });
        }
    };
    if let Some(list) = v["vulnerabilities"]["list"].as_array() {
        for e in list {
            push(e, "vulnerability");
        }
    }
    if let Some(cats) = v["warnings"].as_object() {
        for (cat, arr) in cats {
            if let Some(arr) = arr.as_array() {
                for e in arr {
                    push(e, cat);
                }
            }
        }
    }
    out
}

/// Load a function-localization file (e.g. arbor's output) into
/// `advisory id -> [symbol/type/entrypoint paths]`. Tolerant of two record
/// shapes, both collapsing to a flat path set carve matches reachability on:
///
/// - rich: an object with `vulnerable_symbols` / `public_entrypoints` /
///   `vulnerable_types` (arrays of strings or `{"path":..}`) and/or `functions`.
/// - cargo-audit projection: an object whose keys are the paths
///   (`{ "crate::path::fn": ["<version range>"] }`).
pub fn load_enrichment(
    path: &std::path::Path,
) -> anyhow::Result<std::collections::BTreeMap<String, Vec<String>>> {
    use anyhow::Context;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading enrichment file {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw).context("parsing enrichment JSON")?;
    let mut out = std::collections::BTreeMap::new();
    let Some(obj) = v.as_object() else {
        anyhow::bail!("enrichment file must be a JSON object keyed by advisory id");
    };
    for (id, rec) in obj {
        let mut paths: BTreeSet<String> = BTreeSet::new();
        if let Some(r) = rec.as_object() {
            let known = [
                "functions",
                "public_entrypoints",
                "vulnerable_symbols",
                "vulnerable_types",
            ];
            for key in known {
                collect_paths(r.get(key), &mut paths);
            }
            // cargo-audit projection: no known keys -> the keys themselves are paths.
            if paths.is_empty() {
                for k in r.keys() {
                    paths.insert(k.clone());
                }
            }
        }
        if !paths.is_empty() {
            out.insert(id.clone(), paths.into_iter().collect());
        }
    }
    Ok(out)
}

/// Pull paths out of a value that may be: an array of strings, an array of
/// `{"path": ".."}` objects, or an object whose keys are paths.
fn collect_paths(v: Option<&serde_json::Value>, out: &mut BTreeSet<String>) {
    match v {
        Some(serde_json::Value::Array(arr)) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    out.insert(s.to_string());
                } else if let Some(p) = item.get("path").and_then(|p| p.as_str()) {
                    out.insert(p.to_string());
                }
            }
        }
        Some(serde_json::Value::Object(map)) => {
            for k in map.keys() {
                out.insert(k.clone());
            }
        }
        _ => {}
    }
}

fn severity(s: Status) -> u8 {
    match s {
        Status::Affected => 2,
        Status::UnderInvestigation => 1,
        Status::NotAffected => 0,
    }
}

/// An advisory gated to a platform list excludes our target when the list is
/// non-empty and doesn't mention us — the vulnerable `#[cfg(...)]` code then
/// isn't compiled into our binary at all.
fn platform_excludes(list: &[String], target: &str) -> bool {
    !list.is_empty() && !list.iter().any(|x| x == target)
}

/// Assess one audit finding against a build target (`target_os`/`target_arch`,
/// e.g. `linux`/`x86_64`). When the advisory names specific functions, every one
/// is checked and the **most severe** verdict wins (recall-biased — any reachable
/// vulnerable function makes the whole finding reachable).
pub fn assess_finding(
    product: &str,
    finding: &AuditFinding,
    present_set: &BTreeSet<String>,
    runtime_set: &BTreeSet<String>,
    graph: &TransitiveGraph,
    target_os: &str,
    target_arch: &str,
) -> Assessment {
    // Platform gate: a Windows-only (or other off-target) bug isn't compiled
    // into our binary. Sound for the target we build — assumes the report's
    // target matches the deploy target (override with --target-os/--target-arch).
    if platform_excludes(&finding.os, target_os) || platform_excludes(&finding.arch, target_arch) {
        let mut gate = Vec::new();
        if platform_excludes(&finding.os, target_os) {
            gate.push(format!("os {:?} (target {target_os})", finding.os));
        }
        if platform_excludes(&finding.arch, target_arch) {
            gate.push(format!("arch {:?} (target {target_arch})", finding.arch));
        }
        return Assessment {
            product: product.to_string(),
            crate_name: finding.crate_name.clone(),
            symbol: None,
            status: Status::NotAffected,
            justification: Some(Justification::VulnerableCodeNotPresent),
            present: present_set.contains(&finding.crate_name),
            runtime: runtime_set.contains(&finding.crate_name),
            reached_by: Vec::new(),
            matched_items: Vec::new(),
            rationale: format!(
                "`{}` is vulnerable only on {} — not compiled into {product}'s build for this \
                 target, so the vulnerable code is not present.",
                finding.crate_name,
                gate.join(" / ")
            ),
        };
    }
    if finding.functions.is_empty() {
        return assess(
            product,
            &finding.crate_name,
            None,
            present_set,
            runtime_set,
            graph,
        );
    }
    let mut worst: Option<Assessment> = None;
    for f in &finding.functions {
        // Match on the function's leaf segment (`atty::is` -> `is`).
        let sym = f.rsplit("::").next().unwrap_or(f);
        let a = assess(
            product,
            &finding.crate_name,
            Some(sym),
            present_set,
            runtime_set,
            graph,
        );
        worst = Some(match worst {
            Some(w) if severity(w.status) >= severity(a.status) => w,
            _ => a,
        });
    }
    worst.expect("functions is non-empty")
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
    fn vendored_native_src_crate_is_not_cleared_as_build_only() {
        // openssl-src runs at build time, but compiles OpenSSL that openssl-sys
        // links into the binary. It must NOT be cleared just because it's not in
        // the normal closure — that would be a false "safe".
        let g = graph(vec![]);
        let a = assess(
            "app",
            "openssl-src",
            None,
            &set(&["openssl-src", "openssl-sys"]),
            &set(&["openssl-sys"]), // -sys ships; -src is build-only
            &g,
        );
        assert_eq!(a.status, Status::UnderInvestigation);
        assert!(a.justification.is_none());
    }

    fn finding(crate_name: &str, os: &[&str], arch: &[&str]) -> AuditFinding {
        AuditFinding {
            id: "RUSTSEC-TEST".into(),
            crate_name: crate_name.into(),
            version: Some("1.0.0".into()),
            kind: "vulnerability".into(),
            functions: vec![],
            os: os.iter().map(|s| s.to_string()).collect(),
            arch: arch.iter().map(|s| s.to_string()).collect(),
            title: String::new(),
        }
    }

    #[test]
    fn windows_only_advisory_is_cleared_on_linux_target() {
        // mio NamedPipe bug: os = ["windows"]. On a linux build it's not compiled.
        let g = graph(vec![edge("app", "mio", &["mio::Poll"])]);
        let f = finding("mio", &["windows"], &[]);
        let a = assess_finding(
            "app",
            &f,
            &set(&["mio"]),
            &set(&["mio"]),
            &g,
            "linux",
            "x86_64",
        );
        assert_eq!(a.status, Status::NotAffected);
        assert_eq!(
            a.justification,
            Some(Justification::VulnerableCodeNotPresent)
        );
    }

    #[test]
    fn windows_only_advisory_is_kept_on_windows_target() {
        // Same finding, but we ship to windows — must not be cleared by platform.
        let g = graph(vec![edge("app", "mio", &["mio::Poll"])]);
        let f = finding("mio", &["windows"], &[]);
        let a = assess_finding(
            "app",
            &f,
            &set(&["mio"]),
            &set(&["mio"]),
            &g,
            "windows",
            "x86_64",
        );
        assert_ne!(a.status, Status::NotAffected);
    }

    #[test]
    fn load_enrichment_handles_rich_and_projection_shapes() {
        let dir = std::env::temp_dir().join(format!("carve-enrich-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Rich record (arbor's shape) + a cargo-audit projection record.
        let f = dir.join("enrich.json");
        std::fs::write(
            &f,
            r#"{
              "RUSTSEC-2026-0007": {
                "vulnerable_symbols": [{"path":"bytes::bytes_mut::BytesMut::reserve_inner"}],
                "vulnerable_types":   [{"path":"bytes::bytes_mut::BytesMut"}],
                "public_entrypoints": ["bytes::bytes_mut::BytesMut::reserve"]
              },
              "RUSTSEC-2099-9999": { "foo::bar::baz": [">=1.0.0, <2.0.0"] }
            }"#,
        )
        .unwrap();
        let map = load_enrichment(&f).unwrap();
        let a = map.get("RUSTSEC-2026-0007").unwrap();
        assert!(a.contains(&"bytes::bytes_mut::BytesMut::reserve_inner".to_string()));
        assert!(a.contains(&"bytes::bytes_mut::BytesMut".to_string()));
        assert!(a.contains(&"bytes::bytes_mut::BytesMut::reserve".to_string()));
        // projection: the key itself is the path
        assert_eq!(
            map.get("RUSTSEC-2099-9999").unwrap(),
            &vec!["foo::bar::baz".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrichment_can_only_de_noise_never_clear() {
        // A finding enriched with functions that AREN'T reached -> under_investigation,
        // never not_affected. (Guards the "can't manufacture a false clear" property.)
        let g = graph(vec![edge("app", "bytes", &["bytes::Bytes"])]);
        let f = AuditFinding {
            id: "RUSTSEC-2026-0007".into(),
            crate_name: "bytes".into(),
            version: Some("1.9.0".into()),
            kind: "vulnerability".into(),
            functions: vec!["bytes::BytesMut".into(), "reserve_inner".into()],
            os: vec![],
            arch: vec![],
            title: String::new(),
        };
        let a = assess_finding(
            "app",
            &f,
            &set(&["bytes"]),
            &set(&["bytes"]),
            &g,
            "linux",
            "x86_64",
        );
        assert_eq!(a.status, Status::UnderInvestigation);
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
