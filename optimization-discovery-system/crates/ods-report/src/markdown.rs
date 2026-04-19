use ods_core::TargetSig;
use ods_lang::ProfileReport;
use ods_measure::SpeedupVerdict;
use ods_recipes::{Recipe, RecipeId};
use ods_verify::GateReport;
use std::fmt::Write;

pub struct ReportInputs<'a> {
    pub target: &'a TargetSig,
    pub recipes_applied: &'a [RecipeId],
    pub speedup: &'a SpeedupVerdict,
    pub pre_profile: &'a ProfileReport,
    pub post_profile: &'a ProfileReport,
    pub gate: &'a GateReport,
    pub reproduction_cmd: &'a str,
    /// Optional hydrated recipe records for `recipes_applied`. When
    /// present, we render each recipe's negative_history so reviewers can
    /// see which other repos the pattern has failed on.
    pub recipe_records: &'a [Recipe],
}

pub fn render_pr_body(i: &ReportInputs) -> String {
    let mut s = String::new();
    writeln!(
        s,
        "## {:.2}x speedup on `{}` (lower bound {:.2}x @ {:.0}% CI)",
        i.speedup.speedup_point,
        i.target,
        i.speedup.speedup_lower,
        i.speedup.pre.confidence * 100.0
    )
    .ok();
    writeln!(s).ok();

    writeln!(s, "**Recipes applied:**").ok();
    if i.recipes_applied.is_empty() {
        writeln!(s, "- _none (cold-start discovery)_").ok();
    } else {
        for r in i.recipes_applied {
            let hydrated = i.recipe_records.iter().find(|rec| rec.id == *r);
            match hydrated {
                Some(rec) => {
                    writeln!(
                        s,
                        "- `{}` — {:?} · {} win(s), {} prior negative(s)",
                        rec.id,
                        rec.promotion,
                        rec.success_history.len(),
                        rec.negative_history.len(),
                    )
                    .ok();
                }
                None => {
                    writeln!(s, "- `{}`", r).ok();
                }
            }
        }
    }
    writeln!(s).ok();

    // Negative-history disclosure: if any retrieved recipe has a track
    // record of failures, surface it so reviewers can weigh the risk.
    let negatives: Vec<(&Recipe, usize)> = i
        .recipe_records
        .iter()
        .map(|r| (r, r.negative_history.len()))
        .filter(|(_, n)| *n > 0)
        .collect();
    if !negatives.is_empty() {
        writeln!(s, "### Prior failures on retrieved recipes").ok();
        writeln!(
            s,
            "These retrieved patterns have not helped on every codebase."
        )
        .ok();
        writeln!(
            s,
            "| recipe | prior negatives | most recent outcome | on repo |"
        )
        .ok();
        writeln!(
            s,
            "|--------|-----------------|---------------------|---------|"
        )
        .ok();
        for (recipe, _) in negatives {
            let last = recipe.negative_history.last();
            let (last_outcome, last_repo) = match last {
                Some(n) => (format!("{:?}", n.outcome), n.repo.clone()),
                None => ("—".into(), "—".into()),
            };
            writeln!(
                s,
                "| `{}` | {} | {} | {} |",
                recipe.id,
                recipe.negative_history.len(),
                last_outcome,
                last_repo
            )
            .ok();
        }
        writeln!(s).ok();
    }

    writeln!(s, "### Timing").ok();
    writeln!(s, "|       | mean (ns) | CI lower | CI upper |").ok();
    writeln!(s, "|-------|-----------|----------|----------|").ok();
    writeln!(
        s,
        "| pre   | {:.1}    | {:.1}    | {:.1}    |",
        i.speedup.pre.point, i.speedup.pre.lower, i.speedup.pre.upper
    )
    .ok();
    writeln!(
        s,
        "| post  | {:.1}    | {:.1}    | {:.1}    |",
        i.speedup.post.point, i.speedup.post.lower, i.speedup.post.upper
    )
    .ok();
    writeln!(s).ok();

    writeln!(s, "### Syscalls (pre -> post)").ok();
    let pre_sys: std::collections::HashMap<&str, u64> = i
        .pre_profile
        .syscall_counts
        .iter()
        .map(|(n, c)| (n.as_str(), *c))
        .collect();
    let post_sys: std::collections::HashMap<&str, u64> = i
        .post_profile
        .syscall_counts
        .iter()
        .map(|(n, c)| (n.as_str(), *c))
        .collect();
    let mut keys: std::collections::BTreeSet<&str> = pre_sys.keys().copied().collect();
    keys.extend(post_sys.keys().copied());
    if keys.is_empty() {
        writeln!(s, "_no syscall data collected_").ok();
    } else {
        writeln!(s, "| syscall | pre | post | delta |").ok();
        writeln!(s, "|---------|-----|------|-------|").ok();
        for k in keys {
            let a = *pre_sys.get(k).unwrap_or(&0);
            let b = *post_sys.get(k).unwrap_or(&0);
            writeln!(s, "| {} | {} | {} | {} |", k, a, b, (b as i64) - (a as i64)).ok();
        }
    }
    writeln!(s).ok();

    writeln!(s, "### Compatibility").ok();
    match i.gate.decision {
        ods_verify::GateDecision::Pass => writeln!(s, "- zero-diff gate: **PASS**").ok(),
        ods_verify::GateDecision::Fail => writeln!(s, "- zero-diff gate: **FAIL**").ok(),
    };
    for r in &i.gate.reasons {
        writeln!(s, "  - {}", r).ok();
    }
    writeln!(s).ok();

    writeln!(s, "### Reproduce").ok();
    writeln!(s, "```\n{}\n```", i.reproduction_cmd).ok();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ods_measure::{ConfidenceInterval, Sample, SpeedupVerdict};

    fn dummy_profile() -> ProfileReport {
        ProfileReport {
            wall: std::time::Duration::from_millis(1),
            cycles: None,
            instructions: None,
            llc_misses: None,
            branch_misses: None,
            syscall_counts: vec![("read".into(), 10), ("stat".into(), 42)],
            alloc_count: None,
            alloc_bytes: None,
            flame_svg_path: None,
        }
    }

    fn dummy_verdict() -> SpeedupVerdict {
        SpeedupVerdict {
            pre: ConfidenceInterval {
                lower: 900.0,
                point: 1000.0,
                upper: 1100.0,
                confidence: 0.99,
            },
            post: ConfidenceInterval {
                lower: 400.0,
                point: 500.0,
                upper: 600.0,
                confidence: 0.99,
            },
            speedup_point: 2.0,
            speedup_lower: 1.5,
            accepted: true,
            note: "2x".into(),
        }
    }

    #[test]
    fn renders_headline_and_sections() {
        let target = TargetSig {
            language: "rust".into(),
            module: "std::fs".into(),
            symbol: "read_dir".into(),
            arity: None,
        };
        let gate = GateReport {
            decision: ods_verify::GateDecision::Pass,
            reasons: vec![],
        };
        let pre = dummy_profile();
        let post = ProfileReport {
            syscall_counts: vec![("read".into(), 10), ("stat".into(), 0)],
            ..dummy_profile()
        };
        let v = dummy_verdict();
        let body = render_pr_body(&ReportInputs {
            target: &target,
            recipes_applied: &[],
            speedup: &v,
            pre_profile: &pre,
            post_profile: &post,
            gate: &gate,
            reproduction_cmd: "ods run . --target rust::std::fs::read_dir",
            recipe_records: &[],
        });
        assert!(body.contains("2.00x"));
        assert!(body.contains("Syscalls"));
        assert!(body.contains("zero-diff gate: **PASS**"));
    }

    fn _sample_unused() -> Sample {
        Sample {
            name: "x".into(),
            values_ns: vec![],
        }
    }
}
