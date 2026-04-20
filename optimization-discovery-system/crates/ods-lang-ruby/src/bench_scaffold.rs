//! Scaffold a minimal `benchmark-ips` harness for a Ruby target when
//! the project doesn't ship one. Mirrors the Rust adapter's
//! `bench_scaffold` so the Ruby end-to-end loop can produce
//! before/after numbers on repos like Bootsnap that don't carry a
//! `benchmark/` directory.
//!
//! Output: a single `benchmark/ods_auto_<target>.rb` file that invokes
//! the target function and runs benchmark-ips for ~2 seconds. A second
//! pass ensures the project's Gemfile lists `benchmark-ips` so
//! `bundle install` provides it.

use anyhow::{Context, Result};
use ods_core::TargetSig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaffoldOutcome {
    /// Path to the scaffolded bench file, relative to the repo root.
    pub bench_file: PathBuf,
    /// Bench name used as the `benchmark-ips` report label and file
    /// stem; safe to embed in shell commands.
    pub bench_name: String,
    pub created_files: Vec<PathBuf>,
    pub modified_files: Vec<PathBuf>,
    /// Whether we appended `benchmark-ips` to the Gemfile. The PR body
    /// should mention this so reviewers see the dep delta.
    pub added_benchmark_ips_dep: bool,
}

/// Skip scaffolding when the project already ships any `benchmark/`
/// content (single Ruby file or sub-directory both count).
pub fn has_existing_bench(repo: &Path) -> bool {
    let dir = repo.join("benchmark");
    if !dir.is_dir() {
        return false;
    }
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return false;
    };
    rd.flatten().any(|_| true)
}

/// Scaffold `benchmark/ods_auto_<target>.rb` + add `benchmark-ips` to
/// the Gemfile if missing. Idempotent: re-running with the same target
/// returns the existing outcome unchanged.
pub fn scaffold(repo: &Path, target: &TargetSig) -> Result<ScaffoldOutcome> {
    let bench_name = format!(
        "ods_auto_{}",
        target
            .symbol
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    );
    let benches_dir = repo.join("benchmark");
    std::fs::create_dir_all(&benches_dir).context("create benchmark/")?;
    let bench_file = benches_dir.join(format!("{bench_name}.rb"));

    let mut created = Vec::new();
    let mut modified = Vec::new();

    if !bench_file.exists() {
        let body = render_bench(target, &bench_name);
        std::fs::write(&bench_file, body).context("write bench file")?;
        created.push(bench_file.clone());
    }

    let added_dep = ensure_benchmark_ips_in_gemfile(repo)?;
    if added_dep {
        modified.push(repo.join("Gemfile"));
    }

    Ok(ScaffoldOutcome {
        bench_file,
        bench_name,
        created_files: created,
        modified_files: modified,
        added_benchmark_ips_dep: added_dep,
    })
}

/// Render the bench file body. Deliberately conservative: the
/// scaffold only EXERCISES the target — it doesn't try to
/// auto-construct realistic args. The specialist that runs after
/// this is expected to refine `realistic_input` with sensible inputs
/// via edit_file if the mock isn't right. The PR body calls out
/// the bench harness as scaffolded so reviewers know.
fn render_bench(target: &TargetSig, bench_name: &str) -> String {
    let module_path = target
        .module
        .split("::")
        .filter(|s| !s.is_empty())
        .map(|s| capitalise(s))
        .collect::<Vec<_>>()
        .join("::");
    let invocation = if module_path.is_empty() {
        format!("{}(realistic_input)", target.symbol)
    } else {
        format!("{module_path}.{}(realistic_input)", target.symbol)
    };
    format!(
        r#"# Auto-scaffolded by ods (optimization-discovery-system).
# Exercises `{module}::{symbol}` under benchmark-ips so the loop has a
# pre/post sample to compare. Replace `realistic_input` with a value
# that mirrors the production hot-path; the loop will pick up changes
# on the next run without a re-scaffold.

require "bundler/setup"
require "benchmark/ips"

# TODO(ods): replace with a representative input.
realistic_input = nil

Benchmark.ips do |x|
  x.config(time: 2, warmup: 0.5)
  x.report({bench_name:?}) do
    {invocation}
  end
end
"#,
        module = target.module,
        symbol = target.symbol,
        bench_name = bench_name,
        invocation = invocation,
    )
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().chain(chars).collect(),
    }
}

/// Append a `gem "benchmark-ips"` line to the Gemfile if not already
/// present. Returns true when the file was modified.
fn ensure_benchmark_ips_in_gemfile(repo: &Path) -> Result<bool> {
    let gemfile = repo.join("Gemfile");
    if !gemfile.exists() {
        // No Gemfile = not a bundle-managed project; the user is on
        // their own to install benchmark-ips. Don't try to create one.
        return Ok(false);
    }
    let content = std::fs::read_to_string(&gemfile).context("read Gemfile")?;
    if content
        .lines()
        .any(|l| l.contains("\"benchmark-ips\"") || l.contains("'benchmark-ips'"))
    {
        return Ok(false);
    }
    let mut updated = content;
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("\n# Added by ods scaffold for the bench harness.\n");
    updated.push_str("gem \"benchmark-ips\"\n");
    std::fs::write(&gemfile, updated).context("write Gemfile")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(module: &str, symbol: &str) -> TargetSig {
        TargetSig {
            language: "ruby".into(),
            module: module.into(),
            symbol: symbol.into(),
            arity: None,
        }
    }

    #[test]
    fn scaffold_creates_benchmark_file_and_marks_dep_added() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::write(repo.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();
        let out = scaffold(repo, &target("path_scanner", "native_call")).unwrap();
        assert!(
            out.bench_file
                .ends_with("benchmark/ods_auto_native_call.rb"),
            "got {}",
            out.bench_file.display()
        );
        assert!(out.bench_file.exists());
        assert_eq!(out.created_files.len(), 1);
        assert!(out.added_benchmark_ips_dep);
        let body = std::fs::read_to_string(&out.bench_file).unwrap();
        assert!(body.contains("benchmark/ips"));
        assert!(body.contains("native_call"));
        let gem = std::fs::read_to_string(repo.join("Gemfile")).unwrap();
        assert!(gem.contains("benchmark-ips"));
    }

    #[test]
    fn scaffold_is_idempotent_on_repeat_run() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::write(
            repo.join("Gemfile"),
            "source 'https://rubygems.org'\ngem 'benchmark-ips'\n",
        )
        .unwrap();
        let out1 = scaffold(repo, &target("foo", "bar")).unwrap();
        assert!(!out1.added_benchmark_ips_dep, "Gemfile already had it");
        // Second pass: no new files, no new dep.
        let out2 = scaffold(repo, &target("foo", "bar")).unwrap();
        assert!(out2.created_files.is_empty());
        assert!(!out2.added_benchmark_ips_dep);
    }

    #[test]
    fn has_existing_bench_detects_populated_dir() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        assert!(!has_existing_bench(repo));
        std::fs::create_dir_all(repo.join("benchmark")).unwrap();
        // Empty dir still counts as "no bench" — we want to scaffold.
        assert!(!has_existing_bench(repo));
        std::fs::write(repo.join("benchmark/foo_bench.rb"), "puts 'hi'\n").unwrap();
        assert!(has_existing_bench(repo));
    }
}
