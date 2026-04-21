//! Scaffold a minimal Criterion bench for a target function when the
//! project doesn't already ship one. The goal isn't to produce a
//! production-quality harness - it's to give the measurement pipeline a
//! structured pre/post sample so the race can pick a winner and the PR
//! body has real numbers to show. Reviewers are encouraged (via the PR
//! body) to keep the scaffolded file as a lasting improvement.

use anyhow::{Context, Result};
use ods_core::TargetSig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaffoldOutcome {
    /// Path to the scaffolded bench file, relative to the workspace root.
    pub bench_file: PathBuf,
    /// Bench name registered in Cargo.toml's `[[bench]]` block.
    pub bench_name: String,
    /// Files that were created / modified so a caller can mention them in
    /// the PR body.
    pub created_files: Vec<PathBuf>,
    pub modified_files: Vec<PathBuf>,
    /// Whether we needed to add `criterion` as a dev-dependency. When true
    /// the PR body should call this out.
    pub added_criterion_dep: bool,
}

/// Detect whether a bench harness already exists. We look for:
///   * any file under `benches/`
///   * any `[[bench]]` block in Cargo.toml
///   * any file whose stem contains "bench"
pub fn has_existing_bench(repo: &Path) -> bool {
    let benches_dir = repo.join("benches");
    if benches_dir.is_dir() {
        if let Ok(rd) = std::fs::read_dir(&benches_dir) {
            if rd.flatten().next().is_some() {
                return true;
            }
        }
    }
    if let Ok(cargo) = std::fs::read_to_string(repo.join("Cargo.toml")) {
        if cargo.contains("[[bench]]") {
            return true;
        }
    }
    false
}

/// Scaffold `benches/ods_auto_<bench_name>.rs` + ensure `criterion` is a
/// dev-dep + register the bench in `Cargo.toml`. Idempotent: re-running
/// reuses the same filename and returns the existing outcome when the
/// bench already exists.
pub fn scaffold(repo: &Path, target: &TargetSig) -> Result<ScaffoldOutcome> {
    let bench_name = format!(
        "ods_auto_{}",
        target
            .symbol
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    );
    let benches_dir = repo.join("benches");
    std::fs::create_dir_all(&benches_dir).context("create benches/")?;
    let bench_file = benches_dir.join(format!("{bench_name}.rs"));

    let mut created = Vec::new();
    let mut modified = Vec::new();

    if !bench_file.exists() {
        let body = render_bench(target, &bench_name);
        std::fs::write(&bench_file, body).context("write bench file")?;
        created.push(bench_file.clone());
    }

    // Determine the containing crate (for `cargo bench -p <crate>`).
    let (cargo_path, crate_name) = locate_target_crate(repo, target)?;
    let (added_criterion, touched_cargo) = ensure_cargo_registrations(&cargo_path, &bench_name)?;
    if touched_cargo {
        modified.push(cargo_path.clone());
    }

    tracing::info!(
        target: "ods::bench",
        bench = %bench_name,
        file = %bench_file.display(),
        crate_name = %crate_name,
        "scaffolded synthetic bench harness"
    );

    Ok(ScaffoldOutcome {
        bench_file,
        bench_name,
        created_files: created,
        modified_files: modified,
        added_criterion_dep: added_criterion,
    })
}

fn locate_target_crate(repo: &Path, target: &TargetSig) -> Result<(PathBuf, String)> {
    // Preferred: a member crate whose package name matches the target's
    // top-level module (e.g. `ods_recipes` -> `ods-recipes`).
    let first_mod = target
        .module
        .split("::")
        .next()
        .unwrap_or("")
        .replace('_', "-");
    if !first_mod.is_empty() {
        for candidate in [
            repo.join("crates").join(&first_mod).join("Cargo.toml"),
            repo.join(&first_mod).join("Cargo.toml"),
        ] {
            if candidate.exists() {
                return Ok((candidate, first_mod));
            }
        }
    }
    // Fallback to the workspace root manifest.
    Ok((repo.join("Cargo.toml"), String::new()))
}

/// Make sure `criterion` is in `[dev-dependencies]` and a `[[bench]]`
/// block registers our file. Returns `(added_criterion_dep, touched)`.
fn ensure_cargo_registrations(cargo_path: &Path, bench_name: &str) -> Result<(bool, bool)> {
    let original = std::fs::read_to_string(cargo_path)
        .with_context(|| format!("read {}", cargo_path.display()))?;
    let mut updated = original.clone();
    let mut added_dep = false;

    if !original.contains("criterion") {
        // Append a dev-dependencies block if absent, or inject one line.
        if let Some(idx) = updated.find("[dev-dependencies]") {
            // insert after the section header
            let after_header = idx + "[dev-dependencies]".len();
            updated.insert_str(
                after_header,
                "\ncriterion = { version = \"0.5\", default-features = false }",
            );
        } else {
            updated.push_str(
                "\n\n[dev-dependencies]\ncriterion = { version = \"0.5\", default-features = false }\n",
            );
        }
        added_dep = true;
    }

    if !updated.contains(&format!("name = \"{bench_name}\"")) {
        updated.push_str(&format!(
            "\n[[bench]]\nname = \"{bench_name}\"\nharness = false\n"
        ));
    }

    let touched = updated != original;
    if touched {
        std::fs::write(cargo_path, updated)
            .with_context(|| format!("write {}", cargo_path.display()))?;
    }
    Ok((added_dep, touched))
}

fn render_bench(target: &TargetSig, bench_name: &str) -> String {
    let fq = format!("{}::{}", target.module, target.symbol);
    // The scaffolded body is intentionally a `black_box(())` no-op. Specialists
    // that want a measurable speedup MUST rewrite the `b.iter(...)` block to
    // actually exercise the target. The agent prompt (race.rs) reinforces this.
    format!(
        r#"// Auto-generated by ods (optimization-discovery-system).
//
// We scaffolded this bench because the project did not ship one for
// `{fq}`. The body is a placeholder no-op; the specialist agent MUST
// rewrite `b.iter(...)` below to call the real target with realistic
// inputs before claiming any measured speedup. A no-op bench body
// returns noise, not signal.
//
// Concrete template the specialist should produce:
//
//     let fixture = /* load or construct an input that matches the
//                     production call shape; e.g. the crate's own
//                     source bytes, a realistic JSON payload, etc. */;
//     c.bench_function("{bench_name}", |b| {{
//         b.iter(|| {{
//             criterion::black_box(
//                 your_crate::{fq}(criterion::black_box(&fixture))
//             );
//         }});
//     }});

use criterion::{{black_box, criterion_group, criterion_main, Criterion}};

fn bench_target(c: &mut Criterion) {{
    c.bench_function("{bench_name}", |b| {{
        b.iter(|| {{
            // TODO(ods-specialist): replace with a real invocation of
            // `{fq}` against a realistic input. The current no-op produces
            // zero signal; pre/post bench diffs will be pure noise.
            black_box(());
        }});
    }});
}}

criterion_group!(benches, bench_target);
criterion_main!(benches);
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn detects_missing_bench() {
        let d = make_fake_workspace();
        assert!(!has_existing_bench(d.path()));
    }

    #[test]
    fn detects_existing_bench_directory() {
        let d = make_fake_workspace();
        std::fs::create_dir_all(d.path().join("benches")).unwrap();
        std::fs::write(d.path().join("benches/anything.rs"), "").unwrap();
        assert!(has_existing_bench(d.path()));
    }

    #[test]
    fn scaffold_creates_bench_and_registers() {
        let d = make_fake_workspace();
        let target = TargetSig {
            language: "rust".into(),
            module: "x".into(),
            symbol: "foo".into(),
            arity: None,
        };
        let out = scaffold(d.path(), &target).unwrap();
        assert!(out.bench_file.exists());
        let cargo = std::fs::read_to_string(d.path().join("Cargo.toml")).unwrap();
        assert!(cargo.contains("criterion"));
        assert!(cargo.contains("ods_auto_foo"));
    }
}
