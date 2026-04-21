//! Flame-graph SVG capture for the Rust adapter.
//!
//! Strategy (best tool that's already installed wins):
//!   1. `cargo flamegraph --bin <bench>` if `cargo-flamegraph` is on PATH.
//!   2. `perf record` + `stackcollapse-perf` + `flamegraph.pl` if the perf
//!      suite and FlameGraph scripts are available.
//!   3. Give up gracefully (return `None`); the orchestrator keeps going.
//!
//! The resulting SVG path is stored in `ProfileReport.flame_svg_path` so the
//! PR body can embed a collapsed `<details>` block with a link.

use anyhow::Result;
use ods_exec::{run, which, Invocation};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Produce a flame-graph SVG for `bench_filter` run under `cargo bench`.
/// Returns `Ok(None)` when no supported capture tool is available so the
/// orchestrator can continue without a flame graph.
pub async fn capture(
    workdir: &Path,
    bench_filter: &str,
    out_dir: &Path,
) -> Result<Option<PathBuf>> {
    std::fs::create_dir_all(out_dir)?;
    let svg_path = out_dir.join("flame.svg");

    if which("cargo-flamegraph").is_some() {
        let out = run(&Invocation::new("cargo")
            .args([
                "flamegraph".to_string(),
                "--output".to_string(),
                svg_path.display().to_string(),
                "--bench".to_string(),
                bench_filter.to_string(),
            ])
            .cwd(workdir)
            .timeout(Duration::from_secs(600))
            .allow_nonzero())
        .await?;
        if out.success() && svg_path.exists() {
            return Ok(Some(svg_path));
        }
    }

    if which("perf").is_some() {
        // perf record + fold. Requires `stackcollapse-perf.pl` +
        // `flamegraph.pl` from the FlameGraph repo; fall through if missing.
        let Some(stackcollapse) =
            which("stackcollapse-perf.pl").or_else(|| which("stackcollapse-perf"))
        else {
            return Ok(None);
        };
        let Some(fg) = which("flamegraph.pl").or_else(|| which("flamegraph")) else {
            return Ok(None);
        };

        let data = out_dir.join("perf.data");
        let folded = out_dir.join("perf.folded");
        let _ = run(&Invocation::new("perf")
            .args([
                "record".to_string(),
                "-F".to_string(),
                "997".to_string(),
                "-g".to_string(),
                "-o".to_string(),
                data.display().to_string(),
                "--".to_string(),
                "cargo".to_string(),
                "bench".to_string(),
                "--".to_string(),
                bench_filter.to_string(),
            ])
            .cwd(workdir)
            .timeout(Duration::from_secs(600))
            .allow_nonzero())
        .await?;
        let script = run(&Invocation::new("perf")
            .args(["script", "-i"].map(String::from))
            .arg(data.display().to_string())
            .cwd(workdir)
            .timeout(Duration::from_secs(600))
            .allow_nonzero())
        .await?;
        tokio::fs::write(&folded, script.stdout.as_bytes()).await?;
        let collapsed = run(&Invocation::new(stackcollapse.display().to_string())
            .arg(folded.display().to_string())
            .cwd(workdir)
            .timeout(Duration::from_secs(120))
            .allow_nonzero())
        .await?;
        let folded_collapsed = out_dir.join("collapsed.txt");
        tokio::fs::write(&folded_collapsed, collapsed.stdout.as_bytes()).await?;
        let svg = run(&Invocation::new(fg.display().to_string())
            .arg(folded_collapsed.display().to_string())
            .cwd(workdir)
            .timeout(Duration::from_secs(120))
            .allow_nonzero())
        .await?;
        tokio::fs::write(&svg_path, svg.stdout.as_bytes()).await?;
        if svg_path.exists() && svg.success() {
            return Ok(Some(svg_path));
        }
    }

    Ok(None)
}
