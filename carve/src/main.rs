//! `carve` — supply-chain attack-surface reduction.
//!
//! Pipeline: `analyze` (build the Dependency Functional Usage Graph) ->
//! `plan` (agent decides what to keep) -> `vendor` (transcribe verbatim with
//! provenance) <-> `restore` (reverse), with `status`/`verify` for auditing.

mod agent;
mod analyze;
mod model;
mod obs;
mod vendor;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use model::Confidence;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "carve",
    version,
    about = "Carve out only the dependency code you actually use — verbatim, provenance-tracked, reversible."
)]
struct Cli {
    /// Verbose (debug-level) logging.
    #[arg(long, global = true)]
    verbose: bool,
    /// Emit structured NDJSON logs instead of human-readable text.
    #[arg(long, global = true)]
    log_json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build the Dependency Functional Usage Graph (what dep code we touch).
    Analyze {
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        /// Write the full graph as JSON to this file.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Have the agent propose a minimization plan from the usage graph.
    Plan {
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Transcribe a dependency verbatim into vendor/ with provenance.
    Vendor {
        /// Package name as in Cargo.toml.
        crate_name: String,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        /// Also add the reversible `[patch.crates-io]` entry to Cargo.toml.
        #[arg(long)]
        apply: bool,
        /// Proof-read note to record in the provenance ledger.
        #[arg(long)]
        note: Option<String>,
    },
    /// Reverse a vendored crate back to the upstream dependency.
    Restore {
        crate_name: String,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
    },
    /// Show the provenance ledger (carve.lock).
    Status {
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
    },
    /// Re-hash vendored files and confirm they match the ledger.
    Verify {
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
    },
    /// List the tools available to the autonomous agent.
    Tools,
    /// Agent: locate the upstream definition site of a used item (tool-driven).
    Locate {
        /// Package name as in Cargo.toml.
        crate_name: String,
        /// Item path or bare name to locate, e.g. `serde_json::to_string`.
        item: String,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    obs::init(cli.verbose, cli.log_json);

    match cli.command {
        Command::Analyze { manifest_path, out } => cmd_analyze(&manifest_path, out.as_deref()),
        Command::Plan { manifest_path, out } => cmd_plan(&manifest_path, out.as_deref()),
        Command::Vendor {
            crate_name,
            manifest_path,
            apply,
            note,
        } => cmd_vendor(&crate_name, &manifest_path, apply, note),
        Command::Restore {
            crate_name,
            manifest_path,
        } => cmd_restore(&crate_name, &manifest_path),
        Command::Status { manifest_path } => cmd_status(&manifest_path),
        Command::Verify { manifest_path } => cmd_verify(&manifest_path),
        Command::Tools => cmd_tools(),
        Command::Locate {
            crate_name,
            item,
            manifest_path,
        } => cmd_locate(&crate_name, &item, &manifest_path),
    }
}

fn root_of(manifest_path: &Path) -> PathBuf {
    manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn cmd_analyze(manifest_path: &Path, out: Option<&Path>) -> Result<()> {
    let graph = analyze::build_usage_graph(manifest_path)?;

    println!("\nDependency Functional Usage Graph — {}", graph.package);
    println!("  dependencies referenced: {}", graph.crates.len());
    println!();
    for c in &graph.crates {
        let v = c.version.as_deref().unwrap_or("?");
        let tag = if c.is_normal { "" } else { " [dev/build]" };
        println!(
            "  {} v{}{}  —  {} item(s), {} ref(s)",
            c.name,
            v,
            tag,
            c.items.len(),
            c.total_refs()
        );
        for item in c.items.iter().take(8) {
            println!("      {:>3}×  {}", item.ref_count(), item.path);
        }
        if c.items.len() > 8 {
            println!("      … {} more", c.items.len() - 8);
        }
    }

    if !graph.unused_declared.is_empty() {
        println!("\n  Declared but unreferenced (drop candidates):");
        for d in &graph.unused_declared {
            println!("      - {d}");
        }
    }

    if let Some(path) = out {
        std::fs::write(path, serde_json::to_string_pretty(&graph)?)?;
        println!("\n  graph written to {}", path.display());
    }
    Ok(())
}

fn cmd_plan(manifest_path: &Path, out: Option<&Path>) -> Result<()> {
    let graph = analyze::build_usage_graph(manifest_path)?;
    let agent = agent::RuleBasedAgent::new();
    let plan = agent.plan(&graph);

    println!("\nMinimization plan — {}", plan.package);
    for c in &plan.crates {
        let badge = match c.confidence {
            Confidence::High => "HIGH  (slice)",
            Confidence::Medium => "MED   (slice+verify)",
            Confidence::Low => "LOW   (vendor whole)",
        };
        println!(
            "\n  {} [{}]  {} entrypoint(s), ~{} transitive",
            c.crate_name,
            badge,
            c.entrypoints.len(),
            c.transitive_estimate
        );
        println!("      {}", c.rationale);
    }

    if let Some(path) = out {
        std::fs::write(path, serde_json::to_string_pretty(&plan)?)?;
        println!("\n  plan written to {}", path.display());
    }
    Ok(())
}

fn cmd_vendor(
    crate_name: &str,
    manifest_path: &Path,
    apply: bool,
    note: Option<String>,
) -> Result<()> {
    let root = root_of(manifest_path);

    // Resolve version + the items that justify keeping this crate.
    let graph = analyze::build_usage_graph(manifest_path)?;
    let usage = graph.used_crate(crate_name);
    let version = usage
        .and_then(|c| c.version.clone())
        .or_else(|| {
            // Fall back to metadata even if unreferenced.
            analyze::metadata::load(manifest_path)
                .ok()
                .and_then(|m| {
                    m.deps
                        .values()
                        .find(|d| d.package == crate_name)
                        .and_then(|d| d.version.clone())
                })
        })
        .context("could not resolve a version for that crate from cargo metadata")?;
    let kept_items: Vec<String> = usage
        .map(|c| c.items.iter().map(|i| i.path.clone()).collect())
        .unwrap_or_default();

    println!("Vendoring {crate_name} v{version} (verbatim) …");
    let entry = vendor::vendor_crate(&root, crate_name, &version, kept_items, note)?;

    let mut lock = vendor::load_lock(&root)?;
    let file_count = entry.files.len();
    lock.upsert(entry);
    vendor::save_lock(&root, &lock)?;
    println!("  transcribed {file_count} file(s) -> {}", vendor::vendor_rel_path(crate_name, &version));
    println!("  provenance recorded in carve.lock");

    if apply {
        let rel = vendor::vendor_rel_path(crate_name, &version);
        vendor::apply_patch(&root, crate_name, &rel)?;
        println!("  added [patch.crates-io] {crate_name} -> {rel}");
        println!("  run `cargo build` to compile against the vendored copy");
    } else {
        let rel = vendor::vendor_rel_path(crate_name, &version);
        println!("\n  To activate, add to Cargo.toml (or re-run with --apply):");
        println!("      [patch.crates-io]");
        println!("      {crate_name} = {{ path = \"{rel}\" }}");
    }
    Ok(())
}

fn cmd_restore(crate_name: &str, manifest_path: &Path) -> Result<()> {
    let root = root_of(manifest_path);
    vendor::restore_crate(&root, crate_name)?;
    println!("Restored {crate_name} to its upstream dependency (patch + vendor dir removed).");
    Ok(())
}

fn cmd_status(manifest_path: &Path) -> Result<()> {
    let root = root_of(manifest_path);
    let lock = vendor::load_lock(&root)?;
    if lock.entries.is_empty() {
        println!("No vendored dependencies (carve.lock empty or absent).");
        return Ok(());
    }
    println!("Vendored dependencies ({}):", lock.entries.len());
    for e in &lock.entries {
        println!(
            "\n  {} v{}  —  {} file(s), {} kept item(s)",
            e.crate_name,
            e.version,
            e.files.len(),
            e.kept_items.len()
        );
        println!("      from: {}", e.upstream_src);
        println!("      at:   {}", e.vendored_at.to_rfc3339());
        if let Some(note) = &e.note {
            println!("      note: {note}");
        }
    }
    Ok(())
}

fn cmd_verify(manifest_path: &Path) -> Result<()> {
    let root = root_of(manifest_path);
    let lock = vendor::load_lock(&root)?;
    if lock.entries.is_empty() {
        println!("Nothing to verify.");
        return Ok(());
    }
    let mut all_ok = true;
    for e in &lock.entries {
        let problems = vendor::verify_entry(&root, e);
        if problems.is_empty() {
            println!("  OK   {} v{} ({} files match ledger)", e.crate_name, e.version, e.files.len());
        } else {
            all_ok = false;
            println!("  FAIL {} v{}:", e.crate_name, e.version);
            for p in problems {
                println!("        {p}");
            }
        }
    }
    if !all_ok {
        anyhow::bail!("verification failed: vendored bytes diverge from the provenance ledger");
    }
    println!("\nAll vendored bytes match their upstream provenance.");
    Ok(())
}

fn cmd_tools() -> Result<()> {
    let registry = agent::ToolRegistry::with_defaults();
    println!("Agent tool surface:");
    for (name, desc) in registry.describe() {
        println!("  - {name}: {desc}");
    }
    Ok(())
}

fn cmd_locate(crate_name: &str, item: &str, manifest_path: &Path) -> Result<()> {
    let root = root_of(manifest_path);

    // Prefer an already-vendored copy; otherwise fall back to the registry cache.
    let lock = vendor::load_lock(&root)?;
    let upstream = if let Some(entry) = lock.entry(crate_name) {
        PathBuf::from(&entry.upstream_src)
    } else {
        let meta = analyze::metadata::load(manifest_path)?;
        let version = meta
            .deps
            .values()
            .find(|d| d.package == crate_name)
            .and_then(|d| d.version.clone())
            .context("could not resolve a version for that crate")?;
        vendor::find_registry_src(crate_name, &version)?
    };

    println!("Agent locating `{item}` in {} …", upstream.display());
    let agent = agent::RuleBasedAgent::new();
    match agent.locate_definition(&upstream, item)? {
        Some(found) => {
            println!("  found {} `{}`", found["kind"], found["name"]);
            println!("  defined in: {}", found["file"].as_str().unwrap_or("?"));
            println!("\n  This is the slice the agent would transcribe verbatim.");
        }
        None => println!("  not found as a top-level item (may be a method, macro-generated, or re-export)"),
    }
    Ok(())
}
