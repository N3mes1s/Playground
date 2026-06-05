//! `carve` — supply-chain attack-surface reduction.
//!
//! Pipeline: `analyze` (build the Dependency Functional Usage Graph) ->
//! `plan` (agent decides what to keep) -> `vendor` (transcribe verbatim with
//! provenance) <-> `restore` (reverse), with `status`/`verify` for auditing.

mod agent;
mod analyze;
mod config;
mod impact;
mod model;
mod obs;
mod slice;
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
        /// Go deep: build the usage graph across the WHOLE transitive closure
        /// (dependencies of dependencies), not just direct deps.
        #[arg(long)]
        transitive: bool,
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
    /// Vendor every normal direct dependency verbatim in one shot.
    VendorAll {
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        /// Also add the reversible `[patch.crates-io]` entries to Cargo.toml.
        #[arg(long)]
        apply: bool,
        /// Go deep: vendor the ENTIRE transitive closure (dependencies of
        /// dependencies), for full supply-chain isolation.
        #[arg(long)]
        transitive: bool,
        /// Crate(s) to leave on the upstream registry (repeatable). Merged with
        /// `exclude` in carve.toml.
        #[arg(long)]
        exclude: Vec<String>,
    },
    /// Agent: carve a vendored crate down to only the modules the product needs,
    /// verifying every cut by compiling the real consumer.
    Slice {
        /// Package name as in Cargo.toml (must already be vendored + patched).
        crate_name: String,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Use the LLM agent to plan which modules to drop (needs ANTHROPIC_API_KEY).
        #[arg(long)]
        llm: bool,
        /// After module slicing, also slice at the item level (fn/struct/impl…),
        /// verifying each removal against the consumer build.
        #[arg(long)]
        items: bool,
        /// Extra per-item refinement checks after the cheap compiler-guided
        /// convergence (which always runs, ~O(reference-depth) checks). 0 =
        /// convergence only (cheapest). Raise to squeeze the `impl`/duplicate
        /// tail, at one `cargo check` per candidate.
        #[arg(long, default_value_t = 0)]
        budget: usize,
        /// Behavioral gate: after slicing, run the consumer's own test suite
        /// (`cargo test`), not just compile it — catches removals that compile
        /// but change behavior. As good as the product's test coverage.
        #[arg(long)]
        test: bool,
    },
    /// Autonomously harden the whole supply chain: vendor the closure, then have
    /// the agent slice EVERY compiled vendored crate, and report the aggregate
    /// attack-surface reduction. One command, end to end.
    Harden {
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        /// Vendor + slice the full transitive closure (deps of deps).
        #[arg(long)]
        transitive: bool,
        /// Per-crate item-slicing refinement budget (0 = cheap convergence only).
        #[arg(long, default_value_t = 0)]
        budget: usize,
        /// Minimum LOC reduction (%) for a slice to be "worth owning". Crates
        /// that shed less are reverted to the upstream dependency — not worth the
        /// maintenance of a vendored copy. 0 keeps every slice.
        #[arg(long, default_value_t = 0.0)]
        min_reduction: f64,
        /// Crate(s) to leave on the upstream registry (repeatable). Merged with
        /// `exclude` in carve.toml.
        #[arg(long)]
        exclude: Vec<String>,
        /// Behavioral gate: after hardening, run the consumer's own test suite
        /// (`cargo test`), not just compile it.
        #[arg(long)]
        test: bool,
    },
    /// Check LLM agent connectivity (needs ANTHROPIC_API_KEY).
    LlmCheck,
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
    /// Behavioral equivalence: run the vendored crate's OWN test suite. On a
    /// verbatim copy this proves faithful transcription; on a test-preserving
    /// slice it proves the slice still behaves like upstream.
    VerifyTests {
        /// Package name as in Cargo.toml (must be vendored).
        crate_name: String,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
    },
    /// Record intentional local edits to a vendored crate as tracked patches
    /// (e.g. an emergency CVE fix) so they're deliberate deltas, not drift.
    Patch {
        /// Package name as in Cargo.toml.
        crate_name: String,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        /// Why this patch exists (recorded in the provenance ledger).
        #[arg(long)]
        note: Option<String>,
    },
    /// Assess whether a dependency update touches the code we actually vendored.
    Impact {
        /// Package name as in Cargo.toml (must already be vendored).
        crate_name: String,
        /// Target upstream version to evaluate, e.g. 2.7.5.
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Print the unified diff of the in-slice code the update changes — the
        /// exact, bounded surface to proof-read before bumping.
        #[arg(long)]
        diff: bool,
        /// Security-scan the in-slice update diff with the LLM agent (backdoor /
        /// exfiltration / obfuscation review). Needs ANTHROPIC_API_KEY.
        #[arg(long)]
        scan: bool,
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
        Command::Analyze {
            manifest_path,
            out,
            transitive,
        } => {
            if transitive {
                cmd_analyze_transitive(&manifest_path, out.as_deref())
            } else {
                cmd_analyze(&manifest_path, out.as_deref())
            }
        }
        Command::Plan { manifest_path, out } => cmd_plan(&manifest_path, out.as_deref()),
        Command::Vendor {
            crate_name,
            manifest_path,
            apply,
            note,
        } => cmd_vendor(&crate_name, &manifest_path, apply, note),
        Command::VendorAll {
            manifest_path,
            apply,
            transitive,
            exclude,
        } => cmd_vendor_all(&manifest_path, apply, transitive, &exclude),
        Command::Slice {
            crate_name,
            manifest_path,
            out,
            llm,
            items,
            budget,
            test,
        } => cmd_slice(
            &crate_name,
            &manifest_path,
            out.as_deref(),
            llm,
            items,
            budget,
            test,
        ),
        Command::Harden {
            manifest_path,
            transitive,
            budget,
            min_reduction,
            exclude,
            test,
        } => cmd_harden(
            &manifest_path,
            transitive,
            budget,
            min_reduction,
            &exclude,
            test,
        ),
        Command::LlmCheck => cmd_llm_check(),
        Command::Restore {
            crate_name,
            manifest_path,
        } => cmd_restore(&crate_name, &manifest_path),
        Command::Status { manifest_path } => cmd_status(&manifest_path),
        Command::Verify { manifest_path } => cmd_verify(&manifest_path),
        Command::VerifyTests {
            crate_name,
            manifest_path,
        } => cmd_verify_tests(&crate_name, &manifest_path),
        Command::Patch {
            crate_name,
            manifest_path,
            note,
        } => cmd_patch(&crate_name, &manifest_path, note),
        Command::Impact {
            crate_name,
            to,
            manifest_path,
            out,
            diff,
            scan,
        } => cmd_impact(&crate_name, &to, &manifest_path, out.as_deref(), diff, scan),
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

fn cmd_analyze_transitive(manifest_path: &Path, out: Option<&Path>) -> Result<()> {
    println!("Building the DEEP usage graph (dependencies of dependencies)…");
    let graph = analyze::build_transitive_usage(manifest_path)?;

    // Depth histogram.
    let mut by_depth: std::collections::BTreeMap<usize, usize> = Default::default();
    for n in &graph.nodes {
        *by_depth.entry(n.depth).or_default() += 1;
    }

    println!(
        "\nTransitive Dependency Functional Usage Graph — {}",
        graph.package
    );
    println!(
        "  crates in closure: {}  (max depth {})",
        graph.nodes.len(),
        graph.max_depth
    );
    println!("  functional edges:  {}", graph.edges.len());
    println!("  scanned for usage: {} crates\n", graph.scanned_crates);
    println!("  crates by depth (0 = the product, 1 = direct, 2+ = deps of deps):");
    for (d, n) in &by_depth {
        println!("      depth {d}: {n} crate(s)");
    }

    // Show the heaviest functional edges across the whole tree.
    let mut edges = graph.edges.clone();
    edges.sort_by(|a, b| b.refs.cmp(&a.refs));
    println!("\n  Top functional edges (who leans hardest on whom):");
    for e in edges.iter().take(15) {
        println!(
            "      {} → {}   {} item(s), {} ref(s)",
            e.from, e.to, e.items, e.refs
        );
    }

    // Illustrate a deep chain: product → direct → its dep → …
    if let Some(chain) = deepest_chain(&graph) {
        println!("\n  Example dependency-of-dependency chain:");
        println!("      {}", chain.join("  →  "));
    }

    if let Some(path) = out {
        std::fs::write(path, serde_json::to_string_pretty(&graph)?)?;
        println!("\n  full graph written to {}", path.display());
    }
    Ok(())
}

/// Greedily walk functional edges from the product to the deepest reachable crate.
fn deepest_chain(graph: &model::TransitiveGraph) -> Option<Vec<String>> {
    use std::collections::BTreeMap;
    let depth: BTreeMap<&str, usize> = graph
        .nodes
        .iter()
        .map(|n| (n.name.as_str(), n.depth))
        .collect();
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in &graph.edges {
        adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
    }
    let start = graph.nodes.iter().find(|n| n.depth == 0)?;
    let mut chain = vec![start.name.clone()];
    let mut current = start.name.clone();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        seen.insert(current.clone());
        let next = adj
            .get(current.as_str())
            .into_iter()
            .flatten()
            .filter(|n| !seen.contains(**n))
            .max_by_key(|n| depth.get(**n).copied().unwrap_or(0))
            .map(|s| s.to_string());
        match next {
            Some(n)
                if depth.get(n.as_str()).copied().unwrap_or(0)
                    > depth.get(current.as_str()).copied().unwrap_or(0) =>
            {
                chain.push(n.clone());
                current = n;
            }
            _ => break,
        }
    }
    if chain.len() >= 3 {
        Some(chain)
    } else {
        None
    }
}

/// Crate names cargo actually compiles for this target (from build artifacts).
/// We only slice these — gutting a cfg'd-out crate (e.g. `windows-sys` on Linux)
/// would "verify" because it is never built, which would be unsafe.
fn compiled_crates(manifest_path: &Path) -> Result<std::collections::HashSet<String>> {
    let out = std::process::Command::new("cargo")
        .current_dir(root_of(manifest_path))
        .args(["build", "--message-format=json", "--manifest-path"])
        .arg(manifest_path)
        .output()
        .context("cargo build --message-format=json")?;
    let mut set = std::collections::HashSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact") {
            if let Some(pid) = v.get("package_id").and_then(|p| p.as_str()) {
                set.insert(parse_pkg_name(pid));
            }
        }
    }
    Ok(set)
}

fn parse_pkg_name(pid: &str) -> String {
    // "registry+https://…#aho-corasick@1.1.3", "path+file://…#ripgrep@15.1.0",
    // or older "aho-corasick 1.1.3 (registry+…)".
    let tail = pid.rsplit('#').next().unwrap_or(pid);
    let name = tail.split('@').next().unwrap_or(tail);
    name.split_whitespace().next().unwrap_or(name).to_string()
}

/// Time a clean optimized (`--release`) build, in seconds.
fn release_build_time(manifest_path: &Path) -> Result<f64> {
    let workdir = root_of(manifest_path);
    std::process::Command::new("cargo")
        .current_dir(&workdir)
        .args(["clean", "--release", "--manifest-path"])
        .arg(manifest_path)
        .output()
        .context("cargo clean --release")?;
    let t0 = std::time::Instant::now();
    let out = std::process::Command::new("cargo")
        .current_dir(&workdir)
        .args(["build", "--release", "--manifest-path"])
        .arg(manifest_path)
        .output()
        .context("cargo build --release")?;
    if !out.status.success() {
        anyhow::bail!(
            "release build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(t0.elapsed().as_secs_f64())
}

fn cmd_harden(
    manifest_path: &Path,
    transitive: bool,
    budget: usize,
    min_reduction: f64,
    cli_exclude: &[String],
    test: bool,
) -> Result<()> {
    let root = root_of(manifest_path);
    // CLI overrides carve.toml overrides built-in defaults.
    let cfg = config::Config::load(&root);
    let transitive = transitive || cfg.transitive.unwrap_or(false);
    let budget = if budget != 0 {
        budget
    } else {
        cfg.budget.unwrap_or(0)
    };
    let min_reduction = if min_reduction != 0.0 {
        min_reduction
    } else {
        cfg.min_reduction.unwrap_or(0.0)
    };
    println!("=== Autonomous supply-chain hardening ===");
    println!("  policy: transitive={transitive}  min_reduction={min_reduction:.0}%  budget={budget}  excluded={}\n",
        cfg.exclude.len() + cli_exclude.len());

    println!(
        "[1/5] Vendoring the {} closure…",
        if transitive { "transitive" } else { "direct" }
    );
    cmd_vendor_all(manifest_path, true, transitive, cli_exclude)?;

    println!("\n[2/5] Detecting crates actually compiled for this target…");
    let compiled = compiled_crates(manifest_path)?;
    println!("  {} crate(s) compiled", compiled.len());

    println!("\n[3/5] Timing a clean --release build BEFORE slicing…");
    let before_time = release_build_time(manifest_path)?;
    println!("  {before_time:.1}s");

    println!(
        "\n[4/5] Agent slicing every compiled vendored crate (autonomous loop; keep-if ≥ {min_reduction:.0}% LOC)…"
    );
    // Incremental: a crate already hardened (note set) and still intact is
    // skipped so re-runs don't re-slice everything.
    let targets: Vec<(String, String, bool)> = vendor::load_lock(&root)?
        .entries
        .iter()
        .filter(|e| compiled.contains(&e.crate_name))
        .map(|e| {
            let done = e.note.as_deref().is_some_and(|n| n.starts_with("hardened"))
                && vendor::verify_entry(&root, e).is_empty();
            (e.crate_name.clone(), e.version.clone(), done)
        })
        .collect();

    let agent = agent::RuleBasedAgent::new();
    let mut already = 0usize;
    let mut bt = model::AttackSurface {
        files: 0,
        loc: 0,
        bytes: 0,
        items: 0,
        unsafe_blocks: 0,
    };
    let mut at = bt;
    let mut sliced = 0usize;
    let mut skipped = 0usize;
    let mut reverted = 0usize;

    for (name, version, done) in &targets {
        if *done {
            already += 1;
            continue;
        }
        let vendor_dir = root.join(vendor::vendor_rel_path(name, version));
        let before = slice::measure_surface(&vendor_dir);
        let res = agent
            .slice_crate(name, manifest_path, &vendor_dir, &[])
            .and_then(|_| agent.slice_items(name, manifest_path, &vendor_dir, budget));
        if let Err(e) = res {
            tracing::warn!(crate_name = %name, error = %e, "skipped (slice failed)");
            skipped += 1;
            continue;
        }
        let after = slice::measure_surface(&vendor_dir);
        let pct = bt_pct(before.loc, after.loc);

        // Economic gate: only keep (own) a vendored slice that sheds enough.
        if pct < min_reduction {
            vendor::restore_crate(&root, name)?; // back to upstream dependency
            println!(
                "  {:<24} LOC -{:.0}%  → reverted to upstream (below {:.0}% bar)",
                name, pct, min_reduction
            );
            reverted += 1;
            continue;
        }

        if let Ok(files) = vendor::reindex_files(&root, name, version) {
            let mut l = vendor::load_lock(&root)?;
            if let Some(entry) = l.entry(name).cloned() {
                let mut e2 = entry;
                e2.files = files;
                e2.removed_modules = vec![];
                e2.note = Some(format!(
                    "hardened: LOC {} -> {} (-{:.0}%)",
                    before.loc, after.loc, pct
                ));
                l.upsert(e2);
                vendor::save_lock(&root, &l)?;
            }
        }
        bt.files += before.files;
        bt.loc += before.loc;
        bt.bytes += before.bytes;
        bt.items += before.items;
        bt.unsafe_blocks += before.unsafe_blocks;
        at.files += after.files;
        at.loc += after.loc;
        at.bytes += after.bytes;
        at.items += after.items;
        at.unsafe_blocks += after.unsafe_blocks;
        println!(
            "  {:<24} LOC {:>6} -> {:<6} (-{:.0}%)  ✓ kept",
            name, before.loc, after.loc, pct
        );
        sliced += 1;
    }

    if test {
        println!("\nBehavioral verification — running the consumer's test suite…");
        match run_consumer_tests(manifest_path)? {
            Some(true) => {
                println!("  consumer tests: PASS — hardened tree is behaviorally verified")
            }
            Some(false) => {
                anyhow::bail!(
                    "behavioral verification failed: the hardened tree breaks the consumer's tests"
                )
            }
            None => println!("  consumer has no tests — behavioral gate skipped (compile-only)"),
        }
    }

    println!("\n[5/5] Timing a clean --release build AFTER slicing…");
    let after_time = release_build_time(manifest_path)?;
    println!("  {after_time:.1}s");

    println!("\n══════════ supply-chain hardening summary ══════════");
    println!("  crates owned (sliced & kept): {sliced}    already hardened (reused): {already}");
    println!("  reverted (below {min_reduction:.0}% bar): {reverted}    skipped (unsliceable): {skipped}");
    println!("  across the {sliced} owned crate(s):");
    println!(
        "      files   {:>8} -> {:<8}  -{:.1}%",
        bt.files,
        at.files,
        bt.files_pct(&at)
    );
    println!(
        "      LOC     {:>8} -> {:<8}  -{:.1}%",
        bt.loc,
        at.loc,
        bt.loc_pct(&at)
    );
    println!(
        "      items   {:>8} -> {:<8}  -{:.1}%",
        bt.items,
        at.items,
        bt.items_pct(&at)
    );
    println!(
        "      bytes   {:>8} -> {:<8}  -{:.1}%",
        bt.bytes,
        at.bytes,
        bt.bytes_pct(&at)
    );
    println!(
        "      unsafe  {:>8} -> {:<8}  -{:.1}%",
        bt.unsafe_blocks,
        at.unsafe_blocks,
        bt.unsafe_pct(&at)
    );
    let tpct = if before_time > 0.0 {
        100.0 * (before_time - after_time) / before_time
    } else {
        0.0
    };
    println!("  clean --release build: {before_time:.1}s -> {after_time:.1}s  ({tpct:+.1}%)");
    println!("════════════════════════════════════════════════════");
    Ok(())
}

fn bt_pct(before: usize, after: usize) -> f64 {
    if before == 0 {
        0.0
    } else {
        100.0 * (before.saturating_sub(after)) as f64 / before as f64
    }
}

fn cmd_llm_check() -> Result<()> {
    let agent = agent::LlmAgent::from_env()?;
    println!("Pinging the LLM agent…");
    let reply = agent.ping()?;
    println!("  model replied: {}", reply.trim());
    println!("  LLM agent is wired and reachable.");
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
            analyze::metadata::load(manifest_path).ok().and_then(|m| {
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
    println!(
        "  transcribed {file_count} file(s) -> {}",
        vendor::vendor_rel_path(crate_name, &version)
    );
    println!("  provenance recorded in carve.lock");

    if apply {
        let rel = vendor::vendor_rel_path(crate_name, &version);
        vendor::apply_patch(&root, crate_name, &rel)?;
        vendor::ensure_cap_lints(&root)?;
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

fn cmd_vendor_all(
    manifest_path: &Path,
    apply: bool,
    transitive: bool,
    cli_exclude: &[String],
) -> Result<()> {
    let root = root_of(manifest_path);

    // Map each used crate to its referenced items, for richer provenance.
    // Optional: a virtual workspace has no single root package to analyze, so we
    // proceed without per-crate item provenance rather than failing.
    let graph = analyze::build_usage_graph(manifest_path).ok();
    let kept_for = |pkg: &str| -> Vec<String> {
        graph
            .as_ref()
            .and_then(|g| g.used_crate(pkg))
            .map(|c| c.items.iter().map(|i| i.path.clone()).collect())
            .unwrap_or_default()
    };

    let mut native_count = 0usize;
    let mut targets: Vec<(String, String)> = if transitive {
        // The ENTIRE transitive closure (deps of deps) — full isolation. Native
        // `*-sys` crates ARE vendored too: carve preserves file modes, so their
        // shipped `configure`/`*.sh` build scripts still run and the native build
        // reproduces faithfully from the vendored source.
        let meta = analyze::metadata::load_metadata(manifest_path)?;
        let mut t = Vec::new();
        for n in analyze::metadata::build_closure(&meta)? {
            if n.native_link {
                native_count += 1;
            }
            t.push((n.name, n.version));
        }
        t
    } else {
        // Just the normal direct deps — what `cargo build` of the product needs.
        let meta = analyze::metadata::load(manifest_path)?;
        meta.deps
            .values()
            .filter(|d| d.is_normal)
            .filter_map(|d| d.version.clone().map(|v| (d.package.clone(), v)))
            .collect()
    };
    targets.sort();
    targets.dedup();

    // Policy: drop crates excluded in carve.toml or via --exclude — they stay as
    // normal upstream dependencies.
    let cfg = config::Config::load(&root);
    let excluded: std::collections::HashSet<&str> = cfg
        .exclude
        .iter()
        .chain(cli_exclude.iter())
        .map(String::as_str)
        .collect();
    let before = targets.len();
    if !excluded.is_empty() {
        targets.retain(|(p, _)| !excluded.contains(p.as_str()));
        let dropped = before - targets.len();
        if dropped > 0 {
            println!(
                "Excluded {dropped} crate(s) by policy (kept upstream): {}",
                excluded.iter().copied().collect::<Vec<_>>().join(", ")
            );
        }
    }

    if targets.is_empty() {
        println!("No resolvable dependencies to vendor.");
        return Ok(());
    }

    // A [patch.crates-io] entry is keyed by crate name, so a crate present at
    // multiple versions in the graph can't be patched unambiguously — vendor it
    // for the record but leave it on the registry to keep the build correct.
    let mut name_counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for (pkg, _) in &targets {
        *name_counts.entry(pkg.as_str()).or_default() += 1;
    }

    let scope = if transitive { "transitive" } else { "direct" };
    println!(
        "Vendoring {} {scope} dependency(ies) verbatim …\n",
        targets.len()
    );
    let mut lock = vendor::load_lock(&root)?;
    let mut ok = 0usize;
    let mut patched = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut skipped_patch: Vec<String> = Vec::new();
    let mut reused = 0usize;
    for (pkg, version) in &targets {
        // Incremental: if this exact version is already vendored and intact,
        // keep it as-is (preserving any prior slice) instead of re-copying.
        let already = lock
            .entry(pkg)
            .filter(|e| &e.version == version && vendor::verify_entry(&root, e).is_empty())
            .is_some();
        if already {
            if apply && name_counts.get(pkg.as_str()).copied().unwrap_or(0) <= 1 {
                vendor::apply_patch(&root, pkg, &vendor::vendor_rel_path(pkg, version))?;
                patched += 1;
            }
            ok += 1;
            reused += 1;
            continue;
        }
        match vendor::vendor_crate(&root, pkg, version, kept_for(pkg), None) {
            Ok(entry) => {
                let files = entry.files.len();
                lock.upsert(entry);
                if apply {
                    if name_counts.get(pkg.as_str()).copied().unwrap_or(0) > 1 {
                        skipped_patch.push(format!("{pkg} (multiple versions)"));
                    } else {
                        let rel = vendor::vendor_rel_path(pkg, version);
                        vendor::apply_patch(&root, pkg, &rel)?;
                        patched += 1;
                    }
                }
                ok += 1;
                if ok.is_multiple_of(20) {
                    println!("  … {ok}/{} vendored", targets.len());
                }
                let _ = files;
            }
            Err(e) => {
                failed.push(format!("{pkg} v{version}: {e}"));
            }
        }
    }
    vendor::save_lock(&root, &lock)?;
    if apply {
        vendor::ensure_cap_lints(&root)?;
    }

    println!(
        "\n  vendored {ok}/{} dependency(ies) ({reused} reused intact); provenance in carve.lock",
        targets.len()
    );
    if apply {
        println!(
            "  wired {patched} [patch.crates-io] entries (+ cap-lints shim) — run `cargo build`"
        );
    } else {
        println!("  re-run with --apply to wire the [patch.crates-io] entries");
    }
    if !skipped_patch.is_empty() {
        println!(
            "  left on registry (can't patch a duplicated name): {}",
            skipped_patch.join(", ")
        );
    }
    if native_count > 0 {
        println!(
            "  ({native_count} native-linked sys crate(s) vendored with file modes preserved)"
        );
    }
    if !failed.is_empty() {
        println!(
            "  {} not vendored (source not cached — run `cargo fetch`)",
            failed.len()
        );
        for f in failed.iter().take(8) {
            println!("      {f}");
        }
    }
    Ok(())
}

fn cmd_slice(
    crate_name: &str,
    manifest_path: &Path,
    out: Option<&Path>,
    llm: bool,
    items: bool,
    budget: usize,
    test: bool,
) -> Result<()> {
    let root = root_of(manifest_path);
    let mut lock = vendor::load_lock(&root)?;
    let entry = lock
        .entry(crate_name)
        .cloned()
        .context("crate is not vendored — run `carve vendor` (with --apply) first")?;
    let vendor_dir = root.join(vendor::vendor_rel_path(&entry.crate_name, &entry.version));

    // Measure the attack surface before any carving so we can report the delta.
    let surface_before = slice::measure_surface(&vendor_dir);

    let agent = agent::RuleBasedAgent::new();

    // Optional LLM planner: propose a prioritized removal order. The cargo_check
    // gate inside slice_crate still verifies every cut, so the LLM can never break
    // or invent code — it only steers which modules we try first.
    let prioritized: Vec<String> = if llm {
        let candidates = slice::discover(&vendor_dir)?;
        let modules: Vec<String> = candidates.iter().map(|c| c.rel_name.clone()).collect();
        println!("Consulting LLM agent to plan the slice…");
        let llm_agent = agent::LlmAgent::from_env()?;
        let proposal = llm_agent.propose_removals(
            crate_name,
            &entry.kept_items,
            &modules,
            &vendor_dir.to_string_lossy(),
        )?;
        println!(
            "  LLM proposed removing {} module(s): {}\n",
            proposal.len(),
            proposal.join(", ")
        );
        proposal
    } else {
        Vec::new()
    };

    println!(
        "Agent slicing {} v{} (verifying every cut against the consumer build)…\n",
        entry.crate_name, entry.version
    );
    let report = agent.slice_crate(crate_name, manifest_path, &vendor_dir, &prioritized)?;

    // Re-index provenance so `carve verify` still matches the carved tree.
    let files = vendor::reindex_files(&root, &entry.crate_name, &entry.version)?;
    let mut updated = entry.clone();
    updated.files = files;
    updated.removed_modules = report.removed.clone();
    updated.note = Some(format!(
        "sliced: removed {} module(s), {:.1}% LOC reduction, consumer verified={}",
        report.removed.len(),
        report.loc_reduction_pct(),
        report.verified
    ));
    lock.upsert(updated);
    vendor::save_lock(&root, &lock)?;

    println!("  carved away {} module(s):", report.removed.len());
    for m in &report.removed {
        println!("      - {m}");
    }
    println!(
        "\n  files: {} -> {}   LOC: {} -> {}  ({:.1}% reduction)",
        report.files_before,
        report.files_after,
        report.loc_before,
        report.loc_after,
        report.loc_reduction_pct()
    );
    println!(
        "  kept (needed to compile): {} module(s)",
        report.kept_needed.len()
    );
    println!(
        "  consumer build verified after slicing: {}",
        if report.verified { "YES" } else { "NO" }
    );

    // Optional finer pass: item-level slicing on top of the module-level result.
    if items {
        println!("\nItem-level slicing (budget {budget} verifications)…");
        let item_report = agent.slice_items(crate_name, manifest_path, &vendor_dir, budget)?;
        // Re-index again so provenance matches the item-carved tree.
        let files = vendor::reindex_files(&root, &entry.crate_name, &entry.version)?;
        if let Some(e) = lock.entry(crate_name).cloned() {
            let mut e2 = e;
            e2.files = files;
            e2.note = Some(format!(
                "sliced modules + items: removed {} item(s), {:.1}% LOC reduction overall, verified={}",
                item_report.items_removed,
                item_report.loc_reduction_pct(),
                item_report.verified
            ));
            lock.upsert(e2);
            vendor::save_lock(&root, &lock)?;
        }
        println!(
            "  fast pass: removed {} item(s) in just {} check(s) (compiler-guided convergence)",
            item_report.fast_removed, item_report.fast_checks
        );
        println!(
            "  total: removed {}/{} top-level item(s) via {} verification(s){}",
            item_report.items_removed,
            item_report.items_before,
            item_report.checks_used,
            if budget > 0 && item_report.budget_exhausted {
                " (refinement budget reached)"
            } else {
                ""
            }
        );
        if budget == 0 && item_report.items_removed < item_report.items_before {
            println!("  (convergence-only; pass --budget N to squeeze the impl/duplicate tail)");
        }
        println!(
            "  LOC after items: {} -> {}  ({:.1}% reduction)",
            item_report.loc_before,
            item_report.loc_after,
            item_report.loc_reduction_pct()
        );
        println!(
            "  consumer build verified after item-slicing: {}",
            if item_report.verified { "YES" } else { "NO" }
        );
    }

    // Behavioral gate: compiling proves the slice type-checks; running the
    // consumer's tests proves it still *behaves*. This catches removals that
    // compile but change runtime behavior (Drop, ctor registration, cfg paths),
    // bounded by the product's own test coverage.
    if test {
        println!("\nBehavioral verification — running the consumer's test suite…");
        match run_consumer_tests(manifest_path)? {
            Some(true) => println!("  consumer tests: PASS — slice is behaviorally verified"),
            Some(false) => {
                println!("  consumer tests: FAIL — the slice changed behavior the tests caught");
                anyhow::bail!("behavioral verification failed; restore or re-slice this crate");
            }
            None => println!("  consumer has no tests — behavioral gate skipped (compile-only)"),
        }
    }

    // The headline: how much attack surface did carving actually remove?
    let surface_after = slice::measure_surface(&vendor_dir);
    print_attack_surface(&entry.crate_name, &surface_before, &surface_after);

    if let Some(path) = out {
        let combined = serde_json::json!({
            "slice": report,
            "surface_before": surface_before,
            "surface_after": surface_after,
        });
        std::fs::write(path, serde_json::to_string_pretty(&combined)?)?;
        println!("\n  slice + surface report written to {}", path.display());
    }
    Ok(())
}

/// Run the consumer's own test suite (in the project dir, so the cap-lints shim
/// applies). Returns Some(true)=passed, Some(false)=failed, None=no tests.
fn run_consumer_tests(manifest_path: &Path) -> Result<Option<bool>> {
    // Use an absolute manifest so setting `current_dir` to its parent doesn't
    // re-resolve the (relative) --manifest-path against the workdir and double it.
    let manifest_path = std::fs::canonicalize(manifest_path)
        .with_context(|| format!("resolving {}", manifest_path.display()))?;
    let workdir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let out = std::process::Command::new("cargo")
        .current_dir(&workdir)
        .args(["test", "--manifest-path"])
        .arg(&manifest_path)
        .output()
        .context("spawning cargo test")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Count tests actually run ("running N tests" lines from libtest).
    let mut total = 0usize;
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("running ") {
            if let Some(n) = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<usize>().ok())
            {
                total += n;
            }
        }
    }
    if !out.status.success() {
        return Ok(Some(false));
    }
    Ok(if total == 0 { None } else { Some(true) })
}

fn print_attack_surface(
    crate_name: &str,
    before: &model::AttackSurface,
    after: &model::AttackSurface,
) {
    println!("\n  ── attack surface reduction ({crate_name}) ──");
    let row = |label: &str, b: usize, a: usize, p: f64| {
        println!("      {label:<8} {b:>7} → {a:<7}  -{p:.1}%");
    };
    row("files", before.files, after.files, before.files_pct(after));
    row("LOC", before.loc, after.loc, before.loc_pct(after));
    row("items", before.items, after.items, before.items_pct(after));
    row(
        "bytes",
        before.bytes as usize,
        after.bytes as usize,
        before.bytes_pct(after),
    );
    row(
        "unsafe",
        before.unsafe_blocks,
        after.unsafe_blocks,
        before.unsafe_pct(after),
    );
    println!(
        "      ► attack surface cut by ~{:.0}% (LOC), {:.0}% of `unsafe` blocks removed",
        before.loc_pct(after),
        before.unsafe_pct(after)
    );
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
            let patched = if e.patches.is_empty() {
                String::new()
            } else {
                format!(", {} patched", e.patches.len())
            };
            println!(
                "  OK   {} v{} ({} files match ledger{patched})",
                e.crate_name,
                e.version,
                e.files.len()
            );
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

fn cmd_verify_tests(crate_name: &str, manifest_path: &Path) -> Result<()> {
    let root = root_of(manifest_path);
    let lock = vendor::load_lock(&root)?;
    let entry = lock
        .entry(crate_name)
        .context("crate is not vendored — nothing to test")?;
    let vmanifest = root
        .join(vendor::vendor_rel_path(&entry.crate_name, &entry.version))
        .join("Cargo.toml");
    if !vmanifest.exists() {
        anyhow::bail!("vendored Cargo.toml not found at {}", vmanifest.display());
    }
    println!(
        "Running {}'s OWN test suite against the vendored copy (behavioral equivalence)…",
        entry.crate_name
    );
    match run_consumer_tests(&vmanifest)? {
        Some(true) => {
            println!("  PASS — the vendored copy passes the crate's own tests.");
            println!("  (verbatim → faithful transcription; test-preserving slice → behaviorally equivalent)");
        }
        Some(false) => {
            anyhow::bail!(
                "the vendored copy FAILS the crate's own tests — not behaviorally equivalent"
            )
        }
        None => {
            println!("  No runnable tests in the vendored copy.");
            println!("  (sliced away, or the crate ships none — slice with tests preserved for an equivalence check)");
        }
    }
    Ok(())
}

fn cmd_patch(crate_name: &str, manifest_path: &Path, note: Option<String>) -> Result<()> {
    let root = root_of(manifest_path);
    let mut lock = vendor::load_lock(&root)?;
    let mut entry = lock
        .entry(crate_name)
        .cloned()
        .context("crate is not vendored — nothing to patch")?;
    let recorded = vendor::record_patches(&root, &mut entry, note)?;
    if recorded.is_empty() {
        println!("No local changes detected in {crate_name} — nothing to record.");
        println!(
            "(Edit files under vendor/{}-{}/ first, then re-run.)",
            entry.crate_name, entry.version
        );
        return Ok(());
    }
    lock.upsert(entry);
    vendor::save_lock(&root, &lock)?;
    println!(
        "Recorded {} intentional patch(es) for {crate_name}:",
        recorded.len()
    );
    for p in &recorded {
        println!("      {p}");
    }
    println!("\n  These are now tracked deltas (not drift): `carve verify` accepts them,");
    println!("  and an upgrade can re-base them against the next upstream slice.");
    Ok(())
}

fn cmd_impact(
    crate_name: &str,
    to: &str,
    manifest_path: &Path,
    out: Option<&Path>,
    diff: bool,
    scan: bool,
) -> Result<()> {
    let root = root_of(manifest_path);
    let lock = vendor::load_lock(&root)?;
    let entry = lock
        .entry(crate_name)
        .context("crate is not vendored — nothing to compare an update against")?;

    println!(
        "Assessing {crate_name} v{} -> v{to} against your vendored slice…\n",
        entry.version
    );
    let report = impact::analyze(entry, to)?;

    println!(
        "  upstream changed {} file(s) total:",
        report.total_changed_files
    );
    println!(
        "      {} outside your slice  → cannot touch you",
        report.changed_outside_slice
    );
    println!(
        "      {} inside your slice   → proof-read surface",
        report.changed_in_slice.len() + report.removed_from_slice.len()
    );

    if !report.changed_in_slice.is_empty() {
        println!("\n  Files in your slice that changed:");
        for f in &report.changed_in_slice {
            let flag = if f.affects_used.is_empty() {
                ""
            } else {
                "  ⚠ used API"
            };
            println!("      {}{}", f.upstream_path, flag);
            if !f.items_changed.is_empty() {
                println!("          items: {}", f.items_changed.join(", "));
            }
        }
    }
    if !report.removed_from_slice.is_empty() {
        println!("\n  Slice files DELETED upstream (API drift):");
        for f in &report.removed_from_slice {
            println!("      {f}");
        }
    }

    println!("\n  ──────────────────────────────────────────────");
    if !report.touches_us() {
        println!("  VERDICT: SAFE — this update does not touch any code you vendored.");
        println!("           Bump the version and re-transcribe; no proof-read needed.");
    } else if report.touches_used_api() {
        println!("  VERDICT: PROOF-READ REQUIRED — update changes items you CALL:");
        println!("           {}", report.used_items_affected.join(", "));
    } else {
        println!("  VERDICT: PROOF-READ the changed slice files above.");
        println!("           (They are in your tree but not items you directly call.)");
    }
    println!("  ──────────────────────────────────────────────");

    if diff && !report.changed_in_slice.is_empty() {
        println!("\n  ── proof-read surface: unified diff of in-slice changes ──");
        for (path, d) in impact::unified_diffs(entry, to, &report)? {
            println!("\n### {path}");
            if d.trim().is_empty() {
                println!("(no textual diff)");
            } else {
                print!("{d}");
            }
        }
    }

    if scan && report.touches_us() {
        let combined: String = impact::unified_diffs(entry, to, &report)?
            .into_iter()
            .map(|(p, d)| format!("### {p}\n{d}\n"))
            .collect();
        if combined.trim().is_empty() {
            println!("\n  (no textual diff to scan)");
        } else {
            println!("\n  ── LLM security scan of the in-slice update diff ──");
            match agent::LlmAgent::from_env() {
                Ok(a) => println!("{}", a.review_diff(crate_name, &combined)?),
                Err(e) => println!("  scan unavailable: {e}"),
            }
        }
    }

    if let Some(path) = out {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
        println!("\n  impact report written to {}", path.display());
    }
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
        None => println!(
            "  not found as a top-level item (may be a method, macro-generated, or re-export)"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod dogfood {
    /// carve eats its own dog food: analyze carve's own dependency tree and
    /// confirm the DFUG finds known direct deps. Exercises metadata + scanner
    /// end-to-end on a real crate (this one).
    #[test]
    fn analyzes_its_own_dependency_tree() {
        let graph = crate::analyze::build_usage_graph("Cargo.toml")
            .expect("carve should analyze its own manifest");
        assert_eq!(graph.package, "carve");
        let names: Vec<&str> = graph.crates.iter().map(|c| c.name.as_str()).collect();
        for expected in ["anyhow", "clap", "syn", "serde"] {
            assert!(
                names.contains(&expected),
                "DFUG missing {expected}: {names:?}"
            );
        }
    }
}
