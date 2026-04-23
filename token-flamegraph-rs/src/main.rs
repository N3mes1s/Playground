mod parser;
mod flamegraph;
mod terminal;
mod render;
mod optimizer;
mod compare;
mod auto_optimize;

use clap::Parser as ClapParser;
use std::path::PathBuf;

#[derive(ClapParser)]
#[command(name = "token-flamegraph", about = "Session analysis for AI coding agents (Claude Code, Codex, Aider, Pi, Copilot)")]
struct Cli {
    /// Analyze current session (auto-detects agent)
    #[arg(long = "self")]
    analyze_self: bool,

    /// Show demo with sample data
    #[arg(long)]
    demo: bool,

    /// Generate HTML flamegraph
    #[arg(long, value_name = "FILE")]
    html: Option<PathBuf>,

    /// Run optimizer to generate .claude/rules/
    #[arg(long)]
    optimize: bool,

    /// Snapshot current metrics
    #[arg(long)]
    snapshot: bool,

    /// Diff against last snapshot
    #[arg(long)]
    diff: bool,

    /// Run as Stop hook (auto-optimize)
    #[arg(long)]
    hook: bool,

    /// Parse as Codex CLI session
    #[arg(long)]
    codex: bool,

    /// Parse as Aider session
    #[arg(long)]
    aider: bool,

    /// Parse as Pi session
    #[arg(long)]
    pi: bool,

    /// Parse as Copilot CLI session
    #[arg(long)]
    copilot: bool,

    /// Analyze a teleport export
    #[arg(long, value_name = "FILE")]
    teleport: Option<PathBuf>,

    /// Session JSONL file to analyze
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    if cli.hook {
        auto_optimize::run_hook();
        return;
    }

    if cli.optimize {
        let path = cli.file.or_else(|| parser::find_session_jsonl());
        match path {
            Some(p) => optimizer::run_and_print(&p),
            None => eprintln!("No session file found. Pass a JSONL path or run inside a Claude Code project."),
        }
        return;
    }

    if cli.snapshot {
        let path = cli.file.or_else(|| parser::find_session_jsonl());
        match path {
            Some(p) => compare::snapshot(&p),
            None => eprintln!("No session file found."),
        }
        return;
    }

    if cli.diff {
        let path = cli.file.or_else(|| parser::find_session_jsonl());
        match path {
            Some(p) => compare::diff(&p),
            None => eprintln!("No session file found."),
        }
        return;
    }

    // Parse session — agent-specific flags override auto-detect
    let parse_file = |path: &std::path::Path| -> parser::Session {
        if cli.codex { parser::parse_codex(path) }
        else if cli.aider { parser::parse_aider(path) }
        else if cli.pi { parser::parse_pi(path) }
        else if cli.copilot { parser::parse_copilot(path) }
        else { parser::parse_auto(path) }
    };

    let find_agent_session = || -> Option<PathBuf> {
        if cli.codex { parser::find_codex_session() }
        else if cli.aider { parser::find_aider_session() }
        else if cli.pi { parser::find_pi_session() }
        else if cli.copilot { parser::find_copilot_session() }
        else { parser::find_session_jsonl() }
    };

    let session = if cli.demo {
        parser::demo_session()
    } else if let Some(ref tp) = cli.teleport {
        parser::parse_teleport(tp)
    } else if let Some(ref f) = cli.file {
        parse_file(f)
    } else {
        match find_agent_session() {
            Some(p) => parse_file(&p),
            None => {
                eprintln!("No session found. Supported agents: Claude Code, Codex, Aider, Pi, Copilot CLI");
                eprintln!("Usage: token-flamegraph [--self | --demo | --codex | --aider | --pi | --copilot | FILE]");
                std::process::exit(1);
            }
        }
    };

    if let Some(ref html_path) = cli.html {
        let viz = flamegraph::session_to_viz(&session);
        let html = render::render_html(&viz, "Token Flamegraph");
        std::fs::write(html_path, &html).expect("Failed to write HTML");
        println!("  HTML flamegraph: {}", html_path.display());
    } else {
        let viz = flamegraph::session_to_viz(&session);
        terminal::render_dashboard(&viz);
    }
}
