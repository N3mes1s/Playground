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
#[command(name = "token-flamegraph", about = "Session analysis for Claude Code")]
struct Cli {
    /// Analyze current session
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

    let session = if cli.demo {
        parser::demo_session()
    } else if let Some(ref tp) = cli.teleport {
        parser::parse_teleport(tp)
    } else if cli.analyze_self {
        match parser::find_session_jsonl() {
            Some(p) => parser::parse_jsonl(&p),
            None => {
                eprintln!("No session file found.");
                std::process::exit(1);
            }
        }
    } else if let Some(ref f) = cli.file {
        parser::parse_jsonl(f)
    } else {
        // Default: try --self
        match parser::find_session_jsonl() {
            Some(p) => parser::parse_jsonl(&p),
            None => {
                eprintln!("Usage: token-flamegraph [--self | --demo | FILE]");
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
