use crate::optimizer;
use crate::parser;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const RULES_FILENAME: &str = "token-optimization.md";
const LAST_RUN_FILE: &str = "/tmp/.auto_optimize_last";
const MIN_INTERVAL_SECS: u64 = 300;

fn should_run() -> bool {
    match std::fs::read_to_string(LAST_RUN_FILE) {
        Ok(s) => {
            let last: f64 = s.trim().parse().unwrap_or(0.0);
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
            (now - last) > MIN_INTERVAL_SECS as f64
        }
        Err(_) => true,
    }
}

fn mark_ran() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    let _ = std::fs::write(LAST_RUN_FILE, format!("{}", now));
}

fn find_project_root() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if output.status.success() {
        let s = String::from_utf8(output.stdout).ok()?;
        Some(PathBuf::from(s.trim()))
    } else {
        let cwd = std::env::current_dir().ok()?;
        if cwd.join(".claude").exists() || cwd.join("CLAUDE.md").exists() {
            Some(cwd)
        } else {
            None
        }
    }
}

fn rules_changed(old_content: &str, rules: &[optimizer::Rule]) -> bool {
    let old_titles: std::collections::HashSet<&str> = old_content.lines()
        .filter(|l| l.starts_with("## ["))
        .filter_map(|l| l.split("] ").nth(1))
        .collect();
    let new_titles: std::collections::HashSet<&str> = rules.iter().map(|r| r.title.as_str()).collect();
    old_titles != new_titles
}

pub fn run_hook() {
    if !should_run() { return; }

    let jsonl = match parser::find_session_jsonl() {
        Some(p) => p,
        None => return,
    };

    let rules = optimizer::analyze(&jsonl);
    if rules.is_empty() { return; }

    mark_ran();

    let project_root = match find_project_root() {
        Some(p) => p,
        None => return,
    };

    let rules_dir = project_root.join(".claude").join("rules");
    let _ = std::fs::create_dir_all(&rules_dir);
    let rules_file = rules_dir.join(RULES_FILENAME);

    let old_content = std::fs::read_to_string(&rules_file).unwrap_or_default();

    if rules_changed(&old_content, &rules) {
        let content = optimizer::format_rules(&rules);
        let _ = std::fs::write(&rules_file, &content);
        let top = rules.first().map(|r| r.title.as_str()).unwrap_or("");
        println!("📊 .claude/rules/{} updated: {} rules (top: {})", RULES_FILENAME, rules.len(), top);
    }
}
