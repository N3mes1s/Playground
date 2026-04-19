use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

pub struct Rule {
    pub title: String,
    pub evidence: String,
    pub directive: String,
    pub savings_pct: f64,
    pub priority: u8, // 1=HIGH, 2=MED, 3=LOW
}

pub fn analyze(path: &Path) -> Vec<Rule> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let records: Vec<Value> = content.lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .collect();

    let mut rules = Vec::new();
    rules.extend(check_read_write_sequences(&records));
    rules.extend(check_large_writes(&records));
    rules.extend(check_bash_streaks(&records));
    rules.extend(check_duplicate_reads(&records));
    rules.extend(check_full_reads(&records));
    rules.extend(check_grep_in_bash(&records));
    rules.extend(check_find_in_bash(&records));
    rules.sort_by_key(|r| r.priority);
    rules
}

fn extract_tool_calls(records: &[Value]) -> Vec<(String, &Value)> {
    let mut calls = Vec::new();
    for rec in records {
        if rec.get("type").and_then(|v| v.as_str()) != Some("assistant") { continue; }
        let msg = match rec.get("message") { Some(m) => m, None => continue };
        let content = match msg.get("content").and_then(|v| v.as_array()) { Some(c) => c, None => continue };
        for block in content {
            if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                calls.push((name, block));
            }
        }
    }
    calls
}

fn check_read_write_sequences(records: &[Value]) -> Vec<Rule> {
    let calls = extract_tool_calls(records);
    let mut count = 0;
    for i in 1..calls.len() {
        if calls[i-1].0 == "Read" && calls[i].0 == "Write" {
            count += 1;
        }
    }
    if count >= 2 {
        vec![Rule {
            title: "Use Edit instead of Read+Write".to_string(),
            evidence: format!("{} occurrences of Read immediately followed by Write", count),
            directive: "When modifying existing files, always use Edit (not Read+Write). Edit sends only the changed lines, saving ~60% of output tokens per file modification.".to_string(),
            savings_pct: 15.0,
            priority: 1,
        }]
    } else { vec![] }
}

fn check_large_writes(records: &[Value]) -> Vec<Rule> {
    let calls = extract_tool_calls(records);
    let mut sizes: Vec<usize> = Vec::new();
    for (name, block) in &calls {
        if name == "Write" {
            let content_len = block.get("input")
                .and_then(|v| v.get("content"))
                .and_then(|v| v.as_str())
                .map(|s| s.len())
                .unwrap_or(0);
            if content_len > 3000 { sizes.push(content_len); }
        }
    }
    if sizes.len() >= 3 {
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        let top5: Vec<String> = sizes.iter().take(5).map(|s| s.to_string()).collect();
        vec![Rule {
            title: "Large Write calls dominate output".to_string(),
            evidence: format!("Write sizes: [{}]", top5.join(", ")),
            directive: "For files over 50 lines, prefer Edit over Write. If creating a new large file, consider splitting into smaller logical files to reduce per-call token cost.".to_string(),
            savings_pct: 20.0,
            priority: 1,
        }]
    } else { vec![] }
}

fn check_bash_streaks(records: &[Value]) -> Vec<Rule> {
    let calls = extract_tool_calls(records);
    let mut streaks: Vec<usize> = Vec::new();
    let mut current = 0;
    for (name, _) in &calls {
        if name == "Bash" { current += 1; }
        else {
            if current >= 3 { streaks.push(current); }
            current = 0;
        }
    }
    if current >= 3 { streaks.push(current); }

    if !streaks.is_empty() {
        let streak_strs: Vec<String> = streaks.iter().map(|s| s.to_string()).collect();
        vec![Rule {
            title: "Batch sequential Bash commands".to_string(),
            evidence: format!("Bash streaks: [{}]", streak_strs.join(", ")),
            directive: "Chain independent Bash commands with && in a single call. Run truly independent commands as parallel tool calls. Each separate Bash call costs a full context round-trip.".to_string(),
            savings_pct: 10.0,
            priority: 2,
        }]
    } else { vec![] }
}

fn check_duplicate_reads(records: &[Value]) -> Vec<Rule> {
    let calls = extract_tool_calls(records);
    let mut read_counts: HashMap<String, usize> = HashMap::new();
    for (name, block) in &calls {
        if name == "Read" {
            if let Some(path) = block.get("input").and_then(|v| v.get("file_path")).and_then(|v| v.as_str()) {
                *read_counts.entry(path.to_string()).or_insert(0) += 1;
            }
        }
    }
    let duplicates: HashMap<String, usize> = read_counts.into_iter().filter(|(_, c)| *c > 1).collect();
    let total: usize = duplicates.values().sum();
    if total >= 5 {
        let top: Vec<String> = {
            let mut v: Vec<_> = duplicates.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1));
            v.iter().take(5).map(|(p, c)| format!("'{}': {}", p, c)).collect()
        };
        vec![Rule {
            title: format!("{} duplicate file reads", total),
            evidence: format!("Duplicates: {{{}}}", top.join(", ")),
            directive: "Before reading a file, check if you've already read it in this conversation. Store key information from reads in your response text so you don't need to re-read.".to_string(),
            savings_pct: 5.0,
            priority: 3,
        }]
    } else { vec![] }
}

fn check_full_reads(records: &[Value]) -> Vec<Rule> {
    let calls = extract_tool_calls(records);
    let mut count = 0;
    let mut files = Vec::new();
    for (name, block) in &calls {
        if name == "Read" {
            let input = block.get("input").unwrap_or(&Value::Null);
            if input.get("limit").is_none() && input.get("offset").is_none() {
                count += 1;
                if let Some(p) = input.get("file_path").and_then(|v| v.as_str()) {
                    if files.len() < 5 { files.push(p.to_string()); }
                }
            }
        }
    }
    if count >= 5 {
        vec![Rule {
            title: format!("{} full file reads without limit", count),
            evidence: format!("Full reads: {:?}", files),
            directive: "Use the limit and offset parameters when reading files. Read only the section you need, not the entire file.".to_string(),
            savings_pct: 8.0,
            priority: 3,
        }]
    } else { vec![] }
}

fn check_grep_in_bash(records: &[Value]) -> Vec<Rule> {
    let calls = extract_tool_calls(records);
    let mut count = 0;
    let mut examples = Vec::new();
    for (name, block) in &calls {
        if name == "Bash" {
            if let Some(cmd) = block.get("input").and_then(|v| v.get("command")).and_then(|v| v.as_str()) {
                if cmd.contains("grep ") || cmd.contains("rg ") {
                    count += 1;
                    if examples.len() < 3 { examples.push(cmd.chars().take(50).collect::<String>()); }
                }
            }
        }
    }
    if count >= 3 {
        vec![Rule {
            title: format!("{} grep/rg calls via Bash", count),
            evidence: format!("Commands: {:?}", examples),
            directive: "Never use `grep` or `rg` via Bash. Always use the Grep tool — it's optimized for permissions and returns structured results with less token overhead.".to_string(),
            savings_pct: 3.0,
            priority: 3,
        }]
    } else { vec![] }
}

fn check_find_in_bash(records: &[Value]) -> Vec<Rule> {
    let calls = extract_tool_calls(records);
    let mut count = 0;
    let mut examples = Vec::new();
    for (name, block) in &calls {
        if name == "Bash" {
            if let Some(cmd) = block.get("input").and_then(|v| v.get("command")).and_then(|v| v.as_str()) {
                if cmd.starts_with("find ") || cmd.starts_with("ls ") || cmd.contains("| find ") {
                    count += 1;
                    if examples.len() < 3 { examples.push(cmd.chars().take(50).collect::<String>()); }
                }
            }
        }
    }
    if count >= 3 {
        vec![Rule {
            title: format!("{} find/ls calls via Bash", count),
            evidence: format!("Commands: {:?}", examples),
            directive: "Never use `find` or `ls` via Bash for file discovery. Use the Glob tool with patterns like '**/*.py' — it's faster and costs fewer tokens.".to_string(),
            savings_pct: 3.0,
            priority: 3,
        }]
    } else { vec![] }
}

pub fn format_rules(rules: &[Rule]) -> String {
    let sev = |p: u8| match p { 1 => "HIGH", 2 => "MED", _ => "LOW" };
    let mut lines = vec![
        "# Token Optimization Rules".to_string(),
        String::new(),
        format!("# Auto-generated by token-flamegraph (updated {})", chrono_now()),
        "# This file is managed automatically. Your CLAUDE.md is never touched.".to_string(),
        String::new(),
    ];
    for rule in rules {
        lines.push(format!("## [{}] {}", sev(rule.priority), rule.title));
        lines.push(format!("# Saves ~{:.0}% — {}", rule.savings_pct, rule.evidence));
        lines.push(rule.directive.clone());
        lines.push(String::new());
    }
    lines.join("\n")
}

fn chrono_now() -> String {
    use std::process::Command;
    Command::new("date").arg("+%Y-%m-%d %H:%M:%S")
        .output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn run_and_print(path: &Path) {
    let rules = analyze(path);
    if rules.is_empty() {
        println!("  No optimization rules found (session too short or already efficient).");
        return;
    }
    let total_savings: f64 = rules.iter().map(|r| r.savings_pct).sum();
    println!("Found {} optimization rules (est. ~{:.0}% savings)\n", rules.len(), total_savings);

    let sev_icon = |p: u8| match p { 1 => "🔴", 2 => "🟡", _ => "🔵" };
    let sev_name = |p: u8| match p { 1 => "HIGH", 2 => "MED", _ => "LOW" };
    for rule in &rules {
        println!("  {} [{}] {}", sev_icon(rule.priority), sev_name(rule.priority), rule.title);
        println!("     {}", rule.evidence);
        println!("     💡 {}\n", &rule.directive[..rule.directive.len().min(80)]);
    }
}
