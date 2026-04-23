use crate::parser;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SNAPSHOT_FILE: &str = "/tmp/.flamegraph_snapshot.json";

#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    output_tokens: usize,
    input_tokens: usize,
    thinking_tokens: usize,
    tool_calls: usize,
    turns: usize,
    cache_read: usize,
}

pub fn snapshot(path: &Path) {
    let session = parser::parse_jsonl(path);
    let tool_calls: usize = session.turns.iter().map(|t| t.tool_calls.len()).sum();
    let snap = Snapshot {
        output_tokens: session.total_output,
        input_tokens: session.total_input,
        thinking_tokens: session.total_thinking,
        tool_calls,
        turns: session.turns.len(),
        cache_read: session.total_cache_read,
    };
    let json = serde_json::to_string_pretty(&snap).unwrap();
    std::fs::write(SNAPSHOT_FILE, &json).expect("Failed to write snapshot");
    println!("  📸 Snapshot saved ({} turns, {} output tokens)", snap.turns, snap.output_tokens);
}

pub fn diff(path: &Path) {
    let old: Snapshot = match std::fs::read_to_string(SNAPSHOT_FILE) {
        Ok(s) => serde_json::from_str(&s).expect("Invalid snapshot"),
        Err(_) => {
            eprintln!("  No snapshot found. Run --snapshot first.");
            return;
        }
    };

    let session = parser::parse_jsonl(path);
    let tool_calls: usize = session.turns.iter().map(|t| t.tool_calls.len()).sum();
    let new = Snapshot {
        output_tokens: session.total_output,
        input_tokens: session.total_input,
        thinking_tokens: session.total_thinking,
        tool_calls,
        turns: session.turns.len(),
        cache_read: session.total_cache_read,
    };

    println!("  📊 Session Comparison\n");
    println!("  {:<20} {:>10} {:>10} {:>10}", "Metric", "Before", "After", "Delta");
    println!("  {}", "─".repeat(55));

    let metrics = [
        ("Output tokens", old.output_tokens, new.output_tokens),
        ("Input tokens", old.input_tokens, new.input_tokens),
        ("Thinking tokens", old.thinking_tokens, new.thinking_tokens),
        ("Tool calls", old.tool_calls, new.tool_calls),
        ("Turns", old.turns, new.turns),
        ("Cache read", old.cache_read, new.cache_read),
    ];

    for (name, before, after) in &metrics {
        let delta = *after as i64 - *before as i64;
        let arrow = if delta > 0 { "\x1b[91m↑" } else if delta < 0 { "\x1b[92m↓" } else { "\x1b[90m=" };
        println!("  {:<20} {:>10} {:>10} {}{:>+10}\x1b[0m", name, before, after, arrow, delta);
    }
    println!();
}
