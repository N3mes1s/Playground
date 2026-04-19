use crate::flamegraph::VizData;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const FULL: &str = "█";

fn color(cat: &str) -> &'static str {
    match cat {
        "thinking" => "\x1b[91m",
        "text" => "\x1b[94m",
        "read" => "\x1b[92m",
        "write" => "\x1b[93m",
        "bash" => "\x1b[95m",
        "search" => "\x1b[32m",
        "agent" => "\x1b[31m",
        "other" => "\x1b[96m",
        "cache" => "\x1b[90m",
        "fresh" => "\x1b[37m",
        _ => "\x1b[96m",
    }
}

fn bar(value: usize, max_val: usize, cat: &str, width: usize) -> String {
    if max_val == 0 { return String::new(); }
    let filled = (value as f64 / max_val as f64 * width as f64).ceil() as usize;
    let filled = filled.min(width);
    format!("{}{}{}", color(cat), FULL.repeat(filled), RESET)
}

fn fmt_tokens(n: usize) -> String {
    if n >= 1_000_000 { format!("{:.1}M", n as f64 / 1_000_000.0) }
    else if n >= 1_000 { format!("{:.1}K", n as f64 / 1_000.0) }
    else { format!("{}", n) }
}

fn pct(n: usize, total: usize) -> String {
    if total == 0 { "0%".to_string() }
    else { format!("{:.1}%", n as f64 / total as f64 * 100.0) }
}

fn score_color(s: f64) -> &'static str {
    if s >= 80.0 { "\x1b[92m" }
    else if s >= 60.0 { "\x1b[93m" }
    else { "\x1b[91m" }
}

pub fn render_dashboard(viz: &VizData) {
    let w = 80;
    println!("{BOLD}{}{RESET}", "═".repeat(w));
    println!("{BOLD}  Token Flamegraph{RESET}");
    if !viz.model.is_empty() {
        println!("  {DIM}Model: {}{RESET}", viz.model);
    }
    println!("{BOLD}{}{RESET}", "═".repeat(w));

    let t = &viz.totals;
    let avg_score: f64 = if viz.turns.is_empty() { 0.0 } else {
        viz.turns.iter().map(|t| t.efficiency_score).sum::<f64>() / viz.turns.len() as f64
    };
    let cache_ratio = if t.input > 0 { t.cache as f64 / t.input as f64 * 100.0 } else { 0.0 };

    // Cost estimate (Opus pricing rough)
    let input_cost = t.input as f64 / 1_000_000.0 * 15.0;
    let cached_cost = t.cache as f64 / 1_000_000.0 * 1.5;
    let fresh_cost = (t.input - t.cache) as f64 / 1_000_000.0 * 15.0;
    let output_cost = t.output as f64 / 1_000_000.0 * 75.0;
    let total_cost = cached_cost + fresh_cost + output_cost;
    let saved = input_cost - (cached_cost + fresh_cost);

    println!();
    println!("  {BOLD}Output:{RESET} {:<12} {BOLD}Thinking:{RESET} {:<12} {BOLD}Tool Calls:{RESET} {:<6} {BOLD}Turns:{RESET} {:<4} {BOLD}Score:{RESET} {}⚡{:.0}{RESET}",
        fmt_tokens(t.output), fmt_tokens(t.thinking), t.tool_calls, viz.turns.len(), score_color(avg_score), avg_score);
    println!("  {BOLD}Input:{RESET}  {:<12} {BOLD}Cached:{RESET} {} ({:.1}%)    {BOLD}Cost:{RESET} ${:.2} (saved ${:.2} from cache)",
        fmt_tokens(t.input), fmt_tokens(t.cache), cache_ratio, total_cost, saved);

    // Timeline
    println!();
    println!("  {DIM}{}{RESET}", "─".repeat(w - 4));
    println!("  {BOLD}TIMELINE — Output Tokens per Turn{RESET}");
    println!("  {DIM}{}{RESET}", "─".repeat(w - 4));

    let max_output = viz.turns.iter().map(|t| t.output_tokens).max().unwrap_or(1);

    for turn in &viz.turns {
        let sc = turn.efficiency_score;
        let sc_col = score_color(sc);

        // Main bar
        let mut segments = Vec::new();
        if turn.thinking > 0 { segments.push(bar(turn.thinking, max_output, "thinking", 40)); }
        for tool in &turn.tools {
            segments.push(bar(tool.total_tokens, max_output, &tool.category, 40));
        }
        if turn.text > 0 { segments.push(bar(turn.text, max_output, "text", 40)); }

        let bar_str = segments.join("");
        println!();
        println!("  {BOLD}Turn {:2}{RESET} │{bar_str}│  {:>6} tok  {sc_col}⚡{:>4.0}{RESET}",
            turn.index, fmt_tokens(turn.output_tokens), sc);

        // Tool details
        if !turn.tools.is_empty() {
            let names: Vec<String> = turn.tools.iter().take(6).map(|t| {
                let c = color(&t.category);
                let short: String = t.name.chars().take(28).collect();
                format!("{c}{short}{RESET}")
            }).collect();
            let more = if turn.tools.len() > 6 { format!(" {DIM}+{} more{RESET}", turn.tools.len() - 6) } else { String::new() };
            println!("         │ {}{more}", names.join(", "));
        }
    }

    // Wall time (if available)
    if viz.turns.iter().any(|t| t.duration_ms > 0) {
        println!();
        println!("  {DIM}{}{RESET}", "─".repeat(w - 4));
        println!("  {BOLD}WALL TIME PER TURN{RESET}");
        println!("  {DIM}{}{RESET}", "─".repeat(w - 4));

        let max_dur = viz.turns.iter().map(|t| t.duration_ms).max().unwrap_or(1);
        let total_wall: u64 = viz.turns.iter().map(|t| t.duration_ms).sum();
        let total_api: u64 = viz.turns.iter().map(|t| t.duration_api_ms).sum();

        for turn in &viz.turns {
            if turn.duration_ms == 0 { continue; }
            let api_bar = bar(turn.duration_api_ms as usize, max_dur as usize, "thinking", 30);
            let overhead_bar = bar((turn.duration_ms - turn.duration_api_ms) as usize, max_dur as usize, "bash", 10);
            let model_pct = turn.duration_api_ms * 100 / turn.duration_ms.max(1);
            println!("  T{:<3} {api_bar}{overhead_bar} {:>6.1}s ({}% model)",
                turn.index, turn.duration_ms as f64 / 1000.0, model_pct);
        }
        println!("  {DIM}Total: {:.1}s wall / {:.1}s model / {:.1}s overhead{RESET}",
            total_wall as f64 / 1000.0, total_api as f64 / 1000.0, (total_wall - total_api) as f64 / 1000.0);
    }

    // Output breakdown
    println!();
    println!("  {DIM}{}{RESET}", "─".repeat(w - 4));
    println!("  {BOLD}OUTPUT TOKEN BREAKDOWN{RESET}");
    println!("  {DIM}{}{RESET}", "─".repeat(w - 4));

    let mut categories: Vec<(&str, usize, &str)> = vec![
        ("Thinking", t.thinking, "thinking"),
        ("Text output", t.text, "text"),
    ];
    let cat_names: std::collections::HashMap<&str, &str> = [
        ("read", "File reads"), ("write", "File writes"), ("bash", "Shell commands"),
        ("search", "Search"), ("agent", "Sub-agents"), ("other", "Other tools"),
    ].into();
    let mut cat_list: Vec<_> = viz.category_tokens.iter().collect();
    cat_list.sort_by(|a, b| b.1.cmp(a.1));
    for (cat, tokens) in &cat_list {
        categories.push((cat_names.get(cat.as_str()).unwrap_or(&cat.as_str()), **tokens, cat));
    }
    let max_cat = categories.iter().map(|(_, t, _)| *t).max().unwrap_or(1);
    let total_cat: usize = categories.iter().map(|(_, t, _)| *t).sum();
    for (name, tokens, cat) in &categories {
        let b = bar(*tokens, max_cat, cat, 35);
        println!("  {:<16} {b} {:>7} ({})", name, fmt_tokens(*tokens), pct(*tokens, total_cat));
    }

    // Top tools
    if !viz.top_tools.is_empty() {
        println!();
        println!("  {DIM}{}{RESET}", "─".repeat(w - 4));
        println!("  {BOLD}TOP TOKEN CONSUMERS{RESET}");
        println!("  {DIM}{}{RESET}", "─".repeat(w - 4));

        let max_tool = viz.top_tools[0].tokens;
        for tool in viz.top_tools.iter().take(10) {
            let cat = if tool.name.starts_with("Read") { "read" }
                else if tool.name.starts_with("Edit") || tool.name.starts_with("Write") { "write" }
                else if tool.name.starts_with("Bash") { "bash" }
                else if tool.name.starts_with("Grep") || tool.name.starts_with("Glob") { "search" }
                else if tool.name.starts_with("Agent") { "agent" }
                else { "other" };
            let b = bar(tool.tokens, max_tool, cat, 30);
            let short: String = tool.name.chars().take(42).collect();
            println!("  {:<44} {b} {:>6}", short, fmt_tokens(tool.tokens));
        }
    }

    println!();
    println!("{BOLD}{}{RESET}", "═".repeat(w));

    // Legend
    let legend = [("thinking", "Thinking"), ("text", "Text"), ("write", "Write"),
        ("read", "Read"), ("bash", "Shell"), ("search", "Search"), ("agent", "Agent")];
    let leg: Vec<String> = legend.iter().map(|(cat, name)| format!("{}{FULL}{FULL}{RESET} {name}", color(cat))).collect();
    println!("  {}", leg.join("  "));
    println!();
}
