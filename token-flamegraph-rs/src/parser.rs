use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ToolCall {
    pub name: String,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub duration_ms: u64,
    pub children: Vec<ToolCall>,
    pub input_preview: String,
    pub output_preview: String,
}

#[derive(Debug, Clone, Default)]
pub struct Turn {
    pub index: usize,
    pub role: String,
    pub thinking_tokens: usize,
    pub output_tokens: usize,
    pub input_tokens: usize,
    pub tool_calls: Vec<ToolCall>,
    pub text_preview: String,
    pub cache_read_tokens: usize,
    pub cache_write_tokens: usize,
    pub api_calls: usize,
    pub duration_ms: u64,
    pub duration_api_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Session {
    pub session_id: String,
    pub model: String,
    pub turns: Vec<Turn>,
    pub total_input: usize,
    pub total_output: usize,
    pub total_thinking: usize,
    pub total_cache_read: usize,
    pub total_cache_write: usize,
}

impl Session {
    pub fn compute_totals(&mut self) {
        self.total_input = self.turns.iter().map(|t| t.input_tokens).sum();
        self.total_output = self.turns.iter().map(|t| t.output_tokens).sum();
        self.total_thinking = self.turns.iter().map(|t| t.thinking_tokens).sum();
        self.total_cache_read = self.turns.iter().map(|t| t.cache_read_tokens).sum();
        self.total_cache_write = self.turns.iter().map(|t| t.cache_write_tokens).sum();
    }
}

fn is_real_user_message(rec: &Value) -> bool {
    if rec.get("type").and_then(|v| v.as_str()) != Some("user") {
        return false;
    }
    let msg = match rec.get("message") {
        Some(m) => m,
        None => return false,
    };
    let content = match msg.get("content") {
        Some(c) => c,
        None => return true,
    };
    if content.is_string() {
        return true;
    }
    if let Some(arr) = content.as_array() {
        let all_tool_results = arr.iter().all(|b| {
            b.get("type").and_then(|v| v.as_str()) == Some("tool_result")
        });
        return !all_tool_results;
    }
    true
}

fn parse_tool_use(block: &Value) -> ToolCall {
    let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let input = block.get("input").cloned().unwrap_or(Value::Null);
    let input_str = serde_json::to_string(&input).unwrap_or_default();
    let input_tokens = input_str.len() / 4;
    ToolCall {
        name,
        input_tokens,
        input_preview: input_str.chars().take(120).collect(),
        ..Default::default()
    }
}

pub fn parse_jsonl(path: &Path) -> Session {
    let content = std::fs::read_to_string(path).expect("Failed to read JSONL file");
    let mut session = Session::default();
    let mut turn_idx = 0usize;
    let mut current_turn: Option<Turn> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let rec_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if rec_type != "user" && rec_type != "assistant" {
            continue;
        }

        let msg = match rec.get("message") {
            Some(Value::Object(_)) => rec.get("message").unwrap(),
            _ => continue,
        };

        if session.model.is_empty() {
            if let Some(m) = msg.get("model").and_then(|v| v.as_str()) {
                session.model = m.to_string();
            }
        }
        if session.session_id.is_empty() {
            if let Some(s) = rec.get("sessionId").and_then(|v| v.as_str()) {
                session.session_id = s.to_string();
            }
        }

        if is_real_user_message(&rec) {
            if let Some(t) = current_turn.take() {
                session.turns.push(t);
                turn_idx += 1;
            }
            let mut user_text = String::new();
            if let Some(c) = msg.get("content") {
                if let Some(s) = c.as_str() {
                    user_text = s.chars().take(120).collect();
                } else if let Some(arr) = c.as_array() {
                    for b in arr {
                        if b.get("type").and_then(|v| v.as_str()) == Some("text") {
                            if let Some(t) = b.get("text").and_then(|v| v.as_str()) {
                                user_text = t.chars().take(120).collect();
                                break;
                            }
                        }
                    }
                }
            }
            session.turns.push(Turn {
                index: turn_idx,
                role: "user".to_string(),
                text_preview: user_text,
                ..Default::default()
            });
            turn_idx += 1;
            continue;
        }

        if rec_type == "assistant" {
            let turn = current_turn.get_or_insert_with(|| Turn {
                index: turn_idx,
                role: "assistant".to_string(),
                ..Default::default()
            });
            turn.api_calls += 1;

            let usage = msg.get("usage");
            if let Some(u) = usage {
                // Output tokens: sum per API call
                turn.output_tokens += u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                // Input tokens: take MAX (cumulative per API call within a turn)
                let inp = u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize
                    + u.get("cache_read_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize
                    + u.get("cache_creation_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if inp > turn.input_tokens {
                    turn.input_tokens = inp;
                    turn.cache_read_tokens = u.get("cache_read_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    turn.cache_write_tokens = u.get("cache_creation_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                }
            }

            if let Some(content) = msg.get("content").and_then(|v| v.as_array()) {
                for block in content {
                    let btype = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match btype {
                        "thinking" => {
                            if let Some(text) = block.get("thinking").and_then(|v| v.as_str()) {
                                turn.thinking_tokens += text.len() / 4;
                            }
                        }
                        "text" => {
                            if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                if !text.trim().is_empty() && turn.text_preview.is_empty() {
                                    turn.text_preview = text.chars().take(120).collect();
                                }
                            }
                        }
                        "tool_use" => {
                            let tc = parse_tool_use(block);
                            turn.tool_calls.push(tc);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if let Some(t) = current_turn {
        session.turns.push(t);
    }

    session.compute_totals();
    session
}

pub fn parse_teleport(path: &Path) -> Session {
    let content = std::fs::read_to_string(path).expect("Failed to read teleport export");
    let data: Value = serde_json::from_str(&content).expect("Invalid JSON");
    let events = data.get("events").and_then(|v| v.as_array()).expect("No events array");
    let session_meta = data.get("session").unwrap_or(&Value::Null);

    let mut session = Session::default();
    if let Some(id) = session_meta.get("id").and_then(|v| v.as_str()) {
        session.session_id = id.to_string();
    }
    if let Some(ctx) = session_meta.get("session_context") {
        if let Some(m) = ctx.get("model").and_then(|v| v.as_str()) {
            session.model = m.to_string();
        }
    }

    let mut turn_idx = 0usize;
    let mut current_turn: Option<Turn> = None;

    for event in events {
        let etype = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match etype {
            "system" => {
                if session.model.is_empty() {
                    if let Some(m) = event.get("model").and_then(|v| v.as_str()) {
                        session.model = m.to_string();
                    }
                }
            }
            "user" => {
                let msg = event.get("message").unwrap_or(&Value::Null);
                let content = msg.get("content").unwrap_or(&Value::Null);
                let is_tool_result = if let Some(arr) = content.as_array() {
                    arr.iter().all(|b| b.get("type").and_then(|v| v.as_str()) == Some("tool_result"))
                } else {
                    false
                };
                if !is_tool_result {
                    if let Some(t) = current_turn.take() {
                        session.turns.push(t);
                        turn_idx += 1;
                    }
                    let mut text = String::new();
                    if let Some(s) = content.as_str() {
                        text = s.chars().take(120).collect();
                    } else if let Some(arr) = content.as_array() {
                        for b in arr {
                            if b.get("type").and_then(|v| v.as_str()) == Some("text") {
                                if let Some(t) = b.get("text").and_then(|v| v.as_str()) {
                                    text = t.chars().take(120).collect();
                                    break;
                                }
                            }
                        }
                    }
                    session.turns.push(Turn {
                        index: turn_idx,
                        role: "user".to_string(),
                        text_preview: text,
                        ..Default::default()
                    });
                    turn_idx += 1;
                }
            }
            "assistant" => {
                let turn = current_turn.get_or_insert_with(|| Turn {
                    index: turn_idx,
                    role: "assistant".to_string(),
                    ..Default::default()
                });
                turn.api_calls += 1;
                let msg = event.get("message").unwrap_or(&Value::Null);
                let usage = msg.get("usage");
                let has_usage = usage.map_or(false, |u| u.get("output_tokens").is_some());

                if has_usage {
                    let u = usage.unwrap();
                    turn.input_tokens += u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    turn.output_tokens += u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    turn.cache_read_tokens += u.get("cache_read_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                }

                if let Some(content) = msg.get("content").and_then(|v| v.as_array()) {
                    for block in content {
                        let btype = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        match btype {
                            "thinking" => {
                                if let Some(text) = block.get("thinking").and_then(|v| v.as_str()) {
                                    if !has_usage {
                                        turn.thinking_tokens += text.len() / 4;
                                        turn.output_tokens += text.len() / 4;
                                    }
                                }
                            }
                            "text" => {
                                if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                    if !has_usage {
                                        turn.output_tokens += text.len() / 4;
                                    }
                                    if !text.trim().is_empty() && turn.text_preview.is_empty() {
                                        turn.text_preview = text.chars().take(120).collect();
                                    }
                                }
                            }
                            "tool_use" => {
                                let tc = parse_tool_use(block);
                                if !has_usage {
                                    turn.output_tokens += tc.input_tokens;
                                }
                                turn.tool_calls.push(tc);
                            }
                            _ => {}
                        }
                    }
                }
            }
            "result" => {
                if let Some(ref mut turn) = current_turn {
                    turn.duration_ms += event.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                    turn.duration_api_ms += event.get("duration_api_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                }
            }
            _ => {}
        }
    }

    if let Some(t) = current_turn {
        session.turns.push(t);
    }
    session.compute_totals();
    session
}

pub fn find_session_jsonl() -> Option<PathBuf> {
    // Try Claude Code first, then other agents
    let finders: Vec<Box<dyn Fn() -> Option<PathBuf>>> = vec![
        Box::new(find_claude_session),
        Box::new(find_codex_session),
        Box::new(find_pi_session),
        Box::new(find_copilot_session),
        Box::new(find_aider_session),
    ];
    for finder in finders {
        if let Some(p) = finder() {
            return Some(p);
        }
    }
    None
}

/// Auto-detect format and parse any supported JSONL file
pub fn parse_auto(path: &Path) -> Session {
    let content = std::fs::read_to_string(path).expect("Failed to read file");
    // Peek at first valid JSON line to detect format
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Ok(rec) = serde_json::from_str::<Value>(line) {
            // Claude Code: has "type" field with "user"/"assistant"
            if let Some(t) = rec.get("type").and_then(|v| v.as_str()) {
                if matches!(t, "user" | "assistant" | "queue-operation" | "summary") {
                    return parse_jsonl(path);
                }
                // Pi: has "type": "session" or "type": "message"
                if matches!(t, "session" | "message" | "model_change" | "thinking_level_change") {
                    return parse_pi(path);
                }
            }
            // Codex CLI: has "type": "codex.sse_event" or similar codex prefix
            if rec.get("type").and_then(|v| v.as_str()).map_or(false, |t| t.starts_with("codex.")) {
                return parse_codex(path);
            }
            // Codex CLI alt: has "role" at top level (message format)
            if rec.get("role").is_some() && rec.get("content").is_some() {
                return parse_codex(path);
            }
            // Copilot CLI: has "event_type" field
            if rec.get("event_type").is_some() || rec.get("eventType").is_some() {
                return parse_copilot(path);
            }
            // Aider: has "role" + "content" with possible "token_usage"
            if rec.get("role").is_some() {
                return parse_aider(path);
            }
            // Teleport export
            if rec.get("events").is_some() && rec.get("session").is_some() {
                return parse_teleport(path);
            }
        }
        break;
    }
    // Fallback: try Claude Code
    parse_jsonl(path)
}

// ============================================================
// Codex CLI parser
// Format: JSONL in ~/.codex/sessions/, SSE events with response.completed
// ============================================================

pub fn parse_codex(path: &Path) -> Session {
    let content = std::fs::read_to_string(path).expect("Failed to read Codex session");
    let mut session = Session { model: "codex".to_string(), ..Default::default() };
    let mut turn_idx = 0usize;
    let mut current_turn: Option<Turn> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let rec: Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => continue };

        let role = rec.get("role").and_then(|v| v.as_str()).unwrap_or("");

        if role == "user" {
            if let Some(t) = current_turn.take() {
                session.turns.push(t);
                turn_idx += 1;
            }
            let text = rec.get("content").and_then(|v| v.as_str())
                .or_else(|| rec.get("content").and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|b| b.get("text").and_then(|v| v.as_str())))
                .unwrap_or("").chars().take(120).collect();
            session.turns.push(Turn {
                index: turn_idx, role: "user".to_string(), text_preview: text, ..Default::default()
            });
            turn_idx += 1;
            continue;
        }

        if role == "assistant" {
            let turn = current_turn.get_or_insert_with(|| Turn {
                index: turn_idx, role: "assistant".to_string(), ..Default::default()
            });
            turn.api_calls += 1;

            // Token usage from response metadata
            if let Some(u) = rec.get("usage").or_else(|| rec.get("token_usage")) {
                let inp = u.get("input_tokens").or_else(|| u.get("prompt_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let out = u.get("output_tokens").or_else(|| u.get("completion_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if inp > turn.input_tokens { turn.input_tokens = inp; }
                turn.output_tokens += out;
                turn.cache_read_tokens = u.get("cache_read_input_tokens")
                    .or_else(|| u.get("cached_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            }

            // Content blocks
            if let Some(content) = rec.get("content").and_then(|v| v.as_array()) {
                for block in content {
                    let btype = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match btype {
                        "reasoning" | "thinking" => {
                            if let Some(text) = block.get("text").or_else(|| block.get("thinking")).and_then(|v| v.as_str()) {
                                turn.thinking_tokens += text.len() / 4;
                            }
                        }
                        "text" | "output_text" => {
                            if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                if !text.trim().is_empty() && turn.text_preview.is_empty() {
                                    turn.text_preview = text.chars().take(120).collect();
                                }
                            }
                        }
                        "function_call" | "tool_use" => {
                            let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("tool");
                            let input = block.get("arguments").or_else(|| block.get("input"))
                                .map(|v| serde_json::to_string(v).unwrap_or_default()).unwrap_or_default();
                            turn.tool_calls.push(ToolCall {
                                name: name.to_string(),
                                input_tokens: input.len() / 4,
                                ..Default::default()
                            });
                        }
                        _ => {}
                    }
                }
            } else if let Some(text) = rec.get("content").and_then(|v| v.as_str()) {
                if !text.trim().is_empty() && turn.text_preview.is_empty() {
                    turn.text_preview = text.chars().take(120).collect();
                }
                turn.output_tokens += text.len() / 4;
            }

            // Model
            if session.model == "codex" {
                if let Some(m) = rec.get("model").and_then(|v| v.as_str()) {
                    session.model = m.to_string();
                }
            }
        }

        // SSE event format (codex.sse_event)
        if let Some(t) = rec.get("type").and_then(|v| v.as_str()) {
            if t == "codex.sse_event" || t == "response.completed" {
                if let Some(response) = rec.get("response").or_else(|| rec.get("data")) {
                    if let Some(u) = response.get("usage") {
                        let turn = current_turn.get_or_insert_with(|| Turn {
                            index: turn_idx, role: "assistant".to_string(), ..Default::default()
                        });
                        let inp = u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        let out = u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        if inp > turn.input_tokens { turn.input_tokens = inp; }
                        turn.output_tokens += out;
                    }
                }
            }
        }
    }

    if let Some(t) = current_turn { session.turns.push(t); }
    session.compute_totals();
    session
}

pub fn find_codex_session() -> Option<PathBuf> {
    let dir = dirs_home().join(".codex").join("sessions");
    if !dir.exists() { return None; }
    find_most_recent_jsonl(&dir)
}

// ============================================================
// Aider parser
// Format: JSONL in .aider.history, messages with token_usage
// ============================================================

pub fn parse_aider(path: &Path) -> Session {
    let content = std::fs::read_to_string(path).expect("Failed to read Aider session");
    let mut session = Session { model: "aider".to_string(), ..Default::default() };
    let mut turn_idx = 0usize;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let rec: Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => continue };

        let role = rec.get("role").and_then(|v| v.as_str()).unwrap_or("");

        if role == "user" {
            let text = rec.get("content").and_then(|v| v.as_str())
                .unwrap_or("").chars().take(120).collect();
            session.turns.push(Turn {
                index: turn_idx, role: "user".to_string(), text_preview: text, ..Default::default()
            });
            turn_idx += 1;
        } else if role == "assistant" {
            let mut turn = Turn { index: turn_idx, role: "assistant".to_string(), ..Default::default() };
            turn.api_calls = 1;

            if let Some(u) = rec.get("token_usage").or_else(|| rec.get("usage")) {
                turn.input_tokens = u.get("prompt_tokens").or_else(|| u.get("input_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                turn.output_tokens = u.get("completion_tokens").or_else(|| u.get("output_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                turn.cache_read_tokens = u.get("cache_read_input_tokens")
                    .or_else(|| u.get("cached_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            }

            if let Some(text) = rec.get("content").and_then(|v| v.as_str()) {
                if !text.trim().is_empty() {
                    turn.text_preview = text.chars().take(120).collect();
                }
                if turn.output_tokens == 0 {
                    turn.output_tokens = text.len() / 4;
                }
            }

            if let Some(m) = rec.get("model").and_then(|v| v.as_str()) {
                session.model = m.to_string();
            }

            session.turns.push(turn);
            turn_idx += 1;
        }
    }

    session.compute_totals();
    session
}

pub fn find_aider_session() -> Option<PathBuf> {
    // Check current dir first, then home
    let cwd = std::env::current_dir().ok()?;
    let local = cwd.join(".aider.history");
    if local.exists() { return Some(local); }
    let home = dirs_home().join(".aider.history");
    if home.exists() { return Some(home); }
    None
}

// ============================================================
// Pi parser
// Format: JSONL in ~/.pi/agent/sessions/, tree structure with id/parentId
// ============================================================

pub fn parse_pi(path: &Path) -> Session {
    let content = std::fs::read_to_string(path).expect("Failed to read Pi session");
    let mut session = Session { model: "pi".to_string(), ..Default::default() };
    let mut turn_idx = 0usize;
    let mut current_turn: Option<Turn> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let rec: Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => continue };

        let rec_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match rec_type {
            "session" => {
                if let Some(id) = rec.get("id").and_then(|v| v.as_str()) {
                    session.session_id = id.to_string();
                }
            }
            "model_change" => {
                if let Some(m) = rec.get("model").and_then(|v| v.as_str()) {
                    session.model = m.to_string();
                }
            }
            "message" => {
                let role = rec.get("role").and_then(|v| v.as_str()).unwrap_or("");

                if role == "user" {
                    if let Some(t) = current_turn.take() {
                        session.turns.push(t);
                        turn_idx += 1;
                    }
                    let text = extract_text_from_content(&rec);
                    session.turns.push(Turn {
                        index: turn_idx, role: "user".to_string(), text_preview: text, ..Default::default()
                    });
                    turn_idx += 1;
                } else if role == "assistant" {
                    let turn = current_turn.get_or_insert_with(|| Turn {
                        index: turn_idx, role: "assistant".to_string(), ..Default::default()
                    });
                    turn.api_calls += 1;

                    // Pi usage: {input, output, cacheRead, cacheWrite, totalTokens}
                    if let Some(u) = rec.get("usage").or_else(|| rec.get("Usage")) {
                        let inp = u.get("input").or_else(|| u.get("input_tokens"))
                            .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        let out = u.get("output").or_else(|| u.get("output_tokens"))
                            .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        if inp > turn.input_tokens { turn.input_tokens = inp; }
                        turn.output_tokens += out;
                        turn.cache_read_tokens = u.get("cacheRead").or_else(|| u.get("cache_read"))
                            .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        turn.cache_write_tokens = u.get("cacheWrite").or_else(|| u.get("cache_write"))
                            .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    }

                    // Parse content blocks
                    if let Some(content) = rec.get("content").and_then(|v| v.as_array()) {
                        for block in content {
                            let btype = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                            match btype {
                                "thinking" => {
                                    if let Some(text) = block.get("thinking").or_else(|| block.get("text")).and_then(|v| v.as_str()) {
                                        turn.thinking_tokens += text.len() / 4;
                                    }
                                }
                                "text" => {
                                    if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                        if !text.trim().is_empty() && turn.text_preview.is_empty() {
                                            turn.text_preview = text.chars().take(120).collect();
                                        }
                                    }
                                }
                                "tool_use" => {
                                    let tc = parse_tool_use(block);
                                    turn.tool_calls.push(tc);
                                }
                                _ => {}
                            }
                        }
                    }

                    if let Some(m) = rec.get("model").and_then(|v| v.as_str()) {
                        session.model = m.to_string();
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(t) = current_turn { session.turns.push(t); }
    session.compute_totals();
    session
}

pub fn find_pi_session() -> Option<PathBuf> {
    let dir = dirs_home().join(".pi").join("agent").join("sessions");
    if !dir.exists() { return None; }
    find_most_recent_jsonl(&dir)
}

// ============================================================
// GitHub Copilot CLI parser
// Format: JSONL in ~/.copilot/session-state/, event stream
// No token data — estimate from content
// ============================================================

pub fn parse_copilot(path: &Path) -> Session {
    let content = std::fs::read_to_string(path).expect("Failed to read Copilot session");
    let mut session = Session { model: "copilot".to_string(), ..Default::default() };
    let mut turn_idx = 0usize;
    let mut current_turn: Option<Turn> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let rec: Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => continue };

        let event_type = rec.get("event_type").or_else(|| rec.get("eventType"))
            .and_then(|v| v.as_str()).unwrap_or("");
        let role = rec.get("role").and_then(|v| v.as_str()).unwrap_or("");

        // User message
        if role == "user" || event_type == "user_message" {
            if let Some(t) = current_turn.take() {
                session.turns.push(t);
                turn_idx += 1;
            }
            let text = rec.get("content").and_then(|v| v.as_str())
                .or_else(|| rec.get("message").and_then(|v| v.as_str()))
                .unwrap_or("").chars().take(120).collect();
            session.turns.push(Turn {
                index: turn_idx, role: "user".to_string(), text_preview: text, ..Default::default()
            });
            turn_idx += 1;
            continue;
        }

        // Assistant / tool events
        if role == "assistant" || event_type.contains("assistant") || event_type.contains("response") {
            let turn = current_turn.get_or_insert_with(|| Turn {
                index: turn_idx, role: "assistant".to_string(), ..Default::default()
            });
            turn.api_calls += 1;

            if let Some(text) = rec.get("content").and_then(|v| v.as_str()) {
                turn.output_tokens += text.len() / 4;
                if !text.trim().is_empty() && turn.text_preview.is_empty() {
                    turn.text_preview = text.chars().take(120).collect();
                }
            }

            if let Some(u) = rec.get("usage") {
                let inp = u.get("input_tokens").or_else(|| u.get("prompt_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let out = u.get("output_tokens").or_else(|| u.get("completion_tokens"))
                    .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if inp > turn.input_tokens { turn.input_tokens = inp; }
                turn.output_tokens = out;
            }
        }

        // Tool calls
        if event_type.contains("tool") || event_type == "file_edit" || event_type == "shell_command" {
            let turn = current_turn.get_or_insert_with(|| Turn {
                index: turn_idx, role: "assistant".to_string(), ..Default::default()
            });
            let name = rec.get("tool_name").or_else(|| rec.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or(event_type).to_string();
            let input_str = rec.get("arguments").or_else(|| rec.get("input"))
                .map(|v| serde_json::to_string(v).unwrap_or_default()).unwrap_or_default();
            turn.tool_calls.push(ToolCall {
                name,
                input_tokens: input_str.len() / 4,
                ..Default::default()
            });
        }

        // Timestamp-based duration
        if let Some(dur) = rec.get("duration_ms").and_then(|v| v.as_u64()) {
            if let Some(ref mut turn) = current_turn {
                turn.duration_ms += dur;
            }
        }

        if let Some(m) = rec.get("model").and_then(|v| v.as_str()) {
            session.model = m.to_string();
        }
    }

    if let Some(t) = current_turn { session.turns.push(t); }
    session.compute_totals();
    session
}

pub fn find_copilot_session() -> Option<PathBuf> {
    let dir = dirs_home().join(".copilot").join("session-state");
    if !dir.exists() { return None; }
    find_most_recent_jsonl(&dir)
}

// ============================================================
// Helpers
// ============================================================

fn extract_text_from_content(rec: &Value) -> String {
    if let Some(s) = rec.get("content").and_then(|v| v.as_str()) {
        return s.chars().take(120).collect();
    }
    if let Some(arr) = rec.get("content").and_then(|v| v.as_array()) {
        for b in arr {
            if b.get("type").and_then(|v| v.as_str()) == Some("text") {
                if let Some(t) = b.get("text").and_then(|v| v.as_str()) {
                    return t.chars().take(120).collect();
                }
            }
        }
    }
    String::new()
}

fn find_most_recent_jsonl(dir: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    collect_jsonl(dir, &mut candidates);
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.first().map(|(_, p)| p.clone())
}

fn find_claude_session() -> Option<PathBuf> {
    let claude_dir = dirs_home().join(".claude").join("projects");
    if !claude_dir.exists() { return None; }
    find_most_recent_jsonl(&claude_dir)
}

fn collect_jsonl(dir: &Path, out: &mut Vec<(std::time::SystemTime, PathBuf)>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().map_or(false, |n| n.to_str().map_or(false, |s| s == "subagents")) {
                    continue;
                }
                collect_jsonl(&path, out);
            } else if path.extension().map_or(false, |e| e == "jsonl") {
                if let Ok(meta) = path.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        out.push((mtime, path));
                    }
                }
            }
        }
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

pub fn demo_session() -> Session {
    let mut session = Session {
        session_id: "demo-session".to_string(),
        model: "claude-opus-4-6".to_string(),
        ..Default::default()
    };

    session.turns.push(Turn { index: 0, role: "user".to_string(), text_preview: "Fix the auth bug in login.ts".to_string(), ..Default::default() });
    session.turns.push(Turn {
        index: 1, role: "assistant".to_string(), thinking_tokens: 3200, output_tokens: 4490,
        input_tokens: 12000, cache_read_tokens: 10000,
        tool_calls: vec![
            ToolCall { name: "Grep(auth)".to_string(), input_tokens: 150, output_tokens: 500, ..Default::default() },
            ToolCall { name: "Grep(session)".to_string(), input_tokens: 120, output_tokens: 400, ..Default::default() },
        ],
        api_calls: 1, ..Default::default()
    });
    session.turns.push(Turn { index: 2, role: "user".to_string(), text_preview: "Good, now fix the session handling".to_string(), ..Default::default() });
    session.turns.push(Turn {
        index: 3, role: "assistant".to_string(), thinking_tokens: 2800, output_tokens: 5950,
        input_tokens: 18000, cache_read_tokens: 15000,
        tool_calls: vec![
            ToolCall { name: "Read(login.ts)".to_string(), input_tokens: 200, output_tokens: 800, ..Default::default() },
            ToolCall { name: "Read(middleware.ts)".to_string(), input_tokens: 180, output_tokens: 600, ..Default::default() },
            ToolCall { name: "Read(user.ts)".to_string(), input_tokens: 150, output_tokens: 420, ..Default::default() },
        ],
        api_calls: 1, ..Default::default()
    });
    session.turns.push(Turn { index: 4, role: "user".to_string(), text_preview: "Can you also check the middleware?".to_string(), ..Default::default() });
    session.turns.push(Turn {
        index: 5, role: "assistant".to_string(), thinking_tokens: 5500, output_tokens: 10470,
        input_tokens: 25000, cache_read_tokens: 21000,
        tool_calls: vec![
            ToolCall { name: "Agent(Explore session flow)".to_string(), input_tokens: 1200, output_tokens: 3500, children: vec![
                ToolCall { name: "Grep(middleware)".to_string(), input_tokens: 100, output_tokens: 300, ..Default::default() },
                ToolCall { name: "Read(auth.ts)".to_string(), input_tokens: 200, output_tokens: 600, ..Default::default() },
            ], ..Default::default() },
        ],
        api_calls: 3, ..Default::default()
    });
    session.turns.push(Turn { index: 6, role: "user".to_string(), text_preview: "Apply the fix".to_string(), ..Default::default() });
    session.turns.push(Turn {
        index: 7, role: "assistant".to_string(), thinking_tokens: 4200, output_tokens: 7300,
        input_tokens: 32000, cache_read_tokens: 27000,
        tool_calls: vec![
            ToolCall { name: "Edit(login.ts:42)".to_string(), input_tokens: 300, output_tokens: 200, ..Default::default() },
            ToolCall { name: "Edit(middleware.ts:15)".to_string(), input_tokens: 250, output_tokens: 180, ..Default::default() },
            ToolCall { name: "Bash(npm test)".to_string(), input_tokens: 100, output_tokens: 1200, ..Default::default() },
        ],
        api_calls: 3, ..Default::default()
    });
    session.turns.push(Turn { index: 8, role: "user".to_string(), text_preview: "Looks good, commit it".to_string(), ..Default::default() });
    session.turns.push(Turn {
        index: 9, role: "assistant".to_string(), thinking_tokens: 1900, output_tokens: 4100,
        input_tokens: 38000, cache_read_tokens: 33000,
        tool_calls: vec![
            ToolCall { name: "Bash(git add -A)".to_string(), input_tokens: 50, output_tokens: 80, ..Default::default() },
            ToolCall { name: "Bash(git commit)".to_string(), input_tokens: 200, output_tokens: 300, ..Default::default() },
            ToolCall { name: "Bash(git push)".to_string(), input_tokens: 50, output_tokens: 150, ..Default::default() },
        ],
        api_calls: 3, ..Default::default()
    });
    session.turns.push(Turn { index: 10, role: "user".to_string(), text_preview: "Write a large config file".to_string(), ..Default::default() });
    session.turns.push(Turn {
        index: 11, role: "assistant".to_string(), thinking_tokens: 1500, output_tokens: 5560,
        input_tokens: 42000, cache_read_tokens: 35500,
        tool_calls: vec![
            ToolCall { name: "Write(config.json)".to_string(), input_tokens: 3800, output_tokens: 200, ..Default::default() },
        ],
        api_calls: 1, ..Default::default()
    });

    session.compute_totals();
    session
}
