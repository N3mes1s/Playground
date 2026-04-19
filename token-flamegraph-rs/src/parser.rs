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
    let claude_dir = dirs_home().join(".claude").join("projects");
    if !claude_dir.exists() {
        return None;
    }
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    collect_jsonl(&claude_dir, &mut candidates);
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.first().map(|(_, p)| p.clone())
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
