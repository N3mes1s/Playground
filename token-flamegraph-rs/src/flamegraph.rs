use crate::parser::{Session, ToolCall};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ToolSpan {
    pub name: String,
    pub tokens: usize,
    pub category: String,
    pub children: Vec<ToolSpan>,
    #[serde(rename = "totalTokens")]
    pub total_tokens: usize,
}

impl ToolSpan {
    pub fn compute_total(&mut self) -> usize {
        let child_total: usize = self.children.iter_mut().map(|c| c.compute_total()).sum();
        self.total_tokens = self.tokens + child_total;
        self.total_tokens
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TurnViz {
    pub index: usize,
    pub thinking: usize,
    pub text: usize,
    pub tools: Vec<ToolSpan>,
    #[serde(rename = "toolTokens")]
    pub tool_tokens: usize,
    #[serde(rename = "outputTokens")]
    pub output_tokens: usize,
    #[serde(rename = "inputTokens")]
    pub input_tokens: usize,
    #[serde(rename = "cacheRead")]
    pub cache_read: usize,
    #[serde(rename = "freshInput")]
    pub fresh_input: usize,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "durationApiMs")]
    pub duration_api_ms: u64,
    #[serde(skip_serializing)]
    pub efficiency_score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VizData {
    pub turns: Vec<TurnViz>,
    pub totals: Totals,
    #[serde(rename = "categoryTokens")]
    pub category_tokens: std::collections::HashMap<String, usize>,
    #[serde(rename = "topTools")]
    pub top_tools: Vec<TopTool>,
    pub model: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Totals {
    pub thinking: usize,
    pub text: usize,
    pub tool: usize,
    pub input: usize,
    pub cache: usize,
    pub output: usize,
    #[serde(rename = "toolCalls")]
    pub tool_calls: usize,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "durationApiMs")]
    pub duration_api_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopTool {
    pub name: String,
    pub tokens: usize,
}

fn tool_category(name: &str) -> &'static str {
    if name.starts_with("Read") { "read" }
    else if name.starts_with("Edit") || name.starts_with("Write") { "write" }
    else if name.starts_with("Bash") { "bash" }
    else if name.starts_with("Grep") || name.starts_with("Glob") { "search" }
    else if name.starts_with("Agent") { "agent" }
    else { "other" }
}

fn tool_to_span(tc: &ToolCall) -> ToolSpan {
    let cat = tool_category(&tc.name).to_string();
    let children: Vec<ToolSpan> = tc.children.iter().map(tool_to_span).collect();
    let mut span = ToolSpan {
        name: tc.name.clone(),
        tokens: tc.input_tokens + tc.output_tokens,
        category: cat,
        children,
        total_tokens: 0,
    };
    span.compute_total();
    span
}

fn efficiency_score(turn: &TurnViz) -> f64 {
    let out = turn.output_tokens;
    if out == 0 { return 0.0; }
    let mut score = 100.0f64;
    let num_tools = turn.tools.len();

    if out < 500 { score = score.min(80.0); }

    let write_tokens: usize = turn.tools.iter()
        .filter(|t| t.name.starts_with("Write"))
        .map(|t| t.total_tokens).sum();
    if write_tokens > 0 {
        score -= (write_tokens as f64 / out as f64) * 40.0;
    }

    let think_ratio = turn.thinking as f64 / out as f64;
    if think_ratio > 0.3 {
        score -= (think_ratio - 0.3) * 50.0;
    }

    if out > 5000 && num_tools < 3 { score -= 20.0; }
    if num_tools == 0 && out > 200 { score -= 15.0; }

    if turn.input_tokens > 0 {
        let cache_rate = turn.cache_read as f64 / turn.input_tokens as f64;
        if cache_rate < 0.8 {
            score -= (0.8 - cache_rate) * 30.0;
        }
    }

    let edit_tokens: usize = turn.tools.iter()
        .filter(|t| t.name.starts_with("Edit"))
        .map(|t| t.total_tokens).sum();
    if edit_tokens > 0 && out > 0 {
        score += (edit_tokens as f64 / out as f64 * 20.0).min(10.0);
    }

    if out > 0 && num_tools > 0 {
        let density = num_tools as f64 / (out as f64 / 1000.0);
        score += (density * 2.0).min(10.0);
    }

    score.max(0.0).min(100.0)
}

pub fn session_to_viz(session: &Session) -> VizData {
    let mut turns = Vec::new();
    let mut tool_totals: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut category_totals: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut num_tool_calls = 0usize;

    for turn in &session.turns {
        if turn.role != "assistant" { continue; }

        let tool_spans: Vec<ToolSpan> = turn.tool_calls.iter().map(tool_to_span).collect();
        let tool_tok: usize = tool_spans.iter().map(|s| s.total_tokens).sum();
        let tool_input_est: usize = turn.tool_calls.iter().map(|tc| tc.input_tokens).sum();
        let text_tok = turn.output_tokens.saturating_sub(turn.thinking_tokens).saturating_sub(tool_input_est);

        let mut tv = TurnViz {
            index: turn.index,
            thinking: turn.thinking_tokens,
            text: text_tok,
            tool_tokens: tool_tok,
            output_tokens: turn.thinking_tokens + text_tok + tool_tok,
            input_tokens: turn.input_tokens,
            cache_read: turn.cache_read_tokens,
            fresh_input: turn.input_tokens.saturating_sub(turn.cache_read_tokens),
            duration_ms: turn.duration_ms,
            duration_api_ms: turn.duration_api_ms,
            tools: tool_spans,
            efficiency_score: 0.0,
        };
        tv.efficiency_score = efficiency_score(&tv);
        turns.push(tv);

        for tc in &turn.tool_calls {
            *tool_totals.entry(tc.name.clone()).or_insert(0) += tc.input_tokens + tc.output_tokens;
            *category_totals.entry(tool_category(&tc.name).to_string()).or_insert(0) += tc.input_tokens + tc.output_tokens;
            num_tool_calls += 1;
            num_tool_calls += tc.children.len();
        }
    }

    let mut top: Vec<TopTool> = tool_totals.into_iter()
        .map(|(name, tokens)| TopTool { name, tokens })
        .collect();
    top.sort_by(|a, b| b.tokens.cmp(&a.tokens));
    top.truncate(15);

    let totals = Totals {
        thinking: turns.iter().map(|t| t.thinking).sum(),
        text: turns.iter().map(|t| t.text).sum(),
        tool: turns.iter().map(|t| t.tool_tokens).sum(),
        input: turns.iter().map(|t| t.input_tokens).sum(),
        cache: turns.iter().map(|t| t.cache_read).sum(),
        output: turns.iter().map(|t| t.output_tokens).sum(),
        tool_calls: num_tool_calls,
        duration_ms: turns.iter().map(|t| t.duration_ms).sum(),
        duration_api_ms: turns.iter().map(|t| t.duration_api_ms).sum(),
    };

    VizData { turns, totals, category_tokens: category_totals, top_tools: top, model: session.model.clone() }
}
