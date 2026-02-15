//! # Anthropic Provider
//!
//! Implements the Provider trait for the Anthropic Messages API.
//! Anthropic uses a different API format from OpenAI.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct AnthropicProvider {
    config: ProviderConfig,
}

impl AnthropicProvider {
    pub fn new(config: ProviderConfig) -> Self {
        AnthropicProvider { config }
    }

    fn build_request_json(&self, messages: &[Message], tools: &[ToolSpec]) -> String {
        let mut json = String::from("{");

        // Model
        json.push_str(&format!("\"model\":\"{}\",", self.config.model));

        // Max tokens
        json.push_str(&format!("\"max_tokens\":{},", self.config.max_tokens));

        // System message (Anthropic puts it at top level)
        let system_msg = messages.iter().find(|m| m.role == Role::System);
        if let Some(sys) = system_msg {
            json.push_str(&format!(
                "\"system\":{},",
                json_string_escape(&sys.content)
            ));
        }

        // Messages (excluding system)
        json.push_str("\"messages\":[");
        let mut first = true;
        for msg in messages {
            if msg.role == Role::System {
                continue;
            }
            if !first { json.push(','); }
            first = false;
            json.push_str(&format!(
                "{{\"role\":\"{}\",\"content\":{}}}",
                msg.role.as_str(),
                json_string_escape(&msg.content)
            ));
        }
        json.push(']');

        // Tools
        if !tools.is_empty() {
            json.push_str(",\"tools\":[");
            for (i, tool) in tools.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(
                    "{{\"name\":\"{}\",\"description\":{},\"input_schema\":{}}}",
                    tool.name,
                    json_string_escape(&tool.description),
                    tool.parameters_json
                ));
            }
            json.push(']');
        }

        json.push('}');
        json
    }
}

impl Provider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String> {
        let body = self.build_request_json(messages, tools);

        let req = crate::net::http::Request::new(
            crate::net::http::Method::Post,
            "api.anthropic.com",
            "/v1/messages",
        )
        .header("x-api-key", &self.config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");

        // Add body manually since we need custom headers
        let mut req = req;
        req.body = Some(body.as_bytes().to_vec());

        let response = crate::net::http::request(&req)
            .map_err(|e| String::from(e))?;

        if !response.is_success() {
            return Err(format!(
                "Anthropic API error {}: {}",
                response.status_code,
                response.body_str().unwrap_or("(binary)")
            ));
        }

        parse_anthropic_response(&response.body)
    }

    fn health_check(&self) -> Result<(), String> {
        let response = crate::net::http::get(
            "api.anthropic.com",
            "/v1/messages",
            None,
        );

        match response {
            Ok(_) => Ok(()), // Any response means the API is reachable
            Err(e) => Err(String::from(e)),
        }
    }
}

/// Parse Anthropic's response format (different from OpenAI).
fn parse_anthropic_response(body: &[u8]) -> Result<CompletionResponse, String> {
    let text = core::str::from_utf8(body)
        .map_err(|_| String::from("invalid UTF-8"))?;

    // Anthropic returns content as an array of blocks
    // Extract the text content from the first text block
    let content = extract_anthropic_text(text);

    let finish_reason = match extract_json_string(text, "stop_reason").as_deref() {
        Some("end_turn") => FinishReason::Stop,
        Some("tool_use") => FinishReason::ToolUse,
        Some("max_tokens") => FinishReason::Length,
        _ => FinishReason::Unknown,
    };

    let usage = TokenUsage {
        prompt_tokens: extract_json_number(text, "input_tokens").unwrap_or(0) as u32,
        completion_tokens: extract_json_number(text, "output_tokens").unwrap_or(0) as u32,
        total_tokens: 0, // Anthropic doesn't provide total
    };

    // Extract tool_use blocks
    let tool_calls = extract_anthropic_tool_use(text);

    Ok(CompletionResponse {
        content,
        tool_calls,
        finish_reason,
        usage,
    })
}

fn extract_anthropic_text(json: &str) -> Option<String> {
    // Find "type":"text" block and extract its "text" field
    if let Some(pos) = json.find("\"type\":\"text\"") {
        let rest = &json[pos..];
        return extract_json_string(rest, "text");
    }
    None
}

fn extract_anthropic_tool_use(json: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    let mut search_from = 0;

    while let Some(pos) = json[search_from..].find("\"type\":\"tool_use\"") {
        let abs_pos = search_from + pos;
        // Find the enclosing object
        // Look backwards for '{'
        if let Some(obj_start) = json[..abs_pos].rfind('{') {
            // Find matching '}'
            let mut depth = 1;
            let mut end = abs_pos + 20;
            for (i, c) in json[obj_start + 1..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = obj_start + 1 + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }

            let obj = &json[obj_start..=end];
            if let Some(id) = extract_json_string(obj, "id") {
                if let Some(name) = extract_json_string(obj, "name") {
                    // Extract input as raw JSON
                    let input = extract_json_object(obj, "input")
                        .unwrap_or_default();
                    calls.push(ToolCall {
                        id,
                        name,
                        arguments: input,
                    });
                }
            }
        }
        search_from = abs_pos + 20;
    }

    calls
}

fn extract_json_object(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let rest = &json[start + pattern.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();

    if !rest.starts_with('{') {
        return None;
    }

    let mut depth = 0;
    for (i, c) in rest.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(String::from(&rest[..=i]));
                }
            }
            _ => {}
        }
    }
    None
}
