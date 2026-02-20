//! # Google Gemini Provider
//!
//! Supports the Gemini API with function calling (tool use).
//! Authentication via API key in the URL query parameter.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct GeminiProvider {
    config: ProviderConfig,
}

impl GeminiProvider {
    pub fn new(config: ProviderConfig) -> Self {
        GeminiProvider { config }
    }

    fn build_request_json(&self, messages: &[Message], tools: &[ToolSpec]) -> String {
        let mut json = String::from("{");

        // System instruction (Gemini uses a separate field for system messages)
        let system_msgs: Vec<&Message> = messages.iter()
            .filter(|m| m.role == Role::System)
            .collect();
        if !system_msgs.is_empty() {
            json.push_str("\"systemInstruction\":{\"parts\":[{\"text\":");
            let mut combined = String::new();
            for (i, msg) in system_msgs.iter().enumerate() {
                if i > 0 { combined.push('\n'); }
                combined.push_str(&msg.content);
            }
            json.push_str(&json_string_escape(&combined));
            json.push_str("}]},");
        }

        // Contents (non-system messages)
        json.push_str("\"contents\":[");
        let mut first = true;
        for msg in messages {
            if msg.role == Role::System {
                continue;
            }
            if !first { json.push(','); }
            first = false;

            let role = match msg.role {
                Role::User => "user",
                Role::Assistant => "model",
                _ => "user",
            };

            json.push_str(&format!(
                "{{\"role\":\"{}\",\"parts\":[{{\"text\":{}}}]}}",
                role,
                json_string_escape(&msg.content)
            ));
        }
        json.push_str("],");

        // Tools (function declarations for Gemini)
        if !tools.is_empty() {
            json.push_str("\"tools\":[{\"functionDeclarations\":[");
            for (i, tool) in tools.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(
                    "{{\"name\":\"{}\",\"description\":{},\"parameters\":{}}}",
                    tool.name,
                    json_string_escape(&tool.description),
                    tool.parameters_json
                ));
            }
            json.push_str("]}],");
        }

        // Generation config
        json.push_str("\"generationConfig\":{");
        let temp_int = (self.config.temperature * 10.0) as u32;
        json.push_str(&format!(
            "\"temperature\":0.{},\"maxOutputTokens\":{}",
            temp_int, self.config.max_tokens
        ));
        json.push_str("}}");

        json
    }
}

impl Provider for GeminiProvider {
    fn name(&self) -> &str {
        "gemini"
    }

    fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String> {
        let body = self.build_request_json(messages, tools);
        let path = format!(
            "/v1beta/models/{}:generateContent?key={}",
            self.config.model, self.config.api_key
        );

        let response = crate::net::http::post_json(
            "generativelanguage.googleapis.com",
            &path,
            &body,
            None, // API key is in the URL
        )
        .map_err(|e| String::from(e))?;

        if !response.is_success() {
            return Err(format!(
                "Gemini API error {}: {}",
                response.status_code,
                response.body_str().unwrap_or("(binary)")
            ));
        }

        parse_gemini_response(&response.body)
    }

    fn health_check(&self) -> Result<(), String> {
        let path = format!("/v1beta/models?key={}", self.config.api_key);
        let response = crate::net::http::get(
            "generativelanguage.googleapis.com",
            &path,
            None,
        );

        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(format!("Gemini returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }
}

fn parse_gemini_response(body: &[u8]) -> Result<CompletionResponse, String> {
    let text = core::str::from_utf8(body)
        .map_err(|_| String::from("invalid UTF-8"))?;

    // Check for function call responses
    // Gemini returns: { "candidates": [{ "content": { "parts": [{"functionCall": {"name":"...", "args":{...}}}] } }] }
    let mut tool_calls = Vec::new();
    let mut finish_reason = FinishReason::Stop;

    if text.find("\"functionCall\"").is_some() {
        finish_reason = FinishReason::ToolUse;
        // Parse function calls from the response
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find("\"functionCall\"") {
            let abs_pos = search_from + pos;
            let rest = &text[abs_pos..];

            // Find the function call object bounds
            if let Some(obj_start) = rest.find('{') {
                let obj_rest = &rest[obj_start..];
                let mut depth = 0;
                let mut obj_end = 0;
                for (i, ch) in obj_rest.char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                obj_end = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if obj_end > 0 {
                    let fc_json = &obj_rest[..=obj_end];
                    let name = extract_json_string(fc_json, "name")
                        .unwrap_or_default();

                    // Extract args as a JSON string
                    let args = if let Some(args_pos) = fc_json.find("\"args\"") {
                        let args_rest = &fc_json[args_pos + 6..];
                        let args_rest = args_rest.trim_start().strip_prefix(':').unwrap_or(args_rest);
                        let args_rest = args_rest.trim_start();
                        // Find the matching closing brace
                        if args_rest.starts_with('{') {
                            let mut d = 0;
                            let mut end = 0;
                            for (i, c) in args_rest.char_indices() {
                                match c {
                                    '{' => d += 1,
                                    '}' => {
                                        d -= 1;
                                        if d == 0 {
                                            end = i;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            String::from(&args_rest[..=end])
                        } else {
                            String::from("{}")
                        }
                    } else {
                        String::from("{}")
                    };

                    if !name.is_empty() {
                        tool_calls.push(ToolCall {
                            id: format!("gemini-{}", crate::kernel::rdtsc()),
                            name,
                            arguments: args,
                        });
                    }

                    search_from = abs_pos + obj_end;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Extract text content
    let content = if tool_calls.is_empty() {
        extract_json_string(text, "text")
    } else {
        // May also have text alongside function calls
        extract_json_string(text, "text")
    };

    // Extract usage
    let usage = TokenUsage {
        prompt_tokens: extract_json_number(text, "promptTokenCount").unwrap_or(0) as u32,
        completion_tokens: extract_json_number(text, "candidatesTokenCount").unwrap_or(0) as u32,
        total_tokens: extract_json_number(text, "totalTokenCount").unwrap_or(0) as u32,
    };

    Ok(CompletionResponse {
        content,
        tool_calls,
        finish_reason,
        usage,
    })
}
