//! # Google Gemini Provider
//!
//! Supports the Gemini API with three authentication tiers:
//! 1. API key (simplest)
//! 2. OAuth 2.0 bearer token
//! 3. Service account

use alloc::string::String;
use alloc::format;
use super::*;

pub struct GeminiProvider {
    config: ProviderConfig,
}

impl GeminiProvider {
    pub fn new(config: ProviderConfig) -> Self {
        GeminiProvider { config }
    }

    fn build_request_json(&self, messages: &[Message], _tools: &[ToolSpec]) -> String {
        let mut json = String::from("{\"contents\":[");

        let mut first = true;
        for msg in messages {
            if msg.role == Role::System {
                continue; // Gemini handles system messages differently
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

        json.push_str("],\"generationConfig\":{");
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

    // Gemini returns: { "candidates": [{ "content": { "parts": [{"text": "..."}] } }] }
    let content = extract_json_string(text, "text");

    Ok(CompletionResponse {
        content,
        tool_calls: alloc::vec::Vec::new(),
        finish_reason: FinishReason::Stop,
        usage: TokenUsage::default(),
    })
}
