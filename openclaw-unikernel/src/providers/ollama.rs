//! # Ollama Provider
//!
//! Connects to a local Ollama instance for running LLMs on-device.
//! Uses the OpenAI-compatible API that Ollama exposes.

use alloc::string::String;
use super::*;

pub struct OllamaProvider {
    client: OpenAiCompatibleClient,
}

impl OllamaProvider {
    pub fn new(mut config: ProviderConfig) -> Self {
        // Ollama doesn't need an API key
        if config.api_key.is_empty() {
            config.api_key = String::from("ollama");
        }

        let host = config
            .api_base_url
            .clone()
            .unwrap_or_else(|| String::from("localhost:11434"));

        OllamaProvider {
            client: OpenAiCompatibleClient::new(
                config,
                &host,
                "/api/chat",
            ),
        }
    }
}

impl Provider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String> {
        self.client.send_completion(messages, tools)
    }

    fn health_check(&self) -> Result<(), String> {
        let response = crate::net::http::get(
            &self.client.host,
            "/api/tags",
            None,
        );

        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(alloc::format!("Ollama returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }
}
