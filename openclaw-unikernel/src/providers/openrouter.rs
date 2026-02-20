//! # OpenRouter Provider
//!
//! OpenRouter is an LLM aggregator — routes requests to 200+ models
//! from different providers through a single API.

use alloc::string::String;
use super::*;

pub struct OpenRouterProvider {
    client: OpenAiCompatibleClient,
}

impl OpenRouterProvider {
    pub fn new(config: ProviderConfig) -> Self {
        OpenRouterProvider {
            client: OpenAiCompatibleClient::new(
                config,
                "openrouter.ai",
                "/api/v1/chat/completions",
            ),
        }
    }
}

impl Provider for OpenRouterProvider {
    fn name(&self) -> &str {
        "openrouter"
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
            "openrouter.ai",
            "/api/v1/models",
            Some(&self.client.config.api_key),
        );

        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(alloc::format!("OpenRouter returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }
}
