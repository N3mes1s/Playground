//! # OpenAI Provider
//!
//! Implements the Provider trait for the OpenAI API (and all OpenAI-compatible APIs).
//! This is the base client used by 25+ providers (Groq, Mistral, Together, etc.)

use alloc::string::String;
use super::*;

pub struct OpenAiProvider {
    client: OpenAiCompatibleClient,
}

impl OpenAiProvider {
    pub fn new(config: ProviderConfig) -> Self {
        OpenAiProvider {
            client: OpenAiCompatibleClient::new(
                config,
                "api.openai.com",
                "/v1/chat/completions",
            ),
        }
    }

    pub fn with_base(config: ProviderConfig, host: &str, path: &str) -> Self {
        OpenAiProvider {
            client: OpenAiCompatibleClient::new(config, host, path),
        }
    }
}

impl Provider for OpenAiProvider {
    fn name(&self) -> &str {
        &self.client.config.provider_name
    }

    fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String> {
        self.client.send_completion(messages, tools)
    }

    fn health_check(&self) -> Result<(), String> {
        // Send a minimal request to verify connectivity
        let _test_messages = [Message::new(Role::User, "ping")];

        let config_backup = self.client.config.clone();
        let mut test_config = config_backup;
        test_config.max_tokens = 1;

        // Just check that we can reach the API
        let response = crate::net::http::get(
            &self.client.host,
            "/v1/models",
            Some(&self.client.config.api_key),
        );

        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(alloc::format!("API returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }
}
