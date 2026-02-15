//! # Telegram Channel
//!
//! Communicates via the Telegram Bot API using long-polling.
//! Supports text messages, user allowlisting, and Markdown formatting.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct TelegramChannel {
    config: ChannelConfig,
    running: bool,
    last_update_id: i64,
    pending_messages: Vec<ChannelMessage>,
}

impl TelegramChannel {
    pub fn new(config: ChannelConfig) -> Self {
        TelegramChannel {
            config,
            running: false,
            last_update_id: 0,
            pending_messages: Vec::new(),
        }
    }

    /// Poll for updates from Telegram using getUpdates.
    fn poll_updates(&mut self) {
        let path = format!(
            "/bot{}/getUpdates?offset={}&timeout=5&limit=10",
            self.config.token,
            self.last_update_id + 1
        );

        let response = crate::net::http::get(
            "api.telegram.org",
            &path,
            None,
        );

        if let Ok(resp) = response {
            if resp.is_success() {
                if let Ok(body) = resp.body_str() {
                    self.parse_updates(body);
                }
            }
        }
    }

    fn parse_updates(&mut self, json: &str) {
        // Find each "update_id" in the response
        let mut search_from = 0;
        while let Some(pos) = json[search_from..].find("\"update_id\"") {
            let abs_pos = search_from + pos;
            let rest = &json[abs_pos..];

            // Extract update_id
            if let Some(uid) = crate::providers::extract_json_number(rest, "update_id") {
                self.last_update_id = uid as i64;
            }

            // Extract message text
            if let Some(text) = crate::providers::extract_json_string(rest, "text") {
                // Extract sender info
                let sender = crate::providers::extract_json_number(rest, "id")
                    .map(|id| format!("{}", id))
                    .unwrap_or_else(|| String::from("unknown"));

                // Check allowlist
                if self.config.allowed_users.is_empty()
                    || self.config.allowed_users.contains(&sender)
                {
                    let chat_id = crate::providers::extract_json_number(rest, "chat")
                        .map(|id| format!("{}", id));

                    self.pending_messages.push(ChannelMessage {
                        id: format!("tg-{}", self.last_update_id),
                        channel: String::from("telegram"),
                        sender: chat_id.unwrap_or(sender),
                        content: text,
                        timestamp: crate::kernel::rdtsc(),
                        metadata: MessageMetadata::default(),
                    });
                }
            }

            search_from = abs_pos + 20;
        }
    }
}

impl Channel for TelegramChannel {
    fn name(&self) -> &str {
        "telegram"
    }

    fn start(&mut self) -> Result<(), String> {
        if self.config.token.is_empty() {
            return Err(String::from("telegram bot token not configured"));
        }
        self.running = true;
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        if !self.running {
            return Vec::new();
        }
        self.poll_updates();
        core::mem::take(&mut self.pending_messages)
    }

    fn send_message(&self, chat_id: &str, content: &str) -> Result<(), String> {
        let body = format!(
            "{{\"chat_id\":{},\"text\":{},\"parse_mode\":\"Markdown\"}}",
            chat_id,
            crate::providers::json_string_escape(content)
        );

        let path = format!("/bot{}/sendMessage", self.config.token);

        crate::net::http::post_json(
            "api.telegram.org",
            &path,
            &body,
            None,
        )
        .map_err(|e| String::from(e))?;

        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        let path = format!("/bot{}/getMe", self.config.token);
        let response = crate::net::http::get("api.telegram.org", &path, None);
        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(format!("Telegram returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}
