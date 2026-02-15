//! # Discord Channel
//!
//! Communicates via the Discord REST API with polling.
//! Supports guild filtering and bot self-message filtering.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct DiscordChannel {
    config: ChannelConfig,
    running: bool,
    bot_id: Option<String>,
    last_message_id: Option<String>,
    pending_messages: Vec<ChannelMessage>,
    channel_id: String,
}

impl DiscordChannel {
    pub fn new(config: ChannelConfig) -> Self {
        let channel_id = config.extra.iter()
            .find(|(k, _)| k == "channel_id")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        DiscordChannel {
            config,
            running: false,
            bot_id: None,
            last_message_id: None,
            pending_messages: Vec::new(),
            channel_id,
        }
    }

    fn fetch_bot_id(&mut self) {
        let response = crate::net::http::get(
            "discord.com",
            "/api/v10/users/@me",
            Some(&self.config.token),
        );

        if let Ok(resp) = response {
            if let Ok(body) = resp.body_str() {
                self.bot_id = crate::providers::extract_json_string(body, "id");
            }
        }
    }

    fn poll_messages_from_discord(&mut self) {
        let path = if let Some(ref after) = self.last_message_id {
            format!(
                "/api/v10/channels/{}/messages?after={}&limit=10",
                self.channel_id, after
            )
        } else {
            format!(
                "/api/v10/channels/{}/messages?limit=1",
                self.channel_id
            )
        };

        let response = crate::net::http::get(
            "discord.com",
            &path,
            Some(&self.config.token),
        );

        if let Ok(resp) = response {
            if resp.is_success() {
                if let Ok(body) = resp.body_str() {
                    self.parse_discord_messages(body);
                }
            }
        }
    }

    fn parse_discord_messages(&mut self, json: &str) {
        // Parse message objects from the JSON array
        let mut search_from = 0;
        while let Some(pos) = json[search_from..].find("\"content\"") {
            let abs_pos = search_from + pos;
            // Find the enclosing object
            let context_start = if abs_pos > 500 { abs_pos - 500 } else { 0 };
            let context = &json[context_start..core::cmp::min(json.len(), abs_pos + 2000)];

            if let Some(content) = crate::providers::extract_json_string(context, "content") {
                if content.is_empty() {
                    search_from = abs_pos + 10;
                    continue;
                }

                let author_id = crate::providers::extract_json_string(context, "id");
                let msg_id = crate::providers::extract_json_string(context, "id");

                // Skip bot's own messages
                if let (Some(ref bot_id), Some(ref author)) = (&self.bot_id, &author_id) {
                    if author == bot_id {
                        search_from = abs_pos + 10;
                        continue;
                    }
                }

                if let Some(ref mid) = msg_id {
                    self.last_message_id = Some(mid.clone());
                }

                self.pending_messages.push(ChannelMessage {
                    id: msg_id.unwrap_or_else(|| format!("dc-{}", crate::kernel::rdtsc())),
                    channel: String::from("discord"),
                    sender: author_id.unwrap_or_else(|| String::from("unknown")),
                    content,
                    timestamp: crate::kernel::rdtsc(),
                    metadata: MessageMetadata::default(),
                });
            }

            search_from = abs_pos + 10;
        }
    }
}

impl Channel for DiscordChannel {
    fn name(&self) -> &str {
        "discord"
    }

    fn start(&mut self) -> Result<(), String> {
        if self.config.token.is_empty() {
            return Err(String::from("discord bot token not configured"));
        }
        self.fetch_bot_id();
        self.running = true;
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        if !self.running {
            return Vec::new();
        }
        self.poll_messages_from_discord();
        core::mem::take(&mut self.pending_messages)
    }

    fn send_message(&self, channel_id: &str, content: &str) -> Result<(), String> {
        let body = format!(
            "{{\"content\":{}}}",
            crate::providers::json_string_escape(content)
        );

        let path = format!("/api/v10/channels/{}/messages", channel_id);

        crate::net::http::post_json(
            "discord.com",
            &path,
            &body,
            Some(&self.config.token),
        )
        .map_err(|e| String::from(e))?;

        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        let response = crate::net::http::get(
            "discord.com",
            "/api/v10/users/@me",
            Some(&self.config.token),
        );
        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(format!("Discord returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}
