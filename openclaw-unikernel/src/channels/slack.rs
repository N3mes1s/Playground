//! # Slack Channel
//!
//! Communicates via the Slack Web API using conversations.history polling.
//! Supports bot ID filtering to ignore self-messages.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct SlackChannel {
    config: ChannelConfig,
    running: bool,
    bot_id: Option<String>,
    last_ts: Option<String>,
    pending_messages: Vec<ChannelMessage>,
    default_channel: String,
}

impl SlackChannel {
    pub fn new(config: ChannelConfig) -> Self {
        let default_channel = config.extra.iter()
            .find(|(k, _)| k == "channel")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| String::from("general"));

        SlackChannel {
            config,
            running: false,
            bot_id: None,
            last_ts: None,
            pending_messages: Vec::new(),
            default_channel,
        }
    }

    fn fetch_bot_id(&mut self) {
        let response = crate::net::http::get(
            "slack.com",
            "/api/auth.test",
            Some(&self.config.token),
        );
        if let Ok(resp) = response {
            if let Ok(body) = resp.body_str() {
                self.bot_id = crate::providers::extract_json_string(body, "user_id");
            }
        }
    }

    fn poll_slack_messages(&mut self) {
        let path = if let Some(ref ts) = self.last_ts {
            format!(
                "/api/conversations.history?channel={}&oldest={}&limit=10",
                self.default_channel, ts
            )
        } else {
            format!(
                "/api/conversations.history?channel={}&limit=1",
                self.default_channel
            )
        };

        let response = crate::net::http::get(
            "slack.com",
            &path,
            Some(&self.config.token),
        );

        if let Ok(resp) = response {
            if resp.is_success() {
                if let Ok(body) = resp.body_str() {
                    self.parse_slack_messages(body);
                }
            }
        }
    }

    fn parse_slack_messages(&mut self, json: &str) {
        let mut search_from = 0;
        while let Some(pos) = json[search_from..].find("\"text\"") {
            let abs_pos = search_from + pos;
            let context_start = if abs_pos > 300 { abs_pos - 300 } else { 0 };
            let context_end = core::cmp::min(json.len(), abs_pos + 1000);
            let context = &json[context_start..context_end];

            if let Some(text) = crate::providers::extract_json_string(context, "text") {
                if text.is_empty() {
                    search_from = abs_pos + 6;
                    continue;
                }

                let user = crate::providers::extract_json_string(context, "user");
                let ts = crate::providers::extract_json_string(context, "ts");

                // Skip bot's own messages
                if let (Some(ref bot_id), Some(ref u)) = (&self.bot_id, &user) {
                    if u == bot_id {
                        search_from = abs_pos + 6;
                        continue;
                    }
                }

                if let Some(ref t) = ts {
                    self.last_ts = Some(t.clone());
                }

                // Check allowlist
                let sender = user.unwrap_or_else(|| String::from("unknown"));
                if !self.config.allowed_users.is_empty()
                    && !self.config.allowed_users.contains(&sender)
                {
                    search_from = abs_pos + 6;
                    continue;
                }

                self.pending_messages.push(ChannelMessage {
                    id: ts.unwrap_or_else(|| format!("slack-{}", crate::kernel::rdtsc())),
                    channel: String::from("slack"),
                    sender,
                    content: text,
                    timestamp: crate::kernel::rdtsc(),
                    metadata: MessageMetadata::default(),
                });
            }

            search_from = abs_pos + 6;
        }
    }
}

impl Channel for SlackChannel {
    fn name(&self) -> &str { "slack" }

    fn start(&mut self) -> Result<(), String> {
        if self.config.token.is_empty() {
            return Err(String::from("slack bot token not configured"));
        }
        self.fetch_bot_id();
        self.running = true;
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        if !self.running {
            return Vec::new();
        }
        self.poll_slack_messages();
        core::mem::take(&mut self.pending_messages)
    }

    fn send_message(&self, channel: &str, content: &str) -> Result<(), String> {
        let target = if channel.is_empty() { &self.default_channel } else { channel };
        let body = format!(
            "{{\"channel\":\"{}\",\"text\":{}}}",
            target,
            crate::providers::json_string_escape(content)
        );

        crate::net::http::post_json(
            "slack.com",
            "/api/chat.postMessage",
            &body,
            Some(&self.config.token),
        ).map_err(|e| String::from(e))?;

        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        let response = crate::net::http::get(
            "slack.com",
            "/api/auth.test",
            Some(&self.config.token),
        );
        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(format!("Slack returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}
