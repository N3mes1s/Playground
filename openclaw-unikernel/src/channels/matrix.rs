//! # Matrix Channel
//!
//! Communicates via the Matrix Client-Server API (CS API).
//! Supports decentralized messaging with homeserver configuration.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct MatrixChannel {
    config: ChannelConfig,
    running: bool,
    homeserver: String,
    room_id: String,
    since_token: Option<String>,
    user_id: Option<String>,
    pending_messages: Vec<ChannelMessage>,
}

impl MatrixChannel {
    pub fn new(config: ChannelConfig) -> Self {
        let homeserver = config.extra.iter()
            .find(|(k, _)| k == "homeserver")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| String::from("matrix.org"));

        let room_id = config.extra.iter()
            .find(|(k, _)| k == "room_id")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        MatrixChannel {
            config,
            running: false,
            homeserver,
            room_id,
            since_token: None,
            user_id: None,
            pending_messages: Vec::new(),
        }
    }

    fn fetch_whoami(&mut self) {
        let path = "/_matrix/client/v3/account/whoami";
        let response = crate::net::http::get(
            &self.homeserver,
            path,
            Some(&self.config.token),
        );
        if let Ok(resp) = response {
            if let Ok(body) = resp.body_str() {
                self.user_id = crate::providers::extract_json_string(body, "user_id");
            }
        }
    }

    fn sync(&mut self) {
        let path = if let Some(ref since) = self.since_token {
            format!(
                "/_matrix/client/v3/sync?since={}&timeout=5000&filter={{\"room\":{{\"timeline\":{{\"limit\":10}}}}}}",
                since
            )
        } else {
            String::from("/_matrix/client/v3/sync?timeout=5000&filter={\"room\":{\"timeline\":{\"limit\":1}}}")
        };

        let response = crate::net::http::get(
            &self.homeserver,
            &path,
            Some(&self.config.token),
        );

        if let Ok(resp) = response {
            if resp.is_success() {
                if let Ok(body) = resp.body_str() {
                    // Extract next_batch token
                    if let Some(token) = crate::providers::extract_json_string(body, "next_batch") {
                        self.since_token = Some(token);
                    }
                    self.parse_sync_events(body);
                }
            }
        }
    }

    fn parse_sync_events(&mut self, json: &str) {
        // Look for m.room.message events
        let mut search_from = 0;
        while let Some(pos) = json[search_from..].find("\"m.room.message\"") {
            let abs_pos = search_from + pos;
            // Find surrounding event context
            let context_start = if abs_pos > 500 { abs_pos - 500 } else { 0 };
            let context_end = core::cmp::min(json.len(), abs_pos + 1000);
            let context = &json[context_start..context_end];

            if let Some(body) = crate::providers::extract_json_string(context, "body") {
                let sender = crate::providers::extract_json_string(context, "sender")
                    .unwrap_or_else(|| String::from("unknown"));

                // Skip own messages
                if let Some(ref my_id) = self.user_id {
                    if sender == *my_id {
                        search_from = abs_pos + 16;
                        continue;
                    }
                }

                let event_id = crate::providers::extract_json_string(context, "event_id")
                    .unwrap_or_else(|| format!("matrix-{}", crate::kernel::rdtsc()));

                self.pending_messages.push(ChannelMessage {
                    id: event_id,
                    channel: String::from("matrix"),
                    sender,
                    content: body,
                    timestamp: crate::kernel::rdtsc(),
                    metadata: MessageMetadata::default(),
                });
            }

            search_from = abs_pos + 16;
        }
    }
}

impl Channel for MatrixChannel {
    fn name(&self) -> &str { "matrix" }

    fn start(&mut self) -> Result<(), String> {
        if self.config.token.is_empty() {
            return Err(String::from("matrix access token not configured"));
        }
        if self.room_id.is_empty() {
            return Err(String::from("matrix room_id not configured"));
        }
        self.fetch_whoami();
        self.running = true;
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        if !self.running {
            return Vec::new();
        }
        self.sync();
        core::mem::take(&mut self.pending_messages)
    }

    fn send_message(&self, room_id: &str, content: &str) -> Result<(), String> {
        let target = if room_id.is_empty() { &self.room_id } else { room_id };
        let txn_id = crate::kernel::rdtsc();
        let path = format!(
            "/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            target, txn_id
        );
        let body = format!(
            "{{\"msgtype\":\"m.text\",\"body\":{}}}",
            crate::providers::json_string_escape(content)
        );

        let req = crate::net::http::Request::new(
            crate::net::http::Method::Put,
            &self.homeserver,
            &path,
        )
        .header("Content-Type", "application/json")
        .bearer_auth(&self.config.token);

        let mut req = req;
        req.body = Some(body.into_bytes());

        crate::net::http::request(&req)
            .map_err(|e| String::from(e))?;

        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        let response = crate::net::http::get(
            &self.homeserver,
            "/_matrix/client/v3/account/whoami",
            Some(&self.config.token),
        );
        match response {
            Ok(r) if r.is_success() => Ok(()),
            Ok(r) => Err(format!("Matrix returned {}", r.status_code)),
            Err(e) => Err(String::from(e)),
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}
