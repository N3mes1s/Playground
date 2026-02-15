//! # WhatsApp Channel
//!
//! Communicates via the WhatsApp Business Cloud API.
//! Webhook-based message reception with HMAC-SHA256 signature verification.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct WhatsAppChannel {
    config: ChannelConfig,
    running: bool,
    phone_number_id: String,
    verify_token: String,
    app_secret: String,
    pending_messages: Vec<ChannelMessage>,
}

impl WhatsAppChannel {
    pub fn new(config: ChannelConfig) -> Self {
        let phone_number_id = config.extra.iter()
            .find(|(k, _)| k == "phone_number_id")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let verify_token = config.extra.iter()
            .find(|(k, _)| k == "verify_token")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| String::from("openclaw_verify"));

        let app_secret = config.extra.iter()
            .find(|(k, _)| k == "app_secret")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        WhatsAppChannel {
            config,
            running: false,
            phone_number_id,
            verify_token,
            app_secret,
            pending_messages: Vec::new(),
        }
    }

    /// Verify webhook signature (HMAC-SHA256).
    pub fn verify_signature(&self, payload: &[u8], signature: &str) -> bool {
        if self.app_secret.is_empty() {
            return true; // Skip verification if no secret configured
        }

        let expected_sig = hmac_sha256(self.app_secret.as_bytes(), payload);
        let expected_hex = hex_encode(&expected_sig);
        let expected = format!("sha256={}", expected_hex);

        // Constant-time comparison
        if signature.len() != expected.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in signature.bytes().zip(expected.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Process an incoming webhook payload from Meta.
    pub fn process_webhook(&mut self, json: &str) {
        // Extract messages from the webhook payload
        // Format: { "entry": [{ "changes": [{ "value": { "messages": [...] } }] }] }
        let mut search_from = 0;
        while let Some(pos) = json[search_from..].find("\"messages\"") {
            let abs_pos = search_from + pos;
            let rest = &json[abs_pos..];

            // Find message bodies within the messages array
            let mut msg_search = 0;
            while let Some(body_pos) = rest[msg_search..].find("\"body\"") {
                let body_abs = msg_search + body_pos;
                let context_start = if body_abs > 200 { body_abs - 200 } else { 0 };
                let context_end = core::cmp::min(rest.len(), body_abs + 500);
                let context = &rest[context_start..context_end];

                if let Some(body) = crate::providers::extract_json_string(context, "body") {
                    let from = crate::providers::extract_json_string(context, "from")
                        .unwrap_or_else(|| String::from("unknown"));
                    let wa_msg_id = crate::providers::extract_json_string(context, "id")
                        .unwrap_or_else(|| format!("wa-{}", crate::kernel::rdtsc()));

                    // Check allowlist
                    if !self.config.allowed_users.is_empty()
                        && !self.config.allowed_users.contains(&from)
                    {
                        msg_search = body_abs + 6;
                        continue;
                    }

                    self.pending_messages.push(ChannelMessage {
                        id: wa_msg_id,
                        channel: String::from("whatsapp"),
                        sender: from,
                        content: body,
                        timestamp: crate::kernel::rdtsc(),
                        metadata: MessageMetadata::default(),
                    });
                }

                msg_search = body_abs + 6;
            }

            search_from = abs_pos + 10;
        }
    }

    /// Handle Meta webhook verification challenge.
    pub fn handle_verification(&self, mode: &str, token: &str, challenge: &str) -> Option<String> {
        if mode == "subscribe" && token == self.verify_token {
            Some(String::from(challenge))
        } else {
            None
        }
    }
}

impl Channel for WhatsAppChannel {
    fn name(&self) -> &str { "whatsapp" }

    fn start(&mut self) -> Result<(), String> {
        if self.config.token.is_empty() {
            return Err(String::from("whatsapp access token not configured"));
        }
        if self.phone_number_id.is_empty() {
            return Err(String::from("whatsapp phone_number_id not configured"));
        }
        self.running = true;
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        // WhatsApp is webhook-based — messages are injected via process_webhook()
        // which is called from the gateway when a POST /whatsapp arrives.
        core::mem::take(&mut self.pending_messages)
    }

    fn send_message(&self, to: &str, content: &str) -> Result<(), String> {
        let path = format!(
            "/v17.0/{}/messages",
            self.phone_number_id
        );
        let body = format!(
            "{{\"messaging_product\":\"whatsapp\",\"to\":\"{}\",\"type\":\"text\",\"text\":{{\"body\":{}}}}}",
            to,
            crate::providers::json_string_escape(content)
        );

        crate::net::http::post_json(
            "graph.facebook.com",
            &path,
            &body,
            Some(&self.config.token),
        ).map_err(|e| String::from(e))?;

        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        if self.running && !self.phone_number_id.is_empty() {
            Ok(())
        } else {
            Err(String::from("whatsapp channel not configured"))
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}

// Use the shared HMAC-SHA256 and hex_encode from the security module
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    crate::security::pairing::hmac_sha256(key, data)
}

fn hex_encode(data: &[u8]) -> String {
    crate::security::pairing::hex_encode(data)
}
