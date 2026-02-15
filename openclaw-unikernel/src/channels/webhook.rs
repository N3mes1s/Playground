//! # Webhook Channel
//!
//! Receives messages via the HTTP gateway. This is used for
//! programmatic interaction and WhatsApp webhook delivery.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct WebhookChannel {
    config: ChannelConfig,
    running: bool,
    pending_messages: Vec<ChannelMessage>,
}

impl WebhookChannel {
    pub fn new(config: ChannelConfig) -> Self {
        WebhookChannel {
            config,
            running: false,
            pending_messages: Vec::new(),
        }
    }

    /// Called by the gateway when a webhook message arrives.
    pub fn inject_message(&mut self, sender: &str, content: &str) {
        self.pending_messages.push(ChannelMessage {
            id: format!("webhook-{}", crate::kernel::rdtsc()),
            channel: String::from("webhook"),
            sender: String::from(sender),
            content: String::from(content),
            timestamp: crate::kernel::rdtsc(),
            metadata: MessageMetadata::default(),
        });
    }
}

impl Channel for WebhookChannel {
    fn name(&self) -> &str {
        "webhook"
    }

    fn start(&mut self) -> Result<(), String> {
        self.running = true;
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        core::mem::take(&mut self.pending_messages)
    }

    fn send_message(&self, _to: &str, content: &str) -> Result<(), String> {
        // Webhook responses are sent back in the HTTP response
        // Store for the gateway to pick up
        let _ = content;
        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        if self.running {
            Ok(())
        } else {
            Err(String::from("webhook channel not running"))
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}
