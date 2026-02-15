//! # Channel System
//!
//! Channels are the messaging interfaces through which the agent communicates.
//! Each channel implements the `Channel` trait for receiving and sending messages.
//!
//! Supported channels:
//! - CLI (serial console in unikernel mode)
//! - Webhook (HTTP gateway)
//! - Telegram Bot API
//! - Discord WebSocket + REST
//! - Slack Web API
//! - Matrix Protocol
//! - WhatsApp Business API
//! - Email (SMTP/IMAP)

mod cli;
mod webhook;
mod telegram;
mod discord;
mod slack;
mod matrix;
mod whatsapp;
mod email;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

// ── Global webhook message queue ────────────────────────────────────────────
// Messages injected by the HTTP gateway for webhook-based channels.

static mut WEBHOOK_QUEUE: Option<Vec<ChannelMessage>> = None;

// ── Webhook response store ──────────────────────────────────────────────
// Stores agent responses so they can be polled via GET /messages.

static mut RESPONSE_QUEUE: Option<Vec<WebhookResponse>> = None;

/// A stored webhook response.
#[derive(Debug, Clone)]
pub struct WebhookResponse {
    pub user_message: String,
    pub agent_response: String,
    pub timestamp: u64,
}

/// Initialize the response store (called alongside webhook queue init).
pub fn init_response_store() {
    unsafe {
        RESPONSE_QUEUE = Some(Vec::new());
    }
}

/// Push an agent response into the store.
pub fn push_response(user_msg: &str, response: &str) {
    unsafe {
        if let Some(ref mut queue) = RESPONSE_QUEUE {
            queue.push(WebhookResponse {
                user_message: String::from(user_msg),
                agent_response: String::from(response),
                timestamp: crate::kernel::rdtsc(),
            });
            // Keep at most 50 responses
            if queue.len() > 50 {
                queue.remove(0);
            }
        }
    }
}

/// Drain all responses (returns and clears the queue).
pub fn drain_responses() -> Vec<WebhookResponse> {
    unsafe {
        if let Some(ref mut queue) = RESPONSE_QUEUE {
            core::mem::take(queue)
        } else {
            Vec::new()
        }
    }
}

/// Peek at all responses without draining.
pub fn peek_responses() -> Vec<WebhookResponse> {
    unsafe {
        if let Some(ref queue) = RESPONSE_QUEUE {
            queue.clone()
        } else {
            Vec::new()
        }
    }
}

/// Initialize the webhook message queue.
pub fn init_webhook_queue() {
    unsafe {
        WEBHOOK_QUEUE = Some(Vec::new());
    }
}

/// Inject a message from the HTTP gateway into the webhook queue.
/// Called by the gateway for POST /webhook and POST /whatsapp endpoints.
pub fn inject_webhook_message(content: &str, source: &str) {
    let msg = ChannelMessage {
        id: format!("{}-{}", source, crate::kernel::rdtsc()),
        channel: String::from(source),
        sender: String::from(source),
        content: String::from(content),
        timestamp: crate::kernel::rdtsc(),
        metadata: MessageMetadata::default(),
    };

    unsafe {
        if let Some(ref mut queue) = WEBHOOK_QUEUE {
            queue.push(msg);
        }
    }
}

/// Drain all pending webhook messages (called by the daemon's polling loop).
pub fn drain_webhook_messages() -> Vec<ChannelMessage> {
    unsafe {
        if let Some(ref mut queue) = WEBHOOK_QUEUE {
            core::mem::take(queue)
        } else {
            Vec::new()
        }
    }
}

/// A message received from or sent to a channel.
#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub id: String,
    pub channel: String,
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
    pub metadata: MessageMetadata,
}

/// Additional message metadata.
#[derive(Debug, Clone, Default)]
pub struct MessageMetadata {
    pub reply_to: Option<String>,
    pub attachments: Vec<Attachment>,
    pub is_dm: bool,
}

/// File attachment.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub name: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// Channel trait — all messaging platforms implement this.
pub trait Channel: Send {
    /// Get the channel name.
    fn name(&self) -> &str;

    /// Start listening for messages. Returns a receiver-like interface.
    /// In the unikernel, this spawns a cooperative task.
    fn start(&mut self) -> Result<(), String>;

    /// Poll for new messages (non-blocking).
    fn poll_messages(&mut self) -> Vec<ChannelMessage>;

    /// Send a message through this channel.
    fn send_message(&self, to: &str, content: &str) -> Result<(), String>;

    /// Check if the channel is healthy.
    fn health_check(&self) -> Result<(), String>;

    /// Stop the channel listener.
    fn stop(&mut self) -> Result<(), String>;
}

/// Channel configuration.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    pub channel_type: String,
    pub enabled: bool,
    pub token: String,
    pub allowed_users: Vec<String>,
    pub extra: Vec<(String, String)>,
}

/// Build the system prompt, including identity files and tool descriptions.
pub fn build_system_prompt(
    tools: &[crate::providers::ToolSpec],
    skills: &[crate::skills::Skill],
    identity: &crate::config::IdentityConfig,
) -> String {
    let mut prompt = String::with_capacity(8192);

    // Identity
    prompt.push_str("# Identity\n\n");
    if !identity.soul.is_empty() {
        prompt.push_str(&identity.soul);
        prompt.push('\n');
    }
    if !identity.personality.is_empty() {
        prompt.push_str("\n## Personality\n");
        prompt.push_str(&identity.personality);
        prompt.push('\n');
    }
    if !identity.worldview.is_empty() {
        prompt.push_str("\n## Worldview\n");
        prompt.push_str(&identity.worldview);
        prompt.push('\n');
    }
    if !identity.voice.is_empty() {
        prompt.push_str("\n## Voice\n");
        prompt.push_str(&identity.voice);
        prompt.push('\n');
    }
    if !identity.rules.is_empty() {
        prompt.push_str("\n## Rules\n");
        prompt.push_str(&identity.rules);
        prompt.push('\n');
    }
    if !identity.knowledge.is_empty() {
        prompt.push_str("\n## Knowledge\n");
        prompt.push_str(&identity.knowledge);
        prompt.push('\n');
    }

    // Tools
    if !tools.is_empty() {
        prompt.push_str("\n# Available Tools\n\n");
        prompt.push_str("You have the following tools available. Use them when appropriate:\n\n");
        for tool in tools {
            prompt.push_str(&format!("## {}\n", tool.name));
            prompt.push_str(&tool.description);
            prompt.push_str("\n\n");
        }
    }

    // Skills
    if !skills.is_empty() {
        prompt.push_str("\n# Skills\n\n");
        for skill in skills {
            prompt.push_str(&format!("## {}\n", skill.name));
            prompt.push_str(&skill.description);
            prompt.push_str("\n\n");
        }
    }

    // Runtime metadata
    prompt.push_str("\n# Runtime\n\n");
    prompt.push_str("- Platform: OpenClaw Unikernel (bare-metal Rust)\n");
    prompt.push_str("- Architecture: x86_64\n");
    prompt.push_str(&format!(
        "- Uptime: {} ticks\n",
        crate::kernel::rdtsc()
    ));

    prompt
}

/// Create a channel from configuration.
pub fn create(config: ChannelConfig) -> Box<dyn Channel> {
    match config.channel_type.as_str() {
        "cli" => Box::new(cli::CliChannel::new(config)),
        "webhook" => Box::new(webhook::WebhookChannel::new(config)),
        "telegram" => Box::new(telegram::TelegramChannel::new(config)),
        "discord" => Box::new(discord::DiscordChannel::new(config)),
        "slack" => Box::new(slack::SlackChannel::new(config)),
        "matrix" => Box::new(matrix::MatrixChannel::new(config)),
        "whatsapp" => Box::new(whatsapp::WhatsAppChannel::new(config)),
        "email" => Box::new(email::EmailChannel::new(config)),
        _ => Box::new(cli::CliChannel::new(config)),
    }
}
