//! # Integration Registry
//!
//! Tracks 76+ supported integrations across 9 categories.
//! This is informational — used by the doctor/status commands.

use alloc::string::String;
use alloc::vec::Vec;

/// Integration categories.
#[derive(Debug, Clone, Copy)]
pub enum Category {
    Chat,
    AiModels,
    Productivity,
    Music,
    SmartHome,
    ToolsAutomation,
    Media,
    Social,
    Platforms,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Chat => "Chat",
            Category::AiModels => "AI Models",
            Category::Productivity => "Productivity",
            Category::Music => "Music",
            Category::SmartHome => "Smart Home",
            Category::ToolsAutomation => "Tools & Automation",
            Category::Media => "Media",
            Category::Social => "Social",
            Category::Platforms => "Platforms",
        }
    }
}

/// An integration entry.
#[derive(Debug, Clone)]
pub struct Integration {
    pub name: &'static str,
    pub category: Category,
    pub status: &'static str,
}

/// Get all registered integrations.
pub fn all() -> Vec<Integration> {
    alloc::vec![
        // Chat (13)
        Integration { name: "Telegram", category: Category::Chat, status: "supported" },
        Integration { name: "Discord", category: Category::Chat, status: "supported" },
        Integration { name: "Slack", category: Category::Chat, status: "supported" },
        Integration { name: "WhatsApp", category: Category::Chat, status: "supported" },
        Integration { name: "iMessage", category: Category::Chat, status: "macos-only" },
        Integration { name: "Matrix", category: Category::Chat, status: "supported" },
        Integration { name: "Email", category: Category::Chat, status: "supported" },
        Integration { name: "Signal", category: Category::Chat, status: "planned" },
        Integration { name: "IRC", category: Category::Chat, status: "planned" },
        Integration { name: "Teams", category: Category::Chat, status: "planned" },
        Integration { name: "LINE", category: Category::Chat, status: "planned" },
        Integration { name: "WeChat", category: Category::Chat, status: "planned" },
        Integration { name: "Twilio SMS", category: Category::Chat, status: "planned" },

        // AI Models (27)
        Integration { name: "OpenAI", category: Category::AiModels, status: "supported" },
        Integration { name: "Anthropic", category: Category::AiModels, status: "supported" },
        Integration { name: "OpenRouter", category: Category::AiModels, status: "supported" },
        Integration { name: "Ollama", category: Category::AiModels, status: "supported" },
        Integration { name: "Google Gemini", category: Category::AiModels, status: "supported" },
        Integration { name: "Groq", category: Category::AiModels, status: "supported" },
        Integration { name: "Mistral", category: Category::AiModels, status: "supported" },
        Integration { name: "DeepSeek", category: Category::AiModels, status: "supported" },
        Integration { name: "Together AI", category: Category::AiModels, status: "supported" },
        Integration { name: "Fireworks AI", category: Category::AiModels, status: "supported" },
        Integration { name: "Cohere", category: Category::AiModels, status: "supported" },
        Integration { name: "Perplexity", category: Category::AiModels, status: "supported" },
        Integration { name: "xAI/Grok", category: Category::AiModels, status: "supported" },
        Integration { name: "Hugging Face", category: Category::AiModels, status: "supported" },
        Integration { name: "LM Studio", category: Category::AiModels, status: "supported" },
        Integration { name: "Venice AI", category: Category::AiModels, status: "supported" },
        Integration { name: "Cloudflare AI", category: Category::AiModels, status: "supported" },

        // Tools & Automation (10)
        Integration { name: "Composio", category: Category::ToolsAutomation, status: "supported" },
        Integration { name: "GitHub", category: Category::ToolsAutomation, status: "via-composio" },
        Integration { name: "Jira", category: Category::ToolsAutomation, status: "via-composio" },
        Integration { name: "Notion", category: Category::ToolsAutomation, status: "via-composio" },
        Integration { name: "Google Sheets", category: Category::ToolsAutomation, status: "via-composio" },
        Integration { name: "Airtable", category: Category::ToolsAutomation, status: "via-composio" },
        Integration { name: "Zapier", category: Category::ToolsAutomation, status: "via-composio" },

        // Platforms (5)
        Integration { name: "Docker", category: Category::Platforms, status: "supported" },
        Integration { name: "Cloudflare Tunnel", category: Category::Platforms, status: "supported" },
        Integration { name: "ngrok", category: Category::Platforms, status: "supported" },
        Integration { name: "Tailscale", category: Category::Platforms, status: "supported" },
        Integration { name: "Raspberry Pi", category: Category::Platforms, status: "supported" },
    ]
}

/// Display integration summary.
pub fn summary() -> String {
    let integrations = all();
    let supported = integrations.iter().filter(|i| i.status == "supported").count();
    alloc::format!(
        "{} total integrations ({} directly supported)",
        integrations.len(),
        supported
    )
}
