//! # Configuration System
//!
//! TOML-like configuration loading and a RAM filesystem for the unikernel.
//! Since there's no disk, all "files" live in memory.
//!
//! The configuration can be embedded at build time or loaded via
//! the serial console / network at boot.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use crate::kernel::sync::SpinLock;

/// Identity configuration (SOUL.md, PERSONALITY.md, etc.)
#[derive(Debug, Clone, Default)]
pub struct IdentityConfig {
    pub soul: String,
    pub personality: String,
    pub worldview: String,
    pub knowledge: String,
    pub voice: String,
    pub rules: String,
    pub agent_name: String,
    pub user_name: String,
}

/// Full agent configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub gateway_port: u16,
    pub gateway_host: String,
    pub autonomy_level: String,
    pub memory_backend: String,
    pub channels: Vec<String>,
    pub identity: IdentityConfig,
    pub env_vars: BTreeMap<String, String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            provider: String::from("openai"),
            model: String::from("gpt-4o"),
            api_key: String::new(),
            temperature: 0.7,
            max_tokens: 4096,
            gateway_port: 3000,
            gateway_host: String::from("0.0.0.0"),
            autonomy_level: String::from("supervised"),
            memory_backend: String::from("in-kernel"),
            channels: alloc::vec![String::from("cli")],
            identity: IdentityConfig {
                agent_name: String::from("OpenClaw"),
                user_name: String::from("User"),
                soul: String::from("You are OpenClaw, an AI assistant running as a bare-metal unikernel."),
                ..Default::default()
            },
            env_vars: BTreeMap::new(),
        }
    }
}

// ── Global State ───────────────────────────────────────────────────────────

static mut CONFIG: Option<SpinLock<AgentConfig>> = None;
static mut RAMFS: Option<SpinLock<BTreeMap<String, String>>> = None;

/// Initialize the configuration system.
pub fn init() {
    let config = AgentConfig::default();
    unsafe {
        CONFIG = Some(SpinLock::new(config));
        RAMFS = Some(SpinLock::new(BTreeMap::new()));
    }

    // Populate default ramfs files
    ramfs_write("/workspace/SOUL.md",
        "# Soul\n\nYou are OpenClaw, an autonomous AI agent running as a bare-metal \
         Rust unikernel. You have no operating system — you ARE the operating system. \
         Your network stack, memory system, and security engine are all part of you.");
    ramfs_write("/workspace/config.toml",
        "[agent]\nprovider = \"openai\"\nmodel = \"gpt-4o\"\n\
         api_key = \"OPENAI_API_KEY\"\n\n\
         [autonomy]\nlevel = \"supervised\"\n\n\
         [memory]\nbackend = \"in-kernel\"\n");

    // Apply the config.toml so the API key is actually loaded
    let toml_content = ramfs_read("/workspace/config.toml").unwrap_or_default();
    let parsed = parse_toml(&toml_content);
    update(|c| {
        c.api_key = parsed.api_key;
        c.provider = parsed.provider;
        c.model = parsed.model;
    });
}

/// Get a copy of the current configuration.
pub fn get() -> AgentConfig {
    unsafe {
        CONFIG
            .as_ref()
            .map(|c| c.lock().clone())
            .unwrap_or_default()
    }
}

/// Update the configuration.
pub fn update(f: impl FnOnce(&mut AgentConfig)) {
    unsafe {
        if let Some(ref config) = CONFIG {
            let mut c = config.lock();
            f(&mut c);
        }
    }
}

/// Get an environment variable.
pub fn get_env(name: &str) -> Option<String> {
    unsafe {
        CONFIG
            .as_ref()
            .and_then(|c| c.lock().env_vars.get(name).cloned())
    }
}

/// Set an environment variable.
pub fn set_env(name: &str, value: &str) {
    update(|c| {
        c.env_vars.insert(String::from(name), String::from(value));
    });
}

// ── RAM Filesystem ─────────────────────────────────────────────────────────

/// Read a file from the RAM filesystem.
pub fn ramfs_read(path: &str) -> Option<String> {
    unsafe {
        RAMFS
            .as_ref()
            .and_then(|fs| fs.lock().get(path).cloned())
    }
}

/// Write a file to the RAM filesystem.
pub fn ramfs_write(path: &str, content: &str) {
    unsafe {
        if let Some(ref fs) = RAMFS {
            fs.lock().insert(String::from(path), String::from(content));
        }
    }
}

/// List files in a directory of the RAM filesystem.
pub fn ramfs_list(dir: &str) -> String {
    unsafe {
        if let Some(ref fs) = RAMFS {
            let fs = fs.lock();
            let mut entries: Vec<&String> = fs.keys()
                .filter(|k| {
                    if dir == "/" {
                        true
                    } else {
                        k.starts_with(dir)
                    }
                })
                .collect();
            entries.sort();
            entries.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")
        } else {
            String::from("(ramfs not initialized)")
        }
    }
}

/// Delete a file from the RAM filesystem.
pub fn ramfs_delete(path: &str) -> bool {
    unsafe {
        if let Some(ref fs) = RAMFS {
            return fs.lock().remove(path).is_some();
        }
    }
    false
}

// ── TOML Parser (Minimal) ─────────────────────────────────────────────────

/// Parse a minimal TOML config into the AgentConfig.
pub fn parse_toml(toml_str: &str) -> AgentConfig {
    let mut config = AgentConfig::default();

    let mut current_section = String::new();

    for line in toml_str.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Section header
        if line.starts_with('[') && line.ends_with(']') {
            current_section = String::from(&line[1..line.len() - 1]);
            continue;
        }

        // Key-value pair
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();
            let value = value.trim_matches('"');

            match (current_section.as_str(), key) {
                ("agent" | "", "provider") => config.provider = String::from(value),
                ("agent" | "", "model") => config.model = String::from(value),
                ("agent" | "", "api_key") => config.api_key = String::from(value),
                ("agent" | "", "temperature") => {
                    config.temperature = parse_f32(value).unwrap_or(0.7);
                }
                ("agent" | "", "max_tokens") => {
                    config.max_tokens = parse_u32(value).unwrap_or(4096);
                }
                ("gateway", "port") => {
                    config.gateway_port = parse_u32(value).unwrap_or(3000) as u16;
                }
                ("gateway", "host") => config.gateway_host = String::from(value),
                ("autonomy", "level") => config.autonomy_level = String::from(value),
                ("memory", "backend") => config.memory_backend = String::from(value),
                ("identity", "agent_name") => config.identity.agent_name = String::from(value),
                ("identity", "user_name") => config.identity.user_name = String::from(value),
                _ => {}
            }
        }
    }

    config
}

fn parse_f32(s: &str) -> Option<f32> {
    // Minimal f32 parser for "0.7" style values
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 2 {
        let int_part = parse_u32(parts[0])? as f32;
        let frac_str = parts[1];
        let frac_part = parse_u32(frac_str)? as f32;
        let mut divisor = 1.0f32;
        for _ in 0..frac_str.len() { divisor *= 10.0; }
        Some(int_part + frac_part / divisor)
    } else {
        parse_u32(s).map(|v| v as f32)
    }
}

fn parse_u32(s: &str) -> Option<u32> {
    let mut result: u32 = 0;
    for c in s.chars() {
        if !c.is_ascii_digit() { return None; }
        result = result.checked_mul(10)?;
        result = result.checked_add((c as u32) - ('0' as u32))?;
    }
    Some(result)
}
