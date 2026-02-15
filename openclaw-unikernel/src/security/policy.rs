//! # Security Policy Engine
//!
//! Enforces autonomy levels, command allowlists, path restrictions,
//! injection prevention, and rate limiting.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// Autonomy levels — how much freedom the agent has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomyLevel {
    /// Can observe only; no shell commands, no file writes
    ReadOnly,
    /// Acts within allowlists; only approved commands
    Supervised,
    /// Full access within workspace sandbox
    Full,
}

/// The security policy.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub autonomy: AutonomyLevel,
    pub workspace_only: bool,
    pub workspace_path: String,
    pub allowed_commands: Vec<String>,
    pub forbidden_paths: Vec<String>,
    pub rate_limit_actions_per_hour: u32,
    pub max_cost_per_day_cents: u32,
    /// Sliding window for rate limiting
    action_timestamps: Vec<u64>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_only: true,
            workspace_path: String::from("/workspace"),
            allowed_commands: alloc::vec![
                String::from("git"),
                String::from("npm"),
                String::from("cargo"),
                String::from("ls"),
                String::from("cat"),
                String::from("grep"),
                String::from("find"),
                String::from("echo"),
                String::from("pwd"),
                String::from("wc"),
                String::from("head"),
                String::from("tail"),
            ],
            forbidden_paths: alloc::vec![
                String::from("/etc"),
                String::from("/root"),
                String::from("/proc"),
                String::from("/sys"),
                String::from("/dev"),
                String::from("/.ssh"),
                String::from("/.gnupg"),
                String::from("/.aws"),
                String::from("/.env"),
            ],
            rate_limit_actions_per_hour: 20,
            max_cost_per_day_cents: 500,
            action_timestamps: Vec::new(),
        }
    }
}

impl SecurityPolicy {
    /// Validate a shell command against the policy.
    pub fn validate_command(&self, command: &str) -> Result<(), String> {
        match self.autonomy {
            AutonomyLevel::ReadOnly => {
                return Err(String::from("read-only mode: shell commands are disabled"));
            }
            AutonomyLevel::Full => {
                // Still check for injection patterns
                self.check_injection(command)?;
                return Ok(());
            }
            AutonomyLevel::Supervised => {}
        }

        // Check injection patterns
        self.check_injection(command)?;

        // Parse all command segments (pipes, &&, ||, ;)
        let segments = self.parse_command_segments(command);
        for segment in &segments {
            let cmd_name = self.extract_command_name(segment);
            if !self.allowed_commands.iter().any(|ac| ac == &cmd_name) {
                return Err(format!(
                    "command '{}' not in allowlist. Allowed: {:?}",
                    cmd_name, self.allowed_commands
                ));
            }
        }

        // Check rate limit
        self.check_rate_limit()?;

        Ok(())
    }

    /// Validate a file path against the policy.
    pub fn validate_path(&self, path: &str) -> Result<(), String> {
        // Block null bytes
        if path.contains('\0') {
            return Err(String::from("path contains null byte"));
        }

        // Block path traversal
        if path.contains("..") {
            return Err(String::from("path traversal detected (..)"));
        }

        // Check workspace scope
        if self.workspace_only && !path.starts_with(&*self.workspace_path) {
            // Allow absolute paths within workspace only
            if path.starts_with('/') {
                return Err(format!(
                    "path '{}' is outside workspace '{}'",
                    path, self.workspace_path
                ));
            }
        }

        // Check forbidden paths
        for forbidden in &self.forbidden_paths {
            if path.starts_with(forbidden.as_str()) {
                return Err(format!("path '{}' is forbidden", path));
            }
        }

        Ok(())
    }

    /// Check for command injection patterns.
    fn check_injection(&self, command: &str) -> Result<(), String> {
        // Block backtick substitution
        if command.contains('`') {
            return Err(String::from("backtick command substitution is not allowed"));
        }

        // Block $() substitution
        if command.contains("$(") {
            return Err(String::from("$() command substitution is not allowed"));
        }

        // Block ${} expansion
        if command.contains("${") {
            return Err(String::from("${} variable expansion is not allowed"));
        }

        // Block output redirection (could overwrite sensitive files)
        if self.autonomy != AutonomyLevel::Full {
            if command.contains(">>") || command.contains("> ") {
                return Err(String::from("output redirection is not allowed"));
            }
        }

        Ok(())
    }

    /// Parse a command line into individual command segments.
    fn parse_command_segments<'a>(&self, command: &'a str) -> Vec<&'a str> {
        let mut segments = Vec::new();
        let mut current_start = 0;

        let chars: Vec<char> = command.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                    segments.push(command[current_start..i].trim());
                    i += 2;
                    current_start = i;
                }
                '|' => {
                    segments.push(command[current_start..i].trim());
                    i += 1;
                    current_start = i;
                }
                '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                    segments.push(command[current_start..i].trim());
                    i += 2;
                    current_start = i;
                }
                ';' => {
                    segments.push(command[current_start..i].trim());
                    i += 1;
                    current_start = i;
                }
                '\n' => {
                    segments.push(command[current_start..i].trim());
                    i += 1;
                    current_start = i;
                }
                _ => {
                    i += 1;
                }
            }
        }

        if current_start < command.len() {
            segments.push(command[current_start..].trim());
        }

        segments.retain(|s| !s.is_empty());
        segments
    }

    /// Extract the base command name from a command string.
    fn extract_command_name<'a>(&self, segment: &'a str) -> &'a str {
        // Strip environment variable prefixes (e.g., "FOO=bar command")
        let mut s = segment;
        while let Some(eq_pos) = s.find('=') {
            let before_eq = &s[..eq_pos];
            if before_eq.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                // Skip past the value
                let after_eq = &s[eq_pos + 1..];
                let next_space = after_eq.find(' ').unwrap_or(after_eq.len());
                if next_space < after_eq.len() {
                    s = after_eq[next_space..].trim_start();
                    continue;
                }
            }
            break;
        }

        // Get the first word
        s.split_whitespace().next().unwrap_or("")
    }

    fn check_rate_limit(&self) -> Result<(), String> {
        // One hour in TSC ticks (~2 GHz): 3600s * 2_000_000_000
        const ONE_HOUR_TICKS: u64 = 7_200_000_000_000;

        let now = crate::kernel::rdtsc();

        // Count actions within the sliding window (last hour)
        let recent_count = self.action_timestamps.iter()
            .filter(|&&ts| now.saturating_sub(ts) < ONE_HOUR_TICKS)
            .count();

        if recent_count >= self.rate_limit_actions_per_hour as usize {
            return Err(format!(
                "rate limit exceeded: {} actions in the last hour (limit: {})",
                recent_count, self.rate_limit_actions_per_hour
            ));
        }

        Ok(())
    }

    /// Record an action for rate limiting purposes.
    pub fn record_action(&mut self) {
        const ONE_HOUR_TICKS: u64 = 7_200_000_000_000;
        let now = crate::kernel::rdtsc();
        self.action_timestamps.push(now);

        // Prune old entries outside the window to prevent unbounded growth
        self.action_timestamps.retain(|&ts| now.saturating_sub(ts) < ONE_HOUR_TICKS);
    }
}
