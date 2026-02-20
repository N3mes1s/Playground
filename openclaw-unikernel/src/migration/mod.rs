//! # Migration System
//!
//! Import/export agent state between OpenClaw instances.
//! Supports full state transfer including:
//! - Memory entries (all categories)
//! - Configuration (config.toml)
//! - Identity files (SOUL.md, etc.)
//! - Skills
//! - Secrets (encrypted)
//!
//! Export format is a JSON bundle that can be transferred via
//! the gateway API, serial console, or HTTP fetch.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use crate::memory::{self, Memory, MemoryCategory};

/// What to include in a migration export.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub include_memories: bool,
    pub include_config: bool,
    pub include_identity: bool,
    pub include_skills: bool,
    pub include_secrets: bool,
    pub categories: Option<Vec<MemoryCategory>>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions {
            include_memories: true,
            include_config: true,
            include_identity: true,
            include_skills: true,
            include_secrets: false, // secrets excluded by default for safety
            categories: None,      // all categories
        }
    }
}

/// Migration export result.
#[derive(Debug)]
pub struct ExportBundle {
    pub json: String,
    pub entry_count: usize,
    pub file_count: usize,
}

/// Migration import result.
#[derive(Debug)]
pub struct ImportResult {
    pub memories_imported: usize,
    pub files_imported: usize,
    pub config_updated: bool,
    pub warnings: Vec<String>,
}

/// Export agent state as a JSON bundle.
pub fn export(options: &ExportOptions) -> ExportBundle {
    let mut json = String::from("{\"version\":\"1.0\",\"format\":\"openclaw-migration\"");

    let mut entry_count = 0;
    let mut file_count = 0;

    // Export memories
    if options.include_memories {
        let mem = memory::global().lock();
        let entries = match &options.categories {
            Some(cats) => {
                let mut all = Vec::new();
                for cat in cats {
                    all.extend(mem.list(Some(*cat)));
                }
                all
            }
            None => mem.list(None),
        };

        json.push_str(",\"memories\":[");
        for (i, entry) in entries.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                "{{\"key\":\"{}\",\"content\":\"{}\",\"category\":\"{}\",\"timestamp\":{}}}",
                json_escape(&entry.key),
                json_escape(&entry.content),
                entry.category.as_str(),
                entry.timestamp
            ));
            entry_count += 1;
        }
        json.push(']');
    }

    // Export config
    if options.include_config {
        if let Some(content) = crate::config::ramfs_read("/workspace/config.toml") {
            json.push_str(&format!(
                ",\"config\":\"{}\"",
                json_escape(&content)
            ));
            file_count += 1;
        }
    }

    // Export identity files
    if options.include_identity {
        json.push_str(",\"identity\":{");
        let identity_files = [
            "SOUL.md", "PERSONALITY.md", "WORLDVIEW.md",
            "KNOWLEDGE.md", "VOICE.md", "RULES.md",
        ];
        let mut first = true;
        for name in &identity_files {
            let path = format!("/workspace/{}", name);
            if let Some(content) = crate::config::ramfs_read(&path) {
                if !first {
                    json.push(',');
                }
                first = false;
                json.push_str(&format!(
                    "\"{}\":\"{}\"",
                    name,
                    json_escape(&content)
                ));
                file_count += 1;
            }
        }
        json.push('}');
    }

    // Export skills
    if options.include_skills {
        let listing = crate::config::ramfs_list("/workspace/skills");
        json.push_str(",\"skills\":[");
        let mut first = true;
        for path in listing.lines() {
            if path.ends_with(".md") || path.ends_with(".toml") {
                if let Some(content) = crate::config::ramfs_read(path) {
                    if !first {
                        json.push(',');
                    }
                    first = false;
                    json.push_str(&format!(
                        "{{\"path\":\"{}\",\"content\":\"{}\"}}",
                        json_escape(path),
                        json_escape(&content)
                    ));
                    file_count += 1;
                }
            }
        }
        json.push(']');
    }

    // Export encrypted secrets reference (not the actual secrets)
    if options.include_secrets {
        json.push_str(",\"secrets_included\":true");
        // Secrets are exported as encrypted blobs
        let cfg = crate::config::get();
        let env_keys: Vec<&String> = cfg.env_vars.keys().collect();
        json.push_str(",\"secret_keys\":[");
        for (i, key) in env_keys.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!("\"{}\"", json_escape(key)));
        }
        json.push(']');
    }

    json.push('}');

    crate::kprintln!(
        "[migration] exported {} memories, {} files",
        entry_count, file_count
    );

    ExportBundle {
        json,
        entry_count,
        file_count,
    }
}

/// Import agent state from a JSON bundle.
pub fn import(json: &str) -> Result<ImportResult, String> {
    // Validate format
    let version = extract_json_str(json, "version")
        .ok_or_else(|| String::from("missing version field"))?;
    if version != "1.0" {
        return Err(format!("unsupported migration version: {}", version));
    }

    let format_field = extract_json_str(json, "format")
        .ok_or_else(|| String::from("missing format field"))?;
    if format_field != "openclaw-migration" {
        return Err(format!("unsupported format: {}", format_field));
    }

    let mut result = ImportResult {
        memories_imported: 0,
        files_imported: 0,
        config_updated: false,
        warnings: Vec::new(),
    };

    // Import memories
    if let Some(memories_section) = extract_json_array(json, "memories") {
        let mem = memory::global();
        let mut mem = mem.lock();

        for entry_json in split_json_array(&memories_section) {
            let key = extract_json_str(&entry_json, "key").unwrap_or_default();
            let content = extract_json_str(&entry_json, "content").unwrap_or_default();
            let category_str = extract_json_str(&entry_json, "category").unwrap_or_default();
            let category = MemoryCategory::from_str(&category_str);

            if !key.is_empty() && !content.is_empty() {
                match mem.store(&key, &content, category) {
                    Ok(()) => result.memories_imported += 1,
                    Err(e) => result.warnings.push(format!("memory '{}': {}", key, e)),
                }
            }
        }
    }

    // Import config
    if let Some(config_content) = extract_json_str(json, "config") {
        crate::config::ramfs_write("/workspace/config.toml", &config_content);
        result.config_updated = true;
        result.files_imported += 1;
    }

    // Import identity files
    if let Some(identity_section) = extract_json_object(json, "identity") {
        let identity_files = [
            "SOUL.md", "PERSONALITY.md", "WORLDVIEW.md",
            "KNOWLEDGE.md", "VOICE.md", "RULES.md",
        ];
        for name in &identity_files {
            if let Some(content) = extract_json_str(&identity_section, name) {
                let path = format!("/workspace/{}", name);
                crate::config::ramfs_write(&path, &content);
                result.files_imported += 1;
            }
        }
    }

    // Import skills
    if let Some(skills_section) = extract_json_array(json, "skills") {
        for skill_json in split_json_array(&skills_section) {
            let path = extract_json_str(&skill_json, "path").unwrap_or_default();
            let content = extract_json_str(&skill_json, "content").unwrap_or_default();
            if !path.is_empty() && !content.is_empty() {
                crate::config::ramfs_write(&path, &content);
                result.files_imported += 1;
            }
        }
    }

    crate::kprintln!(
        "[migration] imported {} memories, {} files, config_updated={}",
        result.memories_imported, result.files_imported, result.config_updated
    );

    if !result.warnings.is_empty() {
        crate::kprintln!("[migration] {} warnings", result.warnings.len());
    }

    Ok(result)
}

/// Export from a remote OpenClaw instance via HTTP.
pub fn import_from_url(url: &str, auth_token: Option<&str>) -> Result<ImportResult, String> {
    let host = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
        .ok_or_else(|| String::from("invalid URL"))?;

    let path = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|s| s.find('/').map(|i| &s[i..]))
        .unwrap_or("/export");

    let response = crate::net::http::get(host, path, auth_token)
        .map_err(|e| String::from(e))?;

    if !response.is_success() {
        return Err(format!("HTTP {}", response.status_code));
    }

    let body = response.body_str()
        .map_err(|e| String::from(e))?;

    import(body)
}

// ── JSON Helpers ─────────────────────────────────────────────────────────────

fn json_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c => result.push(c),
        }
    }
    result
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":\"", key);
    let start = json.find(&search)? + search.len();
    let rest = &json[start..];

    let mut end = 0;
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            escaped = false;
            end += ch.len_utf8();
            continue;
        }
        if ch == '\\' {
            escaped = true;
            end += 1;
            continue;
        }
        if ch == '"' {
            break;
        }
        end += ch.len_utf8();
    }

    Some(json_unescape(&rest[..end]))
}

fn extract_json_array(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":[", key);
    let start = json.find(&search)? + search.len() - 1; // include the '['
    let rest = &json[start..];

    // Find matching ']'
    let mut depth = 0;
    let mut end = 0;
    for ch in rest.chars() {
        end += ch.len_utf8();
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(String::from(&rest[..end]));
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_json_object(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":{{", key);
    let start = json.find(&search)? + search.len() - 1; // include the '{'
    let rest = &json[start..];

    let mut depth = 0;
    let mut end = 0;
    for ch in rest.chars() {
        end += ch.len_utf8();
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(String::from(&rest[..end]));
                }
            }
            _ => {}
        }
    }
    None
}

/// Split a JSON array "[{...},{...}]" into individual object strings.
fn split_json_array(arr: &str) -> Vec<String> {
    let inner = arr.trim().trim_start_matches('[').trim_end_matches(']');
    let mut results = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let mut in_string = false;
    let mut escaped = false;

    for (i, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match ch {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                let item = inner[start..i].trim();
                if !item.is_empty() {
                    results.push(String::from(item));
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    let last = inner[start..].trim();
    if !last.is_empty() {
        results.push(String::from(last));
    }

    results
}

fn json_unescape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}
