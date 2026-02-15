//! # Skills System
//!
//! Skills are modular capabilities loaded from the ramfs.
//! Each skill has a name, description, and optional trigger patterns.
//! Skills are injected into the system prompt.

use alloc::string::String;
use alloc::vec::Vec;

/// A loaded skill.
#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub trigger: Option<String>,
    pub prompt_injection: String,
}

/// Load all skills from the ramfs skills/ directory.
pub fn load_all() -> Vec<Skill> {
    let mut skills = Vec::new();

    // Check for skills in ramfs
    let listing = crate::config::ramfs_list("/workspace/skills");
    for path in listing.lines() {
        if path.ends_with(".md") || path.ends_with(".toml") {
            if let Some(content) = crate::config::ramfs_read(path) {
                if let Some(skill) = parse_skill(path, &content) {
                    skills.push(skill);
                }
            }
        }
    }

    if !skills.is_empty() {
        crate::kprintln!("[skills] loaded {} skills", skills.len());
    }

    skills
}

/// Parse a skill from its file content.
fn parse_skill(path: &str, content: &str) -> Option<Skill> {
    let name = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .trim_end_matches(".md")
        .trim_end_matches(".toml");

    if path.ends_with(".toml") {
        parse_toml_skill(name, content)
    } else {
        parse_md_skill(name, content)
    }
}

fn parse_toml_skill(name: &str, content: &str) -> Option<Skill> {
    let description = extract_toml_value(content, "description")
        .unwrap_or_else(|| String::from("(no description)"));
    let trigger = extract_toml_value(content, "trigger");
    let prompt = extract_toml_value(content, "prompt")
        .unwrap_or_else(|| content.to_string());

    Some(Skill {
        name: String::from(name),
        description,
        trigger,
        prompt_injection: prompt,
    })
}

fn parse_md_skill(name: &str, content: &str) -> Option<Skill> {
    // First line as description (if it starts with #)
    let description = content.lines()
        .next()
        .map(|line| line.trim_start_matches('#').trim())
        .unwrap_or("(no description)");

    Some(Skill {
        name: String::from(name),
        description: String::from(description),
        trigger: None,
        prompt_injection: String::from(content),
    })
}

fn extract_toml_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let value = rest.trim().trim_matches('"');
                return Some(String::from(value));
            }
        }
    }
    None
}

/// Install a skill from a URL (git clone into ramfs).
pub fn install_from_url(url: &str) -> Result<String, String> {
    // In the unikernel, we'd fetch the skill file via HTTP
    let host = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
        .ok_or_else(|| String::from("invalid URL"))?;

    let path = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|s| s.find('/').map(|i| &s[i..]))
        .unwrap_or("/");

    let response = crate::net::http::get(host, path, None)
        .map_err(|e| String::from(e))?;

    if response.is_success() {
        let content = response.body_str()
            .map_err(|e| String::from(e))?;
        let name = path.rsplit('/').next().unwrap_or("skill");
        let ramfs_path = alloc::format!("/workspace/skills/{}", name);
        crate::config::ramfs_write(&ramfs_path, content);
        Ok(alloc::format!("installed skill '{}' to {}", name, ramfs_path))
    } else {
        Err(alloc::format!("HTTP {}", response.status_code))
    }
}
