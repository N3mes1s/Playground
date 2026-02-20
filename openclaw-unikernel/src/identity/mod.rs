//! # AIEOS v1.1 JSON Identity Format
//!
//! Implements the AI Entity Operating System identity specification.
//! This is the structured identity format used by ZeroClaw for defining
//! an agent's personality, knowledge, worldview, and behavioral rules
//! as a composable JSON document.
//!
//! AIEOS v1.1 fields:
//! - metadata: version, schema, agent name, created/updated timestamps
//! - soul: core purpose and identity
//! - personality: traits, tone, style
//! - worldview: beliefs, values, perspectives
//! - knowledge: domain expertise and facts
//! - voice: communication style, vocabulary, patterns
//! - rules: behavioral constraints and directives
//! - extensions: custom fields for plugins/skills

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use alloc::collections::BTreeMap;

/// AIEOS v1.1 identity document.
#[derive(Debug, Clone)]
pub struct AieosIdentity {
    pub version: String,
    pub schema: String,
    pub agent_name: String,
    pub created: u64,
    pub updated: u64,
    pub soul: SoulSection,
    pub personality: PersonalitySection,
    pub worldview: WorldviewSection,
    pub knowledge: KnowledgeSection,
    pub voice: VoiceSection,
    pub rules: RulesSection,
    pub extensions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct SoulSection {
    pub purpose: String,
    pub identity: String,
    pub core_values: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PersonalitySection {
    pub traits: Vec<String>,
    pub tone: String,
    pub style: String,
    pub humor: String,
}

#[derive(Debug, Clone, Default)]
pub struct WorldviewSection {
    pub beliefs: Vec<String>,
    pub values: Vec<String>,
    pub perspectives: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct KnowledgeSection {
    pub domains: Vec<String>,
    pub facts: Vec<String>,
    pub expertise_level: String,
}

#[derive(Debug, Clone, Default)]
pub struct VoiceSection {
    pub vocabulary: String,
    pub sentence_style: String,
    pub greeting: String,
    pub farewell: String,
    pub filler_words: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RulesSection {
    pub directives: Vec<String>,
    pub constraints: Vec<String>,
    pub never: Vec<String>,
    pub always: Vec<String>,
}

impl Default for AieosIdentity {
    fn default() -> Self {
        AieosIdentity {
            version: String::from("1.1"),
            schema: String::from("aieos"),
            agent_name: String::from("OpenClaw"),
            created: 0,
            updated: 0,
            soul: SoulSection {
                purpose: String::from("Autonomous AI agent running as a bare-metal unikernel"),
                identity: String::from("OpenClaw — zero overhead, zero compromise"),
                core_values: alloc::vec![
                    String::from("helpfulness"),
                    String::from("honesty"),
                    String::from("safety"),
                ],
            },
            personality: PersonalitySection {
                traits: alloc::vec![
                    String::from("precise"),
                    String::from("efficient"),
                    String::from("knowledgeable"),
                ],
                tone: String::from("professional yet approachable"),
                style: String::from("concise and direct"),
                humor: String::from("subtle and dry"),
            },
            worldview: WorldviewSection::default(),
            knowledge: KnowledgeSection {
                domains: alloc::vec![
                    String::from("software engineering"),
                    String::from("systems programming"),
                ],
                facts: Vec::new(),
                expertise_level: String::from("expert"),
            },
            voice: VoiceSection {
                vocabulary: String::from("technical"),
                sentence_style: String::from("short and clear"),
                greeting: String::from("Hello! How can I help?"),
                farewell: String::from("Let me know if you need anything else."),
                filler_words: Vec::new(),
            },
            rules: RulesSection {
                directives: alloc::vec![
                    String::from("Always be helpful and accurate"),
                    String::from("Respect user privacy"),
                ],
                constraints: alloc::vec![
                    String::from("Follow the configured security policy"),
                ],
                never: alloc::vec![
                    String::from("Never reveal API keys or secrets"),
                    String::from("Never bypass security restrictions"),
                ],
                always: alloc::vec![
                    String::from("Always acknowledge uncertainty"),
                ],
            },
            extensions: BTreeMap::new(),
        }
    }
}

impl AieosIdentity {
    /// Create from the current config identity.
    pub fn from_config(config: &crate::config::IdentityConfig) -> Self {
        let mut identity = AieosIdentity::default();
        let now = crate::kernel::rdtsc();

        identity.agent_name = config.agent_name.clone();
        identity.created = now;
        identity.updated = now;

        if !config.soul.is_empty() {
            identity.soul.purpose = config.soul.clone();
        }
        if !config.personality.is_empty() {
            identity.personality.tone = config.personality.clone();
        }
        if !config.worldview.is_empty() {
            identity.worldview.beliefs.push(config.worldview.clone());
        }
        if !config.knowledge.is_empty() {
            identity.knowledge.domains.push(config.knowledge.clone());
        }
        if !config.voice.is_empty() {
            identity.voice.vocabulary = config.voice.clone();
        }
        if !config.rules.is_empty() {
            identity.rules.directives.push(config.rules.clone());
        }

        identity
    }

    /// Serialize to AIEOS v1.1 JSON format.
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n");

        // Metadata
        json.push_str(&format!("  \"version\": \"{}\",\n", self.version));
        json.push_str(&format!("  \"schema\": \"{}\",\n", self.schema));
        json.push_str(&format!("  \"agent_name\": \"{}\",\n", json_escape(&self.agent_name)));
        json.push_str(&format!("  \"created\": {},\n", self.created));
        json.push_str(&format!("  \"updated\": {},\n", self.updated));

        // Soul
        json.push_str("  \"soul\": {\n");
        json.push_str(&format!("    \"purpose\": \"{}\",\n", json_escape(&self.soul.purpose)));
        json.push_str(&format!("    \"identity\": \"{}\",\n", json_escape(&self.soul.identity)));
        json.push_str(&format!("    \"core_values\": [{}]\n", format_string_array(&self.soul.core_values)));
        json.push_str("  },\n");

        // Personality
        json.push_str("  \"personality\": {\n");
        json.push_str(&format!("    \"traits\": [{}],\n", format_string_array(&self.personality.traits)));
        json.push_str(&format!("    \"tone\": \"{}\",\n", json_escape(&self.personality.tone)));
        json.push_str(&format!("    \"style\": \"{}\",\n", json_escape(&self.personality.style)));
        json.push_str(&format!("    \"humor\": \"{}\"\n", json_escape(&self.personality.humor)));
        json.push_str("  },\n");

        // Worldview
        json.push_str("  \"worldview\": {\n");
        json.push_str(&format!("    \"beliefs\": [{}],\n", format_string_array(&self.worldview.beliefs)));
        json.push_str(&format!("    \"values\": [{}],\n", format_string_array(&self.worldview.values)));
        json.push_str(&format!("    \"perspectives\": [{}]\n", format_string_array(&self.worldview.perspectives)));
        json.push_str("  },\n");

        // Knowledge
        json.push_str("  \"knowledge\": {\n");
        json.push_str(&format!("    \"domains\": [{}],\n", format_string_array(&self.knowledge.domains)));
        json.push_str(&format!("    \"facts\": [{}],\n", format_string_array(&self.knowledge.facts)));
        json.push_str(&format!("    \"expertise_level\": \"{}\"\n", json_escape(&self.knowledge.expertise_level)));
        json.push_str("  },\n");

        // Voice
        json.push_str("  \"voice\": {\n");
        json.push_str(&format!("    \"vocabulary\": \"{}\",\n", json_escape(&self.voice.vocabulary)));
        json.push_str(&format!("    \"sentence_style\": \"{}\",\n", json_escape(&self.voice.sentence_style)));
        json.push_str(&format!("    \"greeting\": \"{}\",\n", json_escape(&self.voice.greeting)));
        json.push_str(&format!("    \"farewell\": \"{}\",\n", json_escape(&self.voice.farewell)));
        json.push_str(&format!("    \"filler_words\": [{}]\n", format_string_array(&self.voice.filler_words)));
        json.push_str("  },\n");

        // Rules
        json.push_str("  \"rules\": {\n");
        json.push_str(&format!("    \"directives\": [{}],\n", format_string_array(&self.rules.directives)));
        json.push_str(&format!("    \"constraints\": [{}],\n", format_string_array(&self.rules.constraints)));
        json.push_str(&format!("    \"never\": [{}],\n", format_string_array(&self.rules.never)));
        json.push_str(&format!("    \"always\": [{}]\n", format_string_array(&self.rules.always)));
        json.push_str("  }");

        // Extensions
        if !self.extensions.is_empty() {
            json.push_str(",\n  \"extensions\": {");
            let mut first = true;
            for (key, value) in &self.extensions {
                if !first {
                    json.push(',');
                }
                first = false;
                json.push_str(&format!("\n    \"{}\": \"{}\"", json_escape(key), json_escape(value)));
            }
            json.push_str("\n  }");
        }

        json.push_str("\n}");
        json
    }

    /// Parse from AIEOS v1.1 JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let mut identity = AieosIdentity::default();

        // Parse version
        if let Some(v) = extract_json_str(json, "version") {
            identity.version = v;
        }
        if let Some(s) = extract_json_str(json, "schema") {
            identity.schema = s;
        }
        if let Some(n) = extract_json_str(json, "agent_name") {
            identity.agent_name = n;
        }

        // Parse soul
        if let Some(soul_section) = extract_json_object(json, "soul") {
            if let Some(p) = extract_json_str(&soul_section, "purpose") {
                identity.soul.purpose = p;
            }
            if let Some(i) = extract_json_str(&soul_section, "identity") {
                identity.soul.identity = i;
            }
            identity.soul.core_values = extract_json_string_array(&soul_section, "core_values");
        }

        // Parse personality
        if let Some(pers_section) = extract_json_object(json, "personality") {
            identity.personality.traits = extract_json_string_array(&pers_section, "traits");
            if let Some(t) = extract_json_str(&pers_section, "tone") {
                identity.personality.tone = t;
            }
            if let Some(s) = extract_json_str(&pers_section, "style") {
                identity.personality.style = s;
            }
            if let Some(h) = extract_json_str(&pers_section, "humor") {
                identity.personality.humor = h;
            }
        }

        // Parse worldview
        if let Some(wv_section) = extract_json_object(json, "worldview") {
            identity.worldview.beliefs = extract_json_string_array(&wv_section, "beliefs");
            identity.worldview.values = extract_json_string_array(&wv_section, "values");
            identity.worldview.perspectives = extract_json_string_array(&wv_section, "perspectives");
        }

        // Parse knowledge
        if let Some(kn_section) = extract_json_object(json, "knowledge") {
            identity.knowledge.domains = extract_json_string_array(&kn_section, "domains");
            identity.knowledge.facts = extract_json_string_array(&kn_section, "facts");
            if let Some(el) = extract_json_str(&kn_section, "expertise_level") {
                identity.knowledge.expertise_level = el;
            }
        }

        // Parse voice
        if let Some(v_section) = extract_json_object(json, "voice") {
            if let Some(v) = extract_json_str(&v_section, "vocabulary") {
                identity.voice.vocabulary = v;
            }
            if let Some(s) = extract_json_str(&v_section, "sentence_style") {
                identity.voice.sentence_style = s;
            }
            if let Some(g) = extract_json_str(&v_section, "greeting") {
                identity.voice.greeting = g;
            }
            if let Some(f) = extract_json_str(&v_section, "farewell") {
                identity.voice.farewell = f;
            }
            identity.voice.filler_words = extract_json_string_array(&v_section, "filler_words");
        }

        // Parse rules
        if let Some(r_section) = extract_json_object(json, "rules") {
            identity.rules.directives = extract_json_string_array(&r_section, "directives");
            identity.rules.constraints = extract_json_string_array(&r_section, "constraints");
            identity.rules.never = extract_json_string_array(&r_section, "never");
            identity.rules.always = extract_json_string_array(&r_section, "always");
        }

        Ok(identity)
    }

    /// Convert identity to a system prompt fragment.
    pub fn to_system_prompt(&self) -> String {
        let mut prompt = String::new();

        if !self.soul.purpose.is_empty() {
            prompt.push_str(&self.soul.purpose);
            prompt.push('\n');
        }
        if !self.soul.identity.is_empty() {
            prompt.push_str(&format!("Identity: {}\n", self.soul.identity));
        }

        if !self.personality.tone.is_empty() {
            prompt.push_str(&format!("Tone: {}\n", self.personality.tone));
        }
        if !self.personality.style.is_empty() {
            prompt.push_str(&format!("Style: {}\n", self.personality.style));
        }

        if !self.rules.directives.is_empty() {
            prompt.push_str("\nDirectives:\n");
            for d in &self.rules.directives {
                prompt.push_str(&format!("- {}\n", d));
            }
        }

        if !self.rules.never.is_empty() {
            prompt.push_str("\nNever:\n");
            for n in &self.rules.never {
                prompt.push_str(&format!("- {}\n", n));
            }
        }

        if !self.rules.always.is_empty() {
            prompt.push_str("\nAlways:\n");
            for a in &self.rules.always {
                prompt.push_str(&format!("- {}\n", a));
            }
        }

        prompt
    }

    /// Merge another identity on top of this one (non-empty fields override).
    pub fn merge(&mut self, other: &AieosIdentity) {
        if !other.agent_name.is_empty() {
            self.agent_name = other.agent_name.clone();
        }
        if !other.soul.purpose.is_empty() {
            self.soul.purpose = other.soul.purpose.clone();
        }
        if !other.soul.identity.is_empty() {
            self.soul.identity = other.soul.identity.clone();
        }
        if !other.soul.core_values.is_empty() {
            self.soul.core_values = other.soul.core_values.clone();
        }
        if !other.personality.traits.is_empty() {
            self.personality.traits = other.personality.traits.clone();
        }
        if !other.personality.tone.is_empty() {
            self.personality.tone = other.personality.tone.clone();
        }
        if !other.personality.style.is_empty() {
            self.personality.style = other.personality.style.clone();
        }
        if !other.rules.directives.is_empty() {
            self.rules.directives.extend(other.rules.directives.clone());
        }
        if !other.rules.never.is_empty() {
            self.rules.never.extend(other.rules.never.clone());
        }
        if !other.rules.always.is_empty() {
            self.rules.always.extend(other.rules.always.clone());
        }
        self.updated = crate::kernel::rdtsc();
    }

    /// Save to ramfs as JSON.
    pub fn save(&self) {
        let json = self.to_json();
        crate::config::ramfs_write("/workspace/identity.json", &json);
        crate::kprintln!("[identity] saved AIEOS v{} identity for '{}'", self.version, self.agent_name);
    }

    /// Load from ramfs.
    pub fn load() -> Option<Self> {
        let json = crate::config::ramfs_read("/workspace/identity.json")?;
        Self::from_json(&json).ok()
    }
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

fn format_string_array(items: &[String]) -> String {
    items.iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":", key);
    let start = json.find(&search)? + search.len();
    let rest = json[start..].trim_start();

    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..]; // skip opening quote

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

fn extract_json_object(json: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":", key);
    let start = json.find(&search)? + search.len();
    let rest = json[start..].trim_start();

    if !rest.starts_with('{') {
        return None;
    }

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

fn extract_json_string_array(json: &str, key: &str) -> Vec<String> {
    let search = format!("\"{}\":", key);
    let start = match json.find(&search) {
        Some(s) => s + search.len(),
        None => return Vec::new(),
    };
    let rest = json[start..].trim_start();

    if !rest.starts_with('[') {
        return Vec::new();
    }

    // Find the matching ]
    let mut depth = 0;
    let mut end = 0;
    for ch in rest.chars() {
        end += ch.len_utf8();
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }

    let array_str = &rest[1..end - 1]; // strip [ and ]
    let mut results = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut current_start = None;

    for (i, ch) in array_str.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }
        if ch == '"' {
            if in_string {
                if let Some(start) = current_start {
                    results.push(json_unescape(&array_str[start..i]));
                }
                in_string = false;
                current_start = None;
            } else {
                in_string = true;
                current_start = Some(i + 1);
            }
        }
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
