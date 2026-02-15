//! # Embedding Provider
//!
//! Generates vector embeddings from text for semantic search.
//! Supports OpenAI-compatible embedding APIs and a noop fallback
//! for keyword-only operation without an embedding endpoint.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// The embedding vector dimension for text-embedding models.
pub const DEFAULT_DIMENSION: usize = 1536; // OpenAI text-embedding-3-small

/// Embedding provider trait.
pub trait EmbeddingProvider: Send {
    /// Generate an embedding vector for the given text.
    fn embed(&self, text: &str) -> Result<Vec<f32>, String>;

    /// Get the embedding dimension.
    fn dimension(&self) -> usize;

    /// Provider name.
    fn name(&self) -> &str;
}

// ── OpenAI-Compatible Embedding Provider ───────────────────────────────────

pub struct OpenAiEmbeddingProvider {
    api_key: String,
    model: String,
    host: String,
    path: String,
    dimension: usize,
}

impl OpenAiEmbeddingProvider {
    pub fn new(api_key: &str, model: &str) -> Self {
        OpenAiEmbeddingProvider {
            api_key: String::from(api_key),
            model: String::from(if model.is_empty() { "text-embedding-3-small" } else { model }),
            host: String::from("api.openai.com"),
            path: String::from("/v1/embeddings"),
            dimension: DEFAULT_DIMENSION,
        }
    }

    pub fn with_custom_endpoint(api_key: &str, model: &str, host: &str, path: &str) -> Self {
        OpenAiEmbeddingProvider {
            api_key: String::from(api_key),
            model: String::from(model),
            host: String::from(host),
            path: String::from(path),
            dimension: DEFAULT_DIMENSION,
        }
    }
}

impl EmbeddingProvider for OpenAiEmbeddingProvider {
    fn embed(&self, text: &str) -> Result<Vec<f32>, String> {
        let body = format!(
            "{{\"model\":\"{}\",\"input\":{}}}",
            self.model,
            crate::providers::json_string_escape(text)
        );

        let response = crate::net::http::post_json(
            &self.host,
            &self.path,
            &body,
            Some(&self.api_key),
        ).map_err(|e| String::from(e))?;

        if !response.is_success() {
            return Err(format!(
                "embedding API error {}: {}",
                response.status_code,
                response.body_str().unwrap_or("(binary)")
            ));
        }

        parse_embedding_response(&response.body)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    fn name(&self) -> &str {
        "openai-embeddings"
    }
}

/// Parse the embedding response JSON.
fn parse_embedding_response(body: &[u8]) -> Result<Vec<f32>, String> {
    let text = core::str::from_utf8(body)
        .map_err(|_| String::from("invalid UTF-8 in embedding response"))?;

    // Find the "embedding" array
    let emb_start = text.find("\"embedding\"")
        .ok_or_else(|| String::from("no embedding field in response"))?;
    let rest = &text[emb_start..];

    let arr_start = rest.find('[')
        .ok_or_else(|| String::from("no embedding array found"))?;
    let arr_end = rest.find(']')
        .ok_or_else(|| String::from("unterminated embedding array"))?;

    let arr_content = &rest[arr_start + 1..arr_end];
    let mut embedding = Vec::new();

    for num_str in arr_content.split(',') {
        let trimmed = num_str.trim();
        if !trimmed.is_empty() {
            let val = parse_f32_full(trimmed)
                .ok_or_else(|| format!("invalid float in embedding: '{}'", trimmed))?;
            embedding.push(val);
        }
    }

    if embedding.is_empty() {
        return Err(String::from("empty embedding vector"));
    }

    Ok(embedding)
}

/// Parse a float string like "0.0234" or "-1.5e-3".
fn parse_f32_full(s: &str) -> Option<f32> {
    let s = s.trim();
    let negative = s.as_bytes().first() == Some(&b'-');
    let s = if negative || s.as_bytes().first() == Some(&b'+') { &s[1..] } else { s };

    // Check for scientific notation
    let (mantissa_str, exponent) = if let Some(e_pos) = s.find(|c: char| c == 'e' || c == 'E') {
        let exp_str = &s[e_pos + 1..];
        let exp: i32 = parse_i32(exp_str)?;
        (&s[..e_pos], exp)
    } else {
        (s, 0i32)
    };

    // Parse mantissa
    let val = if let Some(dot) = mantissa_str.find('.') {
        let int_part = if dot > 0 { parse_u64(&mantissa_str[..dot])? } else { 0 };
        let frac_str = &mantissa_str[dot + 1..];
        let frac_val = if frac_str.is_empty() { 0u64 } else { parse_u64(frac_str)? };
        let frac_div = pow10f(frac_str.len() as i32);
        int_part as f32 + frac_val as f32 / frac_div
    } else {
        parse_u64(mantissa_str)? as f32
    };

    let result = val * pow10f(exponent);
    Some(if negative { -result } else { result })
}

fn parse_u64(s: &str) -> Option<u64> {
    let mut result: u64 = 0;
    for c in s.chars() {
        if !c.is_ascii_digit() { return None; }
        result = result.checked_mul(10)?;
        result = result.checked_add((c as u64) - (b'0' as u64))?;
    }
    Some(result)
}

/// Compute 10^n as f32 for small exponents (no_std compatible).
fn pow10f(n: i32) -> f32 {
    if n == 0 { return 1.0; }
    let mut result = 1.0f32;
    if n > 0 {
        for _ in 0..n { result *= 10.0; }
    } else {
        for _ in 0..(-n) { result /= 10.0; }
    }
    result
}

fn parse_i32(s: &str) -> Option<i32> {
    let negative = s.as_bytes().first() == Some(&b'-');
    let s = if negative || s.as_bytes().first() == Some(&b'+') { &s[1..] } else { s };
    let val = parse_u64(s)? as i32;
    Some(if negative { -val } else { val })
}

// ── Noop Embedding Provider ────────────────────────────────────────────────

/// A no-op provider that returns empty vectors.
/// Used when no embedding API is configured — falls back to keyword-only search.
pub struct NoopEmbeddingProvider;

impl EmbeddingProvider for NoopEmbeddingProvider {
    fn embed(&self, _text: &str) -> Result<Vec<f32>, String> {
        Ok(Vec::new())
    }

    fn dimension(&self) -> usize {
        0
    }

    fn name(&self) -> &str {
        "noop"
    }
}

// ── Embedding Cache ────────────────────────────────────────────────────────

/// LRU-evicting cache for embeddings to minimize redundant API calls.
pub struct EmbeddingCache {
    entries: Vec<(u64, Vec<f32>)>, // (text_hash, embedding)
    max_entries: usize,
}

impl EmbeddingCache {
    pub fn new(max_entries: usize) -> Self {
        EmbeddingCache {
            entries: Vec::with_capacity(max_entries),
            max_entries,
        }
    }

    pub fn get(&self, text_hash: u64) -> Option<&Vec<f32>> {
        self.entries.iter()
            .find(|(h, _)| *h == text_hash)
            .map(|(_, v)| v)
    }

    pub fn insert(&mut self, text_hash: u64, embedding: Vec<f32>) {
        // Remove existing entry for this hash
        self.entries.retain(|(h, _)| *h != text_hash);

        // Evict oldest if at capacity
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }

        self.entries.push((text_hash, embedding));
    }
}

/// Create an embedding provider from configuration.
pub fn create_provider(api_key: &str, model: &str, custom_url: Option<&str>) -> Box<dyn EmbeddingProvider> {
    if api_key.is_empty() {
        return Box::new(NoopEmbeddingProvider);
    }

    if let Some(url) = custom_url {
        let host = url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or("api.openai.com");
        let path = url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.find('/').map(|i| &s[i..]))
            .unwrap_or("/v1/embeddings");
        Box::new(OpenAiEmbeddingProvider::with_custom_endpoint(api_key, model, host, path))
    } else {
        Box::new(OpenAiEmbeddingProvider::new(api_key, model))
    }
}
