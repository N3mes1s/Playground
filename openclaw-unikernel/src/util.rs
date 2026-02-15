//! # Utility Functions
//!
//! Common helpers used across the unikernel.

use alloc::string::String;

/// Truncate a string to `max_len` characters, appending "..." if truncated.
/// Ensures we don't split in the middle of a multi-byte UTF-8 sequence.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return String::from(s);
    }

    // Find the last valid char boundary at or before max_len - 3
    let mut end = max_len.saturating_sub(3);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    let mut result = String::from(&s[..end]);
    result.push_str("...");
    result
}

/// Simple hash function (FNV-1a) for strings.
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Format bytes as a human-readable string (e.g., "1.5 MiB").
pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        alloc::format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        alloc::format!("{} KiB", bytes / 1024)
    } else if bytes < 1024 * 1024 * 1024 {
        let mib = bytes / 1024 / 1024;
        let frac = (bytes % (1024 * 1024)) / (1024 * 1024 / 10);
        alloc::format!("{}.{} MiB", mib, frac)
    } else {
        let gib = bytes / 1024 / 1024 / 1024;
        alloc::format!("{} GiB", gib)
    }
}

/// Check if a string looks like a JSON object.
pub fn is_json_object(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed.starts_with('{') && trimmed.ends_with('}')
}

/// Simple base64 encoding (for auth headers).
pub fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;

    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        result.push(CHARS[(n & 0x3F) as usize] as char);
        i += 3;
    }

    if i + 1 == data.len() {
        let n = (data[i] as u32) << 16;
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        result.push('=');
        result.push('=');
    } else if i + 2 == data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        result.push('=');
    }

    result
}
