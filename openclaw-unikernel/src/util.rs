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

// ── no_std compatibility helpers ─────────────────────────────────────────────

/// Convert a string to ASCII lowercase (no_std replacement for `.to_ascii_lowercase()`).
pub fn ascii_lowercase(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b >= b'A' && b <= b'Z' {
            result.push((b + 32) as char);
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Check if a byte slice starts with a prefix, case-insensitive.
pub fn starts_with_ci(s: &str, prefix: &str) -> bool {
    if s.len() < prefix.len() { return false; }
    let sb = s.as_bytes();
    let pb = prefix.as_bytes();
    for i in 0..pb.len() {
        let a = if sb[i] >= b'A' && sb[i] <= b'Z' { sb[i] + 32 } else { sb[i] };
        let b = if pb[i] >= b'A' && pb[i] <= b'Z' { pb[i] + 32 } else { pb[i] };
        if a != b { return false; }
    }
    true
}

/// Parse a usize from a decimal string (no_std replacement for `.parse::<usize>()`).
pub fn parse_usize(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let mut result: usize = 0;
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' { return None; }
        result = result.checked_mul(10)?;
        result = result.checked_add((b - b'0') as usize)?;
    }
    Some(result)
}

/// Parse a u64 from a decimal string.
pub fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let mut result: u64 = 0;
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' { return None; }
        result = result.checked_mul(10)?;
        result = result.checked_add((b - b'0') as u64)?;
    }
    Some(result)
}

/// Approximate natural logarithm for f32 (no_std compatible).
/// Uses the identity ln(x) = (x-1) - (x-1)^2/2 + ... for values near 1,
/// plus range reduction.
pub fn ln_f32(x: f32) -> f32 {
    if x <= 0.0 { return -1e10; } // Sentinel for invalid input
    // Decompose x = m * 2^e where 1 <= m < 2
    let bits = x.to_bits();
    let exponent = ((bits >> 23) & 0xFF) as i32 - 127;
    let mantissa_bits = (bits & 0x007FFFFF) | 0x3F800000;
    let m = f32::from_bits(mantissa_bits);
    // ln(x) = ln(m) + e * ln(2)
    // For m in [1, 2), use Padé approximation: ln(m) ≈ 2*(m-1)/(m+1) * (1 + (m-1)^2/(3*(m+1)^2))
    let t = (m - 1.0) / (m + 1.0);
    let t2 = t * t;
    let ln_m = 2.0 * t * (1.0 + t2 / 3.0 + t2 * t2 / 5.0);
    ln_m + (exponent as f32) * 0.6931472 // ln(2) ≈ 0.6931472
}

/// Approximate square root for f32 (no_std compatible).
/// Uses the "fast inverse square root" + Newton iterations.
pub fn sqrt_f32(x: f32) -> f32 {
    if x <= 0.0 { return 0.0; }
    // Initial estimate using bit manipulation
    let mut bits = x.to_bits();
    bits = 0x1FBD1DF5 + (bits >> 1);
    let mut y = f32::from_bits(bits);
    // Three Newton-Raphson iterations for accuracy
    y = 0.5 * (y + x / y);
    y = 0.5 * (y + x / y);
    y = 0.5 * (y + x / y);
    y
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
