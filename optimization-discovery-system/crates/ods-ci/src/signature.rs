//! Constant-time HMAC-SHA256 verification of GitHub webhook signatures.
//!
//! GitHub sends the signature in the `X-Hub-Signature-256` header as
//! `sha256=<hex>`. The comparison must be constant-time; we use the
//! `hmac`/`sha2` crates which provide exactly that in their `verify_slice`
//! API.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub enum SignatureVerdict {
    Ok,
    Missing,
    Mismatch,
    Malformed,
}

/// Verify the signature header against the raw request body.
pub fn verify(secret: &[u8], body: &[u8], header: Option<&str>) -> SignatureVerdict {
    let Some(h) = header else {
        return SignatureVerdict::Missing;
    };
    let Some(hex_part) = h.strip_prefix("sha256=") else {
        return SignatureVerdict::Malformed;
    };
    let Some(expected) = decode_hex(hex_part) else {
        return SignatureVerdict::Malformed;
    };
    let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return SignatureVerdict::Malformed,
    };
    mac.update(body);
    match mac.verify_slice(&expected) {
        Ok(()) => SignatureVerdict::Ok,
        Err(_) => SignatureVerdict::Mismatch,
    }
}

pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac key");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    format!("sha256={}", encode_hex(&tag))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const C: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(C[(b >> 4) as usize] as char);
        s.push(C[(b & 0xF) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let secret = b"topsecret";
        let body = br#"{"hello":"world"}"#;
        let header = sign(secret, body);
        assert!(matches!(
            verify(secret, body, Some(&header)),
            SignatureVerdict::Ok
        ));
    }

    #[test]
    fn mismatched_body_fails() {
        let secret = b"topsecret";
        let header = sign(secret, b"foo");
        assert!(matches!(
            verify(secret, b"bar", Some(&header)),
            SignatureVerdict::Mismatch
        ));
    }

    #[test]
    fn missing_header_detected() {
        assert!(matches!(
            verify(b"k", b"b", None),
            SignatureVerdict::Missing
        ));
    }

    #[test]
    fn malformed_header_detected() {
        assert!(matches!(
            verify(b"k", b"b", Some("sha1=abc")),
            SignatureVerdict::Malformed
        ));
        assert!(matches!(
            verify(b"k", b"b", Some("sha256=xyz")),
            SignatureVerdict::Malformed
        ));
    }
}
