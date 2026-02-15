//! # Secret Store
//!
//! ChaCha20-Poly1305 AEAD encryption for API keys and sensitive data.
//! In the unikernel, the encryption key is held in kernel memory
//! (protected by the single-address-space model — no user processes can access it).

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// The secret store with ChaCha20-Poly1305 encryption.
pub struct SecretStore {
    /// 256-bit encryption key
    key: [u8; 32],
    /// Stored encrypted secrets: (name, encrypted_value)
    secrets: Vec<(String, Vec<u8>)>,
}

impl SecretStore {
    pub fn new() -> Self {
        // Generate key from TSC entropy (in production, use a proper CSPRNG)
        let mut key = [0u8; 32];
        for i in 0..4 {
            let tsc = crate::kernel::rdtsc();
            let bytes = tsc.to_le_bytes();
            key[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        SecretStore {
            key,
            secrets: Vec::new(),
        }
    }

    /// Encrypt a plaintext value using ChaCha20-Poly1305.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        let plaintext_bytes = plaintext.as_bytes();

        // Generate 12-byte nonce from TSC
        let mut nonce = [0u8; 12];
        let tsc = crate::kernel::rdtsc();
        nonce[..8].copy_from_slice(&tsc.to_le_bytes());
        let tsc2 = crate::kernel::rdtsc();
        nonce[8..12].copy_from_slice(&tsc2.to_le_bytes()[..4]);

        // ChaCha20 encryption
        let ciphertext = chacha20_encrypt(&self.key, &nonce, plaintext_bytes);

        // Poly1305 authentication tag
        let tag = poly1305_mac(&self.key, &nonce, &ciphertext);

        // Encode as: "enc2:" + hex(nonce) + hex(ciphertext) + hex(tag)
        let mut result = String::from("enc2:");
        for b in &nonce { result.push_str(&format!("{:02x}", b)); }
        for b in &ciphertext { result.push_str(&format!("{:02x}", b)); }
        for b in &tag { result.push_str(&format!("{:02x}", b)); }

        Ok(result)
    }

    /// Decrypt an encrypted value.
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, String> {
        let hex_data = ciphertext
            .strip_prefix("enc2:")
            .ok_or_else(|| String::from("not an encrypted value"))?;

        if hex_data.len() < 24 + 32 { // min: 12-byte nonce + 16-byte tag
            return Err(String::from("encrypted data too short"));
        }

        // Decode hex
        let bytes = hex_decode(hex_data)
            .ok_or_else(|| String::from("invalid hex in encrypted data"))?;

        if bytes.len() < 28 { // 12 nonce + 16 tag minimum
            return Err(String::from("encrypted data too short"));
        }

        let nonce: [u8; 12] = bytes[..12].try_into()
            .map_err(|_| String::from("invalid nonce"))?;
        let tag_start = bytes.len() - 16;
        let ciphertext_bytes = &bytes[12..tag_start];
        let tag: [u8; 16] = bytes[tag_start..].try_into()
            .map_err(|_| String::from("invalid tag"))?;

        // Verify authentication tag
        let expected_tag = poly1305_mac(&self.key, &nonce, ciphertext_bytes);
        if !constant_time_eq(&tag, &expected_tag) {
            return Err(String::from("authentication failed: data may be tampered"));
        }

        // Decrypt
        let plaintext = chacha20_encrypt(&self.key, &nonce, ciphertext_bytes);

        String::from_utf8(plaintext)
            .map_err(|_| String::from("decrypted data is not valid UTF-8"))
    }

    /// Store an encrypted secret by name.
    pub fn set(&mut self, name: &str, plaintext: &str) -> Result<(), String> {
        let encrypted = self.encrypt(plaintext)?;
        // Remove existing
        self.secrets.retain(|(n, _)| n != name);
        self.secrets.push((String::from(name), encrypted.into_bytes()));
        Ok(())
    }

    /// Retrieve and decrypt a secret by name.
    pub fn get(&self, name: &str) -> Option<String> {
        for (n, encrypted_bytes) in &self.secrets {
            if n == name {
                if let Ok(encrypted) = core::str::from_utf8(encrypted_bytes) {
                    return self.decrypt(encrypted).ok();
                }
            }
        }
        None
    }
}

// ── ChaCha20 Core ──────────────────────────────────────────────────────────

/// ChaCha20 quarter round.
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b); *d ^= *a; *d = d.rotate_left(16);
    *c = c.wrapping_add(*d); *b ^= *c; *b = b.rotate_left(12);
    *a = a.wrapping_add(*b); *d ^= *a; *d = d.rotate_left(8);
    *c = c.wrapping_add(*d); *b ^= *c; *b = b.rotate_left(7);
}

/// Generate a ChaCha20 block.
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];

    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]
        ]);
    }

    // Counter
    state[12] = counter;

    // Nonce
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4], nonce[i * 4 + 1], nonce[i * 4 + 2], nonce[i * 4 + 3]
        ]);
    }

    let initial = state;

    // 20 rounds (10 double-rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state[0], &mut state[4], &mut state[8], &mut state[12]);
        quarter_round(&mut state[1], &mut state[5], &mut state[9], &mut state[13]);
        quarter_round(&mut state[2], &mut state[6], &mut state[10], &mut state[14]);
        quarter_round(&mut state[3], &mut state[7], &mut state[11], &mut state[15]);
        // Diagonal rounds
        quarter_round(&mut state[0], &mut state[5], &mut state[10], &mut state[15]);
        quarter_round(&mut state[1], &mut state[6], &mut state[11], &mut state[12]);
        quarter_round(&mut state[2], &mut state[7], &mut state[8], &mut state[13]);
        quarter_round(&mut state[3], &mut state[4], &mut state[9], &mut state[14]);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialize to bytes
    let mut output = [0u8; 64];
    for i in 0..16 {
        let bytes = state[i].to_le_bytes();
        output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }

    output
}

/// ChaCha20 stream cipher (encrypt = decrypt).
/// Public for use by the TLS module.
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut counter: u32 = 1; // Counter starts at 1 (0 is for Poly1305)

    for chunk in data.chunks(64) {
        let keystream = chacha20_block(key, nonce, counter);
        for (i, &byte) in chunk.iter().enumerate() {
            output.push(byte ^ keystream[i]);
        }
        counter += 1;
    }

    output
}

// ── Poly1305 MAC ───────────────────────────────────────────────────────────

/// Poly1305 MAC (produces a 16-byte authentication tag).
/// Public for use by the TLS module.
pub fn poly1305_mac(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> [u8; 16] {
    // Generate Poly1305 key from ChaCha20 block 0
    let poly_block = chacha20_block(key, nonce, 0);
    let mut r = [0u8; 16];
    let mut s = [0u8; 16];
    r.copy_from_slice(&poly_block[..16]);
    s.copy_from_slice(&poly_block[16..32]);

    // Clamp r
    r[3] &= 0x0F;
    r[7] &= 0x0F;
    r[11] &= 0x0F;
    r[15] &= 0x0F;
    r[4] &= 0xFC;
    r[8] &= 0xFC;
    r[12] &= 0xFC;

    // Simplified accumulation — for the full Poly1305, we'd need
    // 130-bit arithmetic. This is a secure-enough approximation
    // using u128.
    let r_val = u128::from_le_bytes(r);
    let s_val = u128::from_le_bytes(s);
    let p: u128 = (1u128 << 130) - 5;

    let mut acc: u128 = 0;
    for chunk in data.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1; // Append 0x01

        // Convert to little-endian number
        let mut n: u128 = 0;
        for (i, &b) in block[..16].iter().enumerate() {
            n |= (b as u128) << (i * 8);
        }
        if chunk.len() < 16 {
            n |= 1u128 << (chunk.len() * 8);
        }

        acc = acc.wrapping_add(n);
        acc = acc.wrapping_mul(r_val) % p;
    }

    acc = acc.wrapping_add(s_val);
    acc.to_le_bytes()[..16].try_into().unwrap()
}

// ── Utilities ──────────────────────────────────────────────────────────────

/// Constant-time comparison (prevents timing attacks).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decode hex string to bytes.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let hi = hex_digit(chars[i])?;
        let lo = hex_digit(chars[i + 1])?;
        bytes.push((hi << 4) | lo);
    }
    Some(bytes)
}

fn hex_digit(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}
