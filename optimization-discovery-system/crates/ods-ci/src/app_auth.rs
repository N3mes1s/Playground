//! GitHub App authentication.
//!
//! Flow:
//!   1. Sign a short JWT (RS256) claiming `iss = <app_id>` for 10 minutes.
//!   2. Exchange it for an installation token via
//!      `POST /app/installations/{installation_id}/access_tokens`.
//!   3. Use the installation token as a bearer against the usual REST
//!      endpoints.
//!
//! Signing is pure-Rust via `rsa` + `sha2`, which keeps the binary
//! musl-friendly (no `ring`/OpenSSL dependency).

use anyhow::{Context, Result};
use pkcs1::DecodeRsaPrivateKey;
use pkcs8::DecodePrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCredentials {
    pub app_id: String,
    pub private_key_pem: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResp {
    token: String,
    #[allow(dead_code)]
    expires_at: Option<String>,
}

pub struct GitHubAppAuth;

impl GitHubAppAuth {
    /// Produce an RS256 JWT valid for `ttl`. iat is backdated 60 s to tolerate
    /// clock skew (GitHub rejects JWTs that are "in the future").
    pub fn jwt(creds: &AppCredentials, ttl: Duration) -> Result<String> {
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
        });
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = serde_json::json!({
            "iat": now - 60,
            "exp": now + ttl.as_secs() as i64,
            "iss": creds.app_id,
        });
        let header_b64 = b64url(&serde_json::to_vec(&header)?);
        let claims_b64 = b64url(&serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{claims_b64}");

        let key = RsaPrivateKey::from_pkcs8_pem(&creds.private_key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&creds.private_key_pem))
            .context("parse GitHub App RSA private key (PKCS#8 / PKCS#1 PEM)")?;
        let signer = SigningKey::<Sha256>::new(key);
        let mut rng = DeterministicRng::new();
        let sig = signer.sign_with_rng(&mut rng, signing_input.as_bytes());
        let sig_b64 = b64url(sig.to_bytes().as_ref());
        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Exchange the JWT for an installation token via the GitHub API.
    pub async fn installation_token(
        client: &reqwest::Client,
        user_agent: &str,
        creds: &AppCredentials,
        installation_id: u64,
    ) -> Result<String> {
        let jwt = Self::jwt(creds, Duration::from_secs(600))?;
        let url =
            format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("User-Agent", user_agent)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?;
        let parsed: InstallationTokenResp = resp.json().await?;
        Ok(parsed.token)
    }
}

/// Minimal RSA sign-path RNG. We use a seeded stream keyed on the current
/// clock nanoseconds + pid so the signature stays unique without a ring /
/// getrandom-syscall dependency cost; PKCS#1 v1.5 doesn't actually require
/// randomness for the *signature* itself, but the trait signature does.
pub(crate) struct DeterministicRng(u64);

impl DeterministicRng {
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self(now ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15))
    }
    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0.max(1);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

impl rsa::rand_core::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        DeterministicRng::next_u64(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let n = self.next_u64().to_le_bytes();
            let take = (dest.len() - i).min(8);
            dest[i..i + take].copy_from_slice(&n[..take]);
            i += take;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for DeterministicRng {}

/// URL-safe base64 without padding.
fn b64url(bytes: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPH[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_omits_padding() {
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"f"), "Zg");
    }
}
