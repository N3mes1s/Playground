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
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCredentials {
    pub app_id: String,
    pub private_key_pem: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResp {
    token: String,
    #[serde(default)]
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
    /// Returns (token, optional expiry in RFC3339). Prefer
    /// [`InstallationTokenCache::get`] for any code path that runs more
    /// than once per process — installation tokens are valid for ~1h
    /// and there's no reason to mint a new one per request.
    pub async fn installation_token(
        client: &reqwest::Client,
        user_agent: &str,
        creds: &AppCredentials,
        installation_id: u64,
    ) -> Result<String> {
        let (token, _expires_at) =
            Self::installation_token_with_expiry(client, user_agent, creds, installation_id)
                .await?;
        Ok(token)
    }

    async fn installation_token_with_expiry(
        client: &reqwest::Client,
        user_agent: &str,
        creds: &AppCredentials,
        installation_id: u64,
    ) -> Result<(String, Option<String>)> {
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
        Ok((parsed.token, parsed.expires_at))
    }
}

/// Cached installation token. Valid until `expires_at_local` (an `Instant`
/// aligned to the local monotonic clock, so DST / wall-clock jumps don't
/// cause false renewals).
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at_local: Instant,
}

/// Per-installation cache of GitHub App installation tokens.
///
/// GitHub issues these with a 1-hour TTL. Minting one costs an API round
/// trip + an RSA signature; under the webhook server's comment-triggered
/// workflow that's one call per `/ods optimize` comment, which we can
/// collapse to one call per hour per installation by caching.
///
/// The cache holds a safety margin (default 5 minutes) before the stated
/// expiry to avoid returning a token that will expire mid-request.
#[derive(Debug, Clone)]
pub struct InstallationTokenCache {
    inner: Arc<Mutex<HashMap<u64, CachedToken>>>,
    safety_margin: Duration,
}

impl Default for InstallationTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InstallationTokenCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            safety_margin: Duration::from_secs(5 * 60),
        }
    }

    pub fn with_safety_margin(mut self, margin: Duration) -> Self {
        self.safety_margin = margin;
        self
    }

    /// Return a valid installation token for `installation_id`, minting a
    /// new one only when the cache is empty or the cached entry is within
    /// `safety_margin` of its expiry. Serialises concurrent refreshes for
    /// the same installation so N simultaneous webhooks produce exactly
    /// one API call.
    pub async fn get(
        &self,
        client: &reqwest::Client,
        user_agent: &str,
        creds: &AppCredentials,
        installation_id: u64,
    ) -> Result<String> {
        let mut guard = self.inner.lock().await;
        if let Some(entry) = guard.get(&installation_id) {
            if entry.expires_at_local > Instant::now() + self.safety_margin {
                return Ok(entry.token.clone());
            }
        }
        // Miss or expired — mint a fresh one. We hold the lock across the
        // network call so a burst of N concurrent requests blocks on one
        // refresh instead of racing to mint N tokens.
        let (token, expires_at) = GitHubAppAuth::installation_token_with_expiry(
            client,
            user_agent,
            creds,
            installation_id,
        )
        .await?;
        let ttl = expires_at
            .as_deref()
            .and_then(parse_rfc3339_to_remaining)
            .unwrap_or_else(|| Duration::from_secs(55 * 60));
        let entry = CachedToken {
            token: token.clone(),
            expires_at_local: Instant::now() + ttl,
        };
        guard.insert(installation_id, entry);
        Ok(token)
    }

    /// Drop any cached entry for `installation_id`. Use after a 401 to
    /// force a refresh on the next call.
    pub async fn invalidate(&self, installation_id: u64) {
        self.inner.lock().await.remove(&installation_id);
    }

    /// Test-only: pre-populate the cache with a synthetic entry so the
    /// hit/expiry branches can be exercised without talking to GitHub.
    #[doc(hidden)]
    pub async fn insert_for_test(
        &self,
        installation_id: u64,
        token: String,
        expires_at_local: Instant,
    ) {
        self.inner.lock().await.insert(
            installation_id,
            CachedToken {
                token,
                expires_at_local,
            },
        );
    }

    /// Test-only: peek at the cached token for `installation_id` without
    /// triggering a refresh.
    #[doc(hidden)]
    pub async fn peek(&self, installation_id: u64) -> Option<String> {
        self.inner
            .lock()
            .await
            .get(&installation_id)
            .map(|e| e.token.clone())
    }
}

/// Parse GitHub's RFC3339 `expires_at` string (e.g. "2024-01-15T12:34:56Z")
/// and return the duration from *now* until that instant. Returns `None`
/// for malformed input or expiries already in the past.
fn parse_rfc3339_to_remaining(s: &str) -> Option<Duration> {
    let expires =
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    let now = time::OffsetDateTime::now_utc();
    let remaining = expires - now;
    if remaining.is_negative() {
        None
    } else {
        Some(Duration::from_secs(remaining.whole_seconds() as u64))
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

    #[test]
    fn parse_rfc3339_returns_positive_duration_for_future() {
        // 10 minutes in the future (plus a skew tolerance).
        let ts = time::OffsetDateTime::now_utc() + time::Duration::seconds(10 * 60);
        let s = ts
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let remaining = parse_rfc3339_to_remaining(&s).unwrap();
        assert!(remaining.as_secs() > 9 * 60 && remaining.as_secs() <= 10 * 60);
    }

    #[test]
    fn parse_rfc3339_returns_none_for_past() {
        let ts = time::OffsetDateTime::now_utc() - time::Duration::seconds(60);
        let s = ts
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        assert!(parse_rfc3339_to_remaining(&s).is_none());
    }

    #[test]
    fn parse_rfc3339_returns_none_for_malformed() {
        assert!(parse_rfc3339_to_remaining("not a date").is_none());
        assert!(parse_rfc3339_to_remaining("").is_none());
    }

    /// A fresh-enough cache entry must be returned without refreshing.
    /// Proving this requires that `get()` short-circuit *before* any
    /// network call; we pass an intentionally unreachable HTTP client to
    /// force a failure if `get()` ever attempts a refresh.
    #[tokio::test]
    async fn cache_hit_short_circuits_without_refresh() {
        let cache = InstallationTokenCache::new();
        // Token that expires 30 minutes from now — well past the 5-minute
        // safety margin.
        cache
            .insert_for_test(
                42,
                "cached-token".into(),
                Instant::now() + Duration::from_secs(30 * 60),
            )
            .await;
        // Client pointed at a black-hole port so any network call would
        // fail; the test must succeed purely from cache.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(1))
            .build()
            .unwrap();
        let creds = AppCredentials {
            app_id: "1".into(),
            private_key_pem: "unused".into(),
        };
        let got = cache.get(&http, "ua", &creds, 42).await.unwrap();
        assert_eq!(got, "cached-token");
    }

    /// A cached entry within the safety margin must NOT short-circuit —
    /// the cache has to attempt a refresh. We verify by observing that
    /// the network call is attempted (and fails against a black-hole
    /// client). A successful "Ok" here would be a correctness bug.
    #[tokio::test]
    async fn cache_within_safety_margin_attempts_refresh() {
        let cache = InstallationTokenCache::new().with_safety_margin(Duration::from_secs(60));
        // Token technically still valid for 10s, but inside the 60s safety
        // margin — we must refresh.
        cache
            .insert_for_test(
                7,
                "about-to-expire".into(),
                Instant::now() + Duration::from_secs(10),
            )
            .await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(1))
            .build()
            .unwrap();
        let creds = AppCredentials {
            app_id: "1".into(),
            private_key_pem: "-----BEGIN INVALID-----\n-----END INVALID-----".into(),
        };
        // The refresh will fail (either at key-parse or at network), but
        // it MUST try — meaning `get()` returns Err, not the stale token.
        let got = cache.get(&http, "ua", &creds, 7).await;
        assert!(
            got.is_err(),
            "cache returned stale token inside safety margin: {got:?}",
        );
    }

    #[tokio::test]
    async fn invalidate_drops_cached_entry() {
        let cache = InstallationTokenCache::new();
        cache
            .insert_for_test(
                99,
                "stale".into(),
                Instant::now() + Duration::from_secs(60 * 60),
            )
            .await;
        assert!(cache.peek(99).await.is_some());
        cache.invalidate(99).await;
        assert!(cache.peek(99).await.is_none());
    }
}
