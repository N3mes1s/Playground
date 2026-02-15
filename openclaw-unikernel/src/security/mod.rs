//! # Security System
//!
//! Defense-in-depth security for the unikernel agent:
//! - Security policy engine (autonomy levels, command allowlists, rate limiting)
//! - ChaCha20-Poly1305 secret encryption
//! - Gateway pairing with brute-force protection
//! - Path traversal prevention
//! - Injection detection

mod policy;
pub mod secrets;
pub mod pairing;

pub use policy::{SecurityPolicy, AutonomyLevel};
pub use secrets::SecretStore;
pub use pairing::PairingManager;

use alloc::string::String;
use crate::kernel::sync::SpinLock;

static mut SECURITY: Option<SpinLock<SecurityState>> = None;

struct SecurityState {
    pub policy: SecurityPolicy,
    pub secrets: SecretStore,
    pub pairing: PairingManager,
}

/// Initialize the security subsystem.
pub fn init() {
    let state = SecurityState {
        policy: SecurityPolicy::default(),
        secrets: SecretStore::new(),
        pairing: PairingManager::new(),
    };
    unsafe {
        SECURITY = Some(SpinLock::new(state));
    }
}

/// Get the global security policy.
pub fn policy() -> SecurityPolicy {
    unsafe {
        SECURITY
            .as_ref()
            .map(|s| s.lock().policy.clone())
            .unwrap_or_default()
    }
}

/// Validate a command against the security policy.
pub fn validate_command(command: &str) -> Result<(), String> {
    policy().validate_command(command)
}

/// Validate a file path against the security policy.
pub fn validate_path(path: &str) -> Result<(), String> {
    policy().validate_path(path)
}

/// Encrypt a secret value.
pub fn encrypt_secret(plaintext: &str) -> Result<String, String> {
    unsafe {
        if let Some(ref sec) = SECURITY {
            return sec.lock().secrets.encrypt(plaintext);
        }
    }
    Err(String::from("security not initialized"))
}

/// Decrypt a secret value.
pub fn decrypt_secret(ciphertext: &str) -> Result<String, String> {
    unsafe {
        if let Some(ref sec) = SECURITY {
            return sec.lock().secrets.decrypt(ciphertext);
        }
    }
    Err(String::from("security not initialized"))
}

/// Attempt gateway pairing.
pub fn attempt_pairing(code: &str) -> Result<String, String> {
    unsafe {
        if let Some(ref sec) = SECURITY {
            return sec.lock().pairing.attempt(code);
        }
    }
    Err(String::from("security not initialized"))
}

/// Validate a bearer token.
pub fn validate_token(token: &str) -> bool {
    unsafe {
        if let Some(ref sec) = SECURITY {
            return sec.lock().pairing.validate_token(token);
        }
    }
    false
}
