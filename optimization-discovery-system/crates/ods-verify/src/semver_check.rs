use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "kebab-case")]
pub enum SemverVerdict {
    Compatible,
    Breaking(Vec<String>),
    Unchecked(String),
}

pub struct SemverCheck;

impl SemverCheck {
    /// Stage 1: shell out to `cargo-semver-checks check-release`. Today we
    /// expose the typed verdict so callers can wire it without the tool
    /// actually being present.
    pub fn run_stub(reason: impl Into<String>) -> SemverVerdict {
        SemverVerdict::Unchecked(reason.into())
    }
}
