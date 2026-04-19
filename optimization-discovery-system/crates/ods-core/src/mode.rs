use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Runtime autonomy budget. Dev is unbounded; CI carries hard caps that are
/// checked at every `LoopStage` transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Mode {
    Dev,
    Ci(Budget),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    #[serde(with = "humantime_serde_compat")]
    pub wall_cap: Duration,
    pub spend_cap_usd: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            wall_cap: Duration::from_secs(15 * 60),
            spend_cap_usd: 5.0,
        }
    }
}

impl Mode {
    pub fn dev() -> Self {
        Self::Dev
    }

    pub fn ci_default() -> Self {
        Self::Ci(Budget::default())
    }

    pub fn budget(&self) -> Option<&Budget> {
        match self {
            Mode::Dev => None,
            Mode::Ci(b) => Some(b),
        }
    }
}

// Minimal humantime-like serde for Duration (seconds). We avoid pulling the
// humantime-serde crate to keep the dep tree small.
mod humantime_serde_compat {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        d.as_secs().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}
