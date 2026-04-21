use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Runtime autonomy budget. Dev is unbounded; CI carries hard caps that are
/// checked at every `LoopStage` transition AND before every Anthropic API
/// call via a shared [`BudgetTracker`].
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

    /// Construct a shared tracker the orchestrator can hand to every
    /// specialist's `ToolUseLoop`. In `Dev` the tracker is unbounded and
    /// [`BudgetTracker::would_exceed`] always returns `None`.
    pub fn budget_tracker(&self) -> BudgetTracker {
        BudgetTracker::new(self.budget())
    }
}

/// Shared per-run spend accumulator. All specialists that race in parallel
/// charge into the same tracker, so a fast-burning specialist can't overshoot
/// the cap by completing an in-flight conversation while another specialist
/// is still waiting to be dispatched.
#[derive(Debug, Clone)]
pub struct BudgetTracker {
    inner: Arc<Mutex<TrackerState>>,
}

#[derive(Debug)]
struct TrackerState {
    spent_usd: f64,
    spend_cap_usd: Option<f64>,
    wall_start: Instant,
    wall_cap: Option<Duration>,
}

/// Record returned when a projected next-call cost would push total spend
/// above the cap, *before* the HTTP POST fires. Callers convert this into
/// `LoopError::BudgetWouldExceed` / `BudgetExhausted` as appropriate.
#[derive(Debug, Clone, Copy)]
pub struct BudgetExceedReason {
    pub current_usd: f64,
    pub projected_usd: f64,
    pub cap_usd: f64,
    pub wall_elapsed: Duration,
    pub wall_exhausted: bool,
}

impl BudgetTracker {
    pub fn new(budget: Option<&Budget>) -> Self {
        let (spend_cap_usd, wall_cap) = match budget {
            Some(b) => (Some(b.spend_cap_usd), Some(b.wall_cap)),
            None => (None, None),
        };
        Self {
            inner: Arc::new(Mutex::new(TrackerState {
                spent_usd: 0.0,
                spend_cap_usd,
                wall_start: Instant::now(),
                wall_cap,
            })),
        }
    }

    /// Accumulate the real cost of an API call that just completed.
    pub fn add_spent(&self, delta_usd: f64) {
        let mut s = self.inner.lock().expect("tracker poisoned");
        s.spent_usd += delta_usd;
    }

    pub fn spent(&self) -> f64 {
        self.inner.lock().expect("tracker poisoned").spent_usd
    }

    /// Remaining headroom in USD, or `None` when no cap is set.
    pub fn remaining(&self) -> Option<f64> {
        let s = self.inner.lock().expect("tracker poisoned");
        s.spend_cap_usd.map(|cap| (cap - s.spent_usd).max(0.0))
    }

    /// Return `Some(reason)` if charging a hypothetical next call whose
    /// worst-case cost is `projection_usd` would push us over the cap, OR
    /// if the wall clock has already exceeded `wall_cap`. Returns `None`
    /// when we're safely under both limits or when no cap is set.
    pub fn would_exceed(&self, projection_usd: f64) -> Option<BudgetExceedReason> {
        let s = self.inner.lock().expect("tracker poisoned");
        let wall_elapsed = s.wall_start.elapsed();
        let wall_exhausted = s.wall_cap.map(|wc| wall_elapsed > wc).unwrap_or(false);
        let spend_exhausted = s
            .spend_cap_usd
            .map(|cap| s.spent_usd + projection_usd > cap)
            .unwrap_or(false);
        if spend_exhausted || wall_exhausted {
            Some(BudgetExceedReason {
                current_usd: s.spent_usd,
                projected_usd: projection_usd,
                cap_usd: s.spend_cap_usd.unwrap_or(0.0),
                wall_elapsed,
                wall_exhausted,
            })
        } else {
            None
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
