use crate::domain::{Hypothesis, RunId, TargetSig};
use crate::mode::Mode;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

/// The stages of the optimization loop, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoopStage {
    TargetSelect,
    Profile,
    RecipeRetrieve,
    Hypothesize,
    Transform,
    Verify,
    Bench,
    Explain,
    Harvest,
}

impl LoopStage {
    pub const ORDER: &'static [LoopStage] = &[
        LoopStage::TargetSelect,
        LoopStage::Profile,
        LoopStage::RecipeRetrieve,
        LoopStage::Hypothesize,
        LoopStage::Transform,
        LoopStage::Verify,
        LoopStage::Bench,
        LoopStage::Explain,
        LoopStage::Harvest,
    ];

    pub fn next(self) -> Option<LoopStage> {
        let idx = Self::ORDER.iter().position(|&s| s == self)?;
        Self::ORDER.get(idx + 1).copied()
    }
}

#[derive(Debug, Error)]
pub enum LoopError {
    #[error("budget exhausted at stage {stage:?} (wall {elapsed_secs}s, spent ${spent_usd:.2})")]
    BudgetExhausted {
        stage: LoopStage,
        elapsed_secs: u64,
        spent_usd: f64,
    },
    #[error("compatibility gate failed at stage {stage:?}: {detail}")]
    CompatFailure { stage: LoopStage, detail: String },
    #[error("stage {stage:?} produced no result: {detail}")]
    NoResult { stage: LoopStage, detail: String },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// In-memory aggregate describing one optimization run.
#[derive(Debug)]
pub struct Run {
    pub id: RunId,
    pub mode: Mode,
    pub target: Option<TargetSig>,
    pub hypotheses: Vec<Hypothesis>,
    pub stage: LoopStage,
    pub started_at: Instant,
    pub spent_usd: f64,
}

impl Run {
    pub fn new(mode: Mode) -> Self {
        Self {
            id: RunId::new(),
            mode,
            target: None,
            hypotheses: Vec::new(),
            stage: LoopStage::TargetSelect,
            started_at: Instant::now(),
            spent_usd: 0.0,
        }
    }

    /// Check if we can transition to the next stage under the current budget.
    pub fn check_budget(&self) -> Result<(), LoopError> {
        let Some(budget) = self.mode.budget() else {
            return Ok(());
        };
        let elapsed = self.started_at.elapsed();
        if elapsed > budget.wall_cap || self.spent_usd > budget.spend_cap_usd {
            return Err(LoopError::BudgetExhausted {
                stage: self.stage,
                elapsed_secs: elapsed.as_secs(),
                spent_usd: self.spent_usd,
            });
        }
        Ok(())
    }

    /// Move to the next stage, enforcing the budget gate first.
    pub fn advance(&mut self) -> Result<Option<LoopStage>, LoopError> {
        self.check_budget()?;
        match self.stage.next() {
            Some(next) => {
                self.stage = next;
                Ok(Some(next))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_order_is_complete() {
        let mut stage = LoopStage::TargetSelect;
        let mut count = 1;
        while let Some(n) = stage.next() {
            stage = n;
            count += 1;
        }
        assert_eq!(count, LoopStage::ORDER.len());
        assert_eq!(stage, LoopStage::Harvest);
    }

    #[test]
    fn dev_mode_has_no_budget() {
        let run = Run::new(Mode::dev());
        assert!(run.check_budget().is_ok());
    }
}
