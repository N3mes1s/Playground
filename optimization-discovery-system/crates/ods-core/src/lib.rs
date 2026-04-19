//! Core domain types and the Loop state machine.
//!
//! Mirrors the byroot "faster paths" methodology:
//!
//! `TargetSelect -> Profile -> RecipeRetrieve -> Hypothesize -> Transform ->
//!  Verify -> Bench -> Explain -> Harvest`

pub mod domain;
pub mod git;
pub mod loop_;
pub mod mode;

pub use domain::{Hypothesis, OptimizationCategory, RunId, TargetSig};
pub use git::{Worktree, WorktreeHandle};
pub use loop_::{LoopError, LoopStage, Run};
pub use mode::{Budget, Mode};
