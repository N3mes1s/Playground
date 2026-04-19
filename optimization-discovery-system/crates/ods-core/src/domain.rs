use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub Uuid);

impl RunId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Identifies the function/primitive we are trying to optimize.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetSig {
    pub language: String,
    pub module: String,
    pub symbol: String,
    pub arity: Option<u8>,
}

impl fmt::Display for TargetSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.language, self.module, self.symbol)
    }
}

/// The fixed set of transformation families we recognise. Matches the
/// classification in the blog post plus one cross-dependency role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptimizationCategory {
    SyscallElimination,
    AllocReduction,
    FastPathSpecialization,
    Algorithmic,
    ValidationRemoval,
    Caching,
    DependencyOptimization,
}

impl OptimizationCategory {
    pub const ALL: &'static [OptimizationCategory] = &[
        OptimizationCategory::SyscallElimination,
        OptimizationCategory::AllocReduction,
        OptimizationCategory::FastPathSpecialization,
        OptimizationCategory::Algorithmic,
        OptimizationCategory::ValidationRemoval,
        OptimizationCategory::Caching,
        OptimizationCategory::DependencyOptimization,
    ];
}

impl fmt::Display for OptimizationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OptimizationCategory::*;
        let s = match self {
            SyscallElimination     => "syscall-elimination",
            AllocReduction         => "alloc-reduction",
            FastPathSpecialization => "fast-path-specialization",
            Algorithmic            => "algorithmic",
            ValidationRemoval      => "validation-removal",
            Caching                => "caching",
            DependencyOptimization => "dependency-optimization",
        };
        f.write_str(s)
    }
}

/// A planner-emitted hypothesis routed to a single specialist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub category: OptimizationCategory,
    pub target: TargetSig,
    pub rationale: String,
    /// Optional recipe id retrieved from the corpus that seeded this hypothesis.
    pub seed_recipe_id: Option<String>,
}
