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
///
/// `RuntimeConfig` covers wins that live outside the source code — tuning
/// GC thresholds, selecting allocators, enabling transparent-huge-pages,
/// configuring pre-fork worker hooks. These are behaviour-changing
/// optimisations that a CI-time bench can't fully validate, so recipes
/// in this category surface as *suggestions* and are never auto-applied
/// by the specialist race until a canary-style gate lands. See
/// `docs/retrospective-coverage.md` Slice C.
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
    RuntimeConfig,
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
        OptimizationCategory::RuntimeConfig,
    ];

    /// True for categories whose effect is a runtime-behaviour change
    /// (not a local-semantic patch), which the current `ZeroDiffGate`
    /// can't fully validate. Callers in the specialist race use this
    /// to route the hypothesis to a suggestion path instead of an
    /// auto-apply path.
    pub fn requires_canary(self) -> bool {
        matches!(self, OptimizationCategory::RuntimeConfig)
    }
}

impl fmt::Display for OptimizationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OptimizationCategory::*;
        let s = match self {
            SyscallElimination => "syscall-elimination",
            AllocReduction => "alloc-reduction",
            FastPathSpecialization => "fast-path-specialization",
            Algorithmic => "algorithmic",
            ValidationRemoval => "validation-removal",
            Caching => "caching",
            DependencyOptimization => "dependency-optimization",
            RuntimeConfig => "runtime-config",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_canary_is_honored_only_for_runtime_config() {
        for cat in OptimizationCategory::ALL {
            let expected = matches!(cat, OptimizationCategory::RuntimeConfig);
            assert_eq!(
                cat.requires_canary(),
                expected,
                "{cat:?} should {}require canary",
                if expected { "" } else { "NOT " }
            );
        }
    }

    #[test]
    fn runtime_config_serialises_as_kebab_case() {
        let s = OptimizationCategory::RuntimeConfig.to_string();
        assert_eq!(s, "runtime-config");
        // Round-trip through serde as well, since recipe YAML depends on it.
        let json = serde_json::to_string(&OptimizationCategory::RuntimeConfig).unwrap();
        assert_eq!(json, "\"runtime-config\"");
        let back: OptimizationCategory = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, OptimizationCategory::RuntimeConfig));
    }
}
