use ods_core::OptimizationCategory;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecialistKind {
    SyscallEliminator,
    AllocReducer,
    FastPathSpecializer,
    AlgorithmicFixer,
    ValidationRemover,
    CachingSpecialist,
    DependencyOptimizer,
    /// Read-only survey role that proposes *new* recipes from a codebase.
    /// Does not apply patches or run tests; its output is a list of
    /// Hypothesized recipes that grow the corpus.
    Explorer,
}

impl SpecialistKind {
    pub fn category(self) -> OptimizationCategory {
        use SpecialistKind::*;
        match self {
            SyscallEliminator     => OptimizationCategory::SyscallElimination,
            AllocReducer          => OptimizationCategory::AllocReduction,
            FastPathSpecializer   => OptimizationCategory::FastPathSpecialization,
            AlgorithmicFixer      => OptimizationCategory::Algorithmic,
            ValidationRemover     => OptimizationCategory::ValidationRemoval,
            CachingSpecialist     => OptimizationCategory::Caching,
            DependencyOptimizer   => OptimizationCategory::DependencyOptimization,
            // Explorer is not bound to a single category: it proposes
            // patterns across all of them. We pick a neutral one here so
            // callers that expect every SpecialistKind to have a category
            // (e.g. the planner) still compile. The Explorer never flows
            // through the category-driven retrieval path.
            Explorer              => OptimizationCategory::Algorithmic,
        }
    }

    pub fn system_prompt(self) -> &'static str {
        // Stage 1 refines each prompt. The MVP keeps them terse but
        // category-specific so the model primes correctly.
        use SpecialistKind::*;
        match self {
            SyscallEliminator => {
                "You eliminate redundant syscalls. Preferred moves: use d_type \
                 from readdir entries, cache stat results, batch file metadata \
                 lookups. Never change observable behaviour."
            }
            AllocReducer => {
                "You reduce allocations. Preferred moves: prefer borrowed \
                 slices over owned Vec/String, use SmallVec for small-N, \
                 replace variadic collection with explicit argc/argv. Never \
                 change observable behaviour."
            }
            FastPathSpecializer => {
                "You add a fast path for the common case while preserving a \
                 correct slow path. Typical splits: ASCII vs general encoding, \
                 single-argument vs many-argument, zero-length inputs."
            }
            AlgorithmicFixer => {
                "You fix algorithmic inefficiencies: backward scans where \
                 appropriate, early exit, O(n^2) to O(n). Never change \
                 observable behaviour."
            }
            ValidationRemover => {
                "You remove validation that is unreachable given the caller's \
                 invariants. You must prove the invariant holds from callers \
                 before removing the check."
            }
            CachingSpecialist => {
                "You introduce memoisation or hoist loop-invariant work. \
                 Caching must be referentially transparent."
            }
            DependencyOptimizer => {
                "You propose dependency bumps or swaps where the upstream \
                 release contains the optimisation. You must verify cargo-semver-checks \
                 passes and downstream consumers still build."
            }
            Explorer => {
                "You are the Explorer. You do NOT apply patches or run \
                 tests. You survey the codebase (read_file / list_dir / \
                 ast_query only) and propose a handful of reusable \
                 performance-optimisation patterns as JSON. Each pattern \
                 describes a *shape* that could apply to many codebases, \
                 not a specific one-liner fix. Before inventing a pattern, \
                 call `recipe_search` to check whether the corpus already \
                 contains something similar. Finish with a single fenced \
                 ```json block containing a top-level {\"recipes\": [...]} \
                 array."
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistOutcome {
    pub kind: SpecialistKind,
    pub patch_diff: Option<String>,
    pub rationale: String,
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub estimated_cost_usd: f64,
}

pub struct Specialist {
    pub kind: SpecialistKind,
}

impl Specialist {
    pub fn new(kind: SpecialistKind) -> Self {
        Self { kind }
    }

    pub fn system_prompt(&self) -> &'static str {
        self.kind.system_prompt()
    }
}
