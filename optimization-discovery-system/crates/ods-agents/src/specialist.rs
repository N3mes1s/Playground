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
            SyscallEliminator => OptimizationCategory::SyscallElimination,
            AllocReducer => OptimizationCategory::AllocReduction,
            FastPathSpecializer => OptimizationCategory::FastPathSpecialization,
            AlgorithmicFixer => OptimizationCategory::Algorithmic,
            ValidationRemover => OptimizationCategory::ValidationRemoval,
            CachingSpecialist => OptimizationCategory::Caching,
            DependencyOptimizer => OptimizationCategory::DependencyOptimization,
            // Explorer is not bound to a single category: it proposes
            // patterns across all of them. We pick a neutral one here so
            // callers that expect every SpecialistKind to have a category
            // (e.g. the planner) still compile. The Explorer never flows
            // through the category-driven retrieval path.
            Explorer => OptimizationCategory::Algorithmic,
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
                "You are the Explorer. You survey a codebase (read-only -- \
                 no apply_patch, no run_tests, no run_bench) and propose \
                 reusable performance-optimisation patterns as structured \
                 JSON.\n\n\
                 **Process.** Before emitting your final response you MUST \
                 actually explore. A principled survey includes:\n\
                 1. `list_dir` on repo root AND on the primary source \
                 directory (`src/`, `lib/`, etc.).\n\
                 2. `read_file` on at least 3 source files that look hot \
                 (parsers, core loops, formatters, I/O paths).\n\
                 3. At least 2 `ast_query` calls targeting concrete \
                 performance smells (loops, allocations, syscalls, \
                 unchecked casts).\n\
                 4. One `recipe_search` call to confirm you are not \
                 re-proposing something already in the corpus.\n\n\
                 Only after all four are done should you emit your final \
                 response. Returning an empty `{\"recipes\": []}` on \
                 iteration 1 without exploration is a failure mode -- do \
                 not take that shortcut.\n\n\
                 **Output.** Each pattern you propose describes a \
                 reusable SHAPE (regex trigger + profile signature + \
                 transformation steps + preserved invariants), not a \
                 one-off fix for a specific function. Your final text \
                 response is grammar-constrained to a JSON object matching \
                 the schema the tool harness has attached to this \
                 request; you do not need to worry about fences or \
                 syntax, only about picking good patterns."
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
