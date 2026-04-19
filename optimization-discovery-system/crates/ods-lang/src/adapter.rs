use anyhow::Result;
use async_trait::async_trait;
use ods_core::TargetSig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Build {
    pub workdir: PathBuf,
    pub artifact: Option<PathBuf>,
    pub toolchain: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TestScope {
    Unit,
    Integration,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub log_path: Option<PathBuf>,
}

impl TestReport {
    pub fn green(&self) -> bool {
        self.failed == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchSample {
    pub name: String,
    pub ns_per_iter: f64,
    pub iters: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub samples: Vec<BenchSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileReport {
    pub wall: Duration,
    pub cycles: Option<u64>,
    pub instructions: Option<u64>,
    pub llc_misses: Option<u64>,
    pub branch_misses: Option<u64>,
    pub syscall_counts: Vec<(String, u64)>,
    pub alloc_count: Option<u64>,
    pub alloc_bytes: Option<u64>,
    pub flame_svg_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edit {
    pub file: PathBuf,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub unified_diff: String,
    pub edits: Vec<Edit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstMatch {
    pub file: PathBuf,
    pub start_line: u32,
    pub end_line: u32,
    pub text: String,
    /// Name of the nearest enclosing function / method / def, extracted
    /// by the language adapter via a tree-sitter ancestor walk. `None`
    /// when the match is at module scope.
    #[serde(default)]
    pub enclosing_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzReport {
    pub minutes: u32,
    pub crashes: u32,
    pub seed_corpus_size: u32,
}

/// Everything the loop needs from a concrete language to run end-to-end.
#[async_trait]
pub trait LanguageAdapter: Send + Sync {
    fn name(&self) -> &'static str;

    async fn detect(&self, repo: &Path) -> Result<bool>;

    async fn build(&self, repo: &Path, patch: Option<&Patch>) -> Result<Build>;

    async fn run_tests(&self, build: &Build, scope: TestScope) -> Result<TestReport>;

    async fn run_bench(&self, build: &Build, target: &TargetSig) -> Result<BenchReport>;

    async fn profile(&self, build: &Build, target: &TargetSig) -> Result<ProfileReport>;

    async fn ast_query(&self, file: &Path, query: &str) -> Result<Vec<AstMatch>>;

    /// Run N queries against the same file. The default implementation
    /// loops over `ast_query`, re-reading and re-parsing the file each
    /// time. Adapters backed by a tree-sitter grammar override this to
    /// parse once and execute every query against the shared tree —
    /// the parser reuse amortises, and more importantly the agent
    /// saves an LLM turn per extra pattern it wants to probe.
    async fn ast_query_batch(&self, file: &Path, queries: &[&str]) -> Result<Vec<Vec<AstMatch>>> {
        let mut out = Vec::with_capacity(queries.len());
        for q in queries {
            out.push(self.ast_query(file, q).await?);
        }
        Ok(out)
    }

    fn emit_patch(&self, edits: &[Edit]) -> Result<Patch>;

    async fn fuzz(&self, build: &Build, target: &TargetSig, budget: Duration)
        -> Result<FuzzReport>;
}
