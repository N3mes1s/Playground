//! Language-adapter trait and registry. Each supported language is a separate
//! crate implementing [`LanguageAdapter`]; the registry lets the orchestrator
//! pick the right adapter by [`detect`].

pub mod adapter;
pub mod registry;

pub use adapter::{
    AstMatch, BenchReport, BenchSample, Build, Edit, FuzzReport, LanguageAdapter, Patch,
    ProfileReport, TestReport, TestScope,
};
pub use registry::Registry;
