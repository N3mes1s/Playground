//! GitHub integration. Two modes:
//!
//! - `Action`: one-shot, run inside a GitHub Actions job; authenticates with
//!   a bot PAT (`ODS_GITHUB_TOKEN`) and opens a PR.
//! - `App`:   long-running webhook server; authenticates as a GitHub App,
//!   handles comment-triggered runs, status checks, and repo-allowlist gating.
//!
//! This crate currently exposes the typed API surface; the HTTP server lands
//! in stage 2.

pub mod github_app;

pub use github_app::{CiMode, OpenPrRequest, PrAllowlist};
