//! GitHub integration. Two modes:
//!
//! - `Action`: one-shot, run inside a GitHub Actions job; authenticates with
//!   a bot PAT (`ODS_GITHUB_TOKEN`) and opens a PR.
//! - `App`:   long-running webhook server; authenticates as a GitHub App,
//!   handles comment-triggered runs, status checks, and repo-allowlist
//!   gating.

pub mod api;
pub mod app_auth;
pub mod github_app;
pub mod signature;
pub mod webhook;

pub use api::{BranchRef, GitHubClient, PullRequest};
pub use app_auth::{AppCredentials, GitHubAppAuth, InstallationTokenCache};
pub use github_app::{CiMode, OpenPrRequest, PrAllowlist};
pub use signature::{sign as sign_webhook, verify as verify_webhook, SignatureVerdict};
pub use webhook::{WebhookEvent, WebhookServer};
