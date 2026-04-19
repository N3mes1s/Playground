//! axum-based webhook server for the GitHub App mode. Handles the single
//! event we care about for comment-triggered runs: `issue_comment.created`
//! with a body starting with `/ods optimize`. The actual run is dispatched
//! to an async channel; the HTTP handler only acknowledges receipt so GitHub
//! doesn't time out.
//!
//! Signature verification is TODO (requires the App's webhook secret); we
//! expose the raw payload so a later stage can verify `X-Hub-Signature-256`.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub repo: String,
    pub issue_number: u64,
    pub user: String,
    pub body: String,
}

pub struct WebhookServer {
    pub port: u16,
}

impl WebhookServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Run the HTTP listener until `cancel` is cancelled. Events parsed from
    /// `issue_comment.created` payloads are forwarded on the returned
    /// channel; callers dispatch runs without blocking the HTTP handler.
    pub async fn run(
        self,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<mpsc::UnboundedReceiver<WebhookEvent>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(tx);
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/webhook", post(handle))
            .with_state(state);
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, "webhook listening");
        let shutdown = async move {
            let mut cancel = cancel;
            let _ = cancel.changed().await;
        };
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
            {
                tracing::error!(err = %e, "axum serve exited");
            }
        });
        Ok(rx)
    }
}

#[derive(Debug, Deserialize)]
struct IssueCommentPayload {
    action: String,
    repository: Repo,
    issue: Issue,
    comment: Comment,
}

#[derive(Debug, Deserialize)]
struct Repo {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct Issue {
    number: u64,
}

#[derive(Debug, Deserialize)]
struct Comment {
    user: User,
    body: String,
}

#[derive(Debug, Deserialize)]
struct User {
    login: String,
}

async fn handle(
    State(tx): State<Arc<mpsc::UnboundedSender<WebhookEvent>>>,
    Json(payload): Json<serde_json::Value>,
) -> (StatusCode, &'static str) {
    // We only care about comment-triggered events; any other payload shape
    // should still return 200 to keep GitHub happy.
    let Ok(parsed) = serde_json::from_value::<IssueCommentPayload>(payload) else {
        return (StatusCode::OK, "ignored");
    };
    if parsed.action != "created" {
        return (StatusCode::OK, "ignored");
    }
    if !parsed.comment.body.trim_start().starts_with("/ods optimize") {
        return (StatusCode::OK, "ignored");
    }
    let event = WebhookEvent {
        repo: parsed.repository.full_name,
        issue_number: parsed.issue.number,
        user: parsed.comment.user.login,
        body: parsed.comment.body,
    };
    let _ = tx.send(event);
    (StatusCode::OK, "queued")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comment_payload() {
        let json = serde_json::json!({
            "action": "created",
            "repository": { "full_name": "acme/widgets" },
            "issue": { "number": 42 },
            "comment": {
                "user": { "login": "byroot" },
                "body": "/ods optimize File.join"
            }
        });
        let p: IssueCommentPayload = serde_json::from_value(json).unwrap();
        assert_eq!(p.action, "created");
        assert_eq!(p.repository.full_name, "acme/widgets");
        assert_eq!(p.issue.number, 42);
        assert!(p.comment.body.contains("optimize"));
    }
}
