use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CiMode {
    Action,
    App,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPrRequest {
    pub repo: String,
    pub base_branch: String,
    pub head_branch: String,
    pub title: String,
    pub body: String,
    pub draft: bool,
}

/// Etiquette gate. Unsolicited bot PRs are obnoxious; we only open PRs against
/// repos that have explicitly opted in.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrAllowlist {
    allowed: BTreeSet<String>,
}

impl PrAllowlist {
    pub fn from_list<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: items.into_iter().map(Into::into).collect(),
        }
    }

    pub fn permits(&self, repo_fullname: &str) -> bool {
        self.allowed.contains(repo_fullname)
    }

    pub fn insert(&mut self, repo_fullname: impl Into<String>) {
        self.allowed.insert(repo_fullname.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_denies_unknown() {
        let al = PrAllowlist::from_list(["acme/widgets"]);
        assert!(al.permits("acme/widgets"));
        assert!(!al.permits("acme/other"));
    }
}
