use crate::adapter::LanguageAdapter;
use anyhow::{bail, Result};
use std::path::Path;
use std::sync::Arc;

#[derive(Default)]
pub struct Registry {
    adapters: Vec<Arc<dyn LanguageAdapter>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, adapter: Arc<dyn LanguageAdapter>) {
        self.adapters.push(adapter);
    }

    pub async fn detect(&self, repo: &Path) -> Result<Arc<dyn LanguageAdapter>> {
        for adapter in &self.adapters {
            if adapter.detect(repo).await? {
                return Ok(adapter.clone());
            }
        }
        bail!("no language adapter matched {}", repo.display())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn LanguageAdapter>> {
        self.adapters.iter()
    }
}
