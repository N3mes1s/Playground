//! Batch scheduler for `ods optimize`.
//!
//! Pipeline: Discoverer.scan_with_recipes → pick top-K → run each under a
//! shared budget cap → write a batch artifact referencing every child run.

use crate::discover::Discoverer;
use crate::orchestrator::Orchestrator;
use anyhow::Result;
use ods_core::{Mode, TargetSig};
use ods_lang::LanguageAdapter;
use ods_recipes::Store;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchArtifact {
    pub id: String,
    pub repo: String,
    pub budget_usd: f64,
    pub total_spent_usd: f64,
    pub child_runs: Vec<String>,
    pub winners: u32,
    pub started_at: String,
    pub finished_at: String,
}

pub struct Scheduler {
    adapter: Arc<dyn LanguageAdapter>,
    store: Arc<Store>,
    repo: PathBuf,
    mode: Mode,
    budget_usd: f64,
}

impl Scheduler {
    pub fn new(
        adapter: Arc<dyn LanguageAdapter>,
        store: Arc<Store>,
        repo: PathBuf,
        mode: Mode,
        budget_usd: f64,
    ) -> Self {
        Self {
            adapter,
            store,
            repo,
            mode,
            budget_usd,
        }
    }

    pub async fn run(&self, top_k: usize, allow_llm: bool) -> Result<BatchArtifact> {
        let batch_id = ods_core::RunId::new().to_string();
        let started_at = now_rfc3339()?;

        let candidates =
            Discoverer::default().scan_with_recipes(&self.repo, self.store.as_ref(), top_k)?;
        tracing::info!(
            candidates = candidates.len(),
            budget_usd = self.budget_usd,
            "scheduler: picked top-K targets"
        );

        let mut child_runs = Vec::new();
        let mut total_spent = 0.0;
        let mut winners = 0u32;

        for cand in candidates {
            if total_spent >= self.budget_usd {
                tracing::info!(
                    total_spent,
                    budget_usd = self.budget_usd,
                    "scheduler: budget exhausted; stopping"
                );
                break;
            }
            let target = TargetSig {
                language: cand.language,
                module: cand.module,
                symbol: cand.symbol,
                arity: None,
            };
            let orch = Orchestrator::new(
                self.adapter.clone(),
                self.store.clone(),
                self.repo.clone(),
                self.mode.clone(),
            );
            match orch.run(target.clone(), allow_llm).await {
                Ok(art) => {
                    total_spent += art.spent_usd;
                    if art.winning_specialist.is_some() {
                        winners += 1;
                    }
                    child_runs.push(art.run_id);
                }
                Err(e) => {
                    tracing::warn!(target = %target, err = %e, "scheduler: run failed");
                }
            }
        }

        let finished_at = now_rfc3339()?;
        let artifact = BatchArtifact {
            id: batch_id.clone(),
            repo: self.repo.display().to_string(),
            budget_usd: self.budget_usd,
            total_spent_usd: total_spent,
            child_runs,
            winners,
            started_at,
            finished_at,
        };

        // Persist batch artifact next to per-run artifacts.
        let batch_dir = self.repo.join(".ods").join("batches");
        std::fs::create_dir_all(&batch_dir)?;
        std::fs::write(
            batch_dir.join(format!("{batch_id}.json")),
            serde_json::to_string_pretty(&artifact)?,
        )?;

        Ok(artifact)
    }
}

fn now_rfc3339() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)?)
}
