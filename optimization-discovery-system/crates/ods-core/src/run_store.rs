//! SQLite-backed run persistence. Replaces the JSON-only dump in
//! `.ods/runs/<id>.json` with a durable, resumable store keyed by run_id.
//! A run's state machine position, accumulated spend, recipe hits, and
//! per-stage artifacts live here so `ods explain` can rehydrate any prior
//! run and so interrupted CI runs can be resumed from their last committed
//! stage.

use crate::domain::RunId;
use crate::loop_::LoopStage;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    language     TEXT NOT NULL,
    target_lang  TEXT NOT NULL,
    target_mod   TEXT NOT NULL,
    target_sym   TEXT NOT NULL,
    stage        TEXT NOT NULL,
    spent_usd    REAL NOT NULL DEFAULT 0.0,
    started_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL,
    artifact     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS idx_runs_updated ON runs(updated_at);

CREATE TABLE IF NOT EXISTS run_events (
    run_id      TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    at          TEXT NOT NULL,
    stage       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    detail      TEXT,
    PRIMARY KEY (run_id, seq),
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    InProgress,
    Completed,
    Failed,
    AbortedBudget,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::InProgress => "in-progress",
            RunStatus::Completed => "completed",
            RunStatus::Failed => "failed",
            RunStatus::AbortedBudget => "aborted-budget",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "completed" => RunStatus::Completed,
            "failed" => RunStatus::Failed,
            "aborted-budget" => RunStatus::AbortedBudget,
            _ => RunStatus::InProgress,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: String,
    pub language: String,
    pub target: (String, String, String),
    pub stage: LoopStage,
    pub spent_usd: f64,
    pub started_at: String,
    pub updated_at: String,
    pub finished_at: Option<String>,
    pub status: RunStatus,
    /// Caller-defined JSON-serialized artifact blob. In practice we store
    /// the orchestrator's `RunArtifact` here.
    pub artifact_json: String,
}

pub struct RunStore {
    conn: Connection,
}

impl RunStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open run store")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn insert(&self, r: &RunRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO runs(id, language, target_lang, target_mod, target_sym, stage,
                              spent_usd, started_at, updated_at, finished_at, status, artifact)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                r.id,
                r.language,
                r.target.0,
                r.target.1,
                r.target.2,
                stage_str(r.stage),
                r.spent_usd,
                r.started_at,
                r.updated_at,
                r.finished_at,
                r.status.as_str(),
                r.artifact_json,
            ],
        )?;
        Ok(())
    }

    pub fn update_stage(
        &self,
        id: &RunId,
        stage: LoopStage,
        spent_usd: f64,
        artifact_json: &str,
    ) -> Result<()> {
        let now = now_rfc3339()?;
        self.conn.execute(
            "UPDATE runs SET stage = ?1, spent_usd = ?2, artifact = ?3, updated_at = ?4 WHERE id = ?5",
            params![stage_str(stage), spent_usd, artifact_json, now, id.to_string()],
        )?;
        Ok(())
    }

    pub fn finish(&self, id: &RunId, status: RunStatus, artifact_json: &str) -> Result<()> {
        let now = now_rfc3339()?;
        self.conn.execute(
            "UPDATE runs SET status = ?1, finished_at = ?2, updated_at = ?2, artifact = ?3 WHERE id = ?4",
            params![status.as_str(), now, artifact_json, id.to_string()],
        )?;
        Ok(())
    }

    pub fn get(&self, id: &RunId) -> Result<Option<RunRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, language, target_lang, target_mod, target_sym, stage, spent_usd,
                    started_at, updated_at, finished_at, status, artifact
             FROM runs WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id.to_string()])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_record(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn append_event(
        &self,
        id: &RunId,
        stage: LoopStage,
        kind: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        let seq: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM run_events WHERE run_id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .unwrap_or(1);
        let at = now_rfc3339()?;
        self.conn.execute(
            "INSERT INTO run_events(run_id, seq, at, stage, kind, detail)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![id.to_string(), seq, at, stage_str(stage), kind, detail],
        )?;
        Ok(())
    }

    /// Return runs that didn't reach a terminal state, oldest first. Useful
    /// for `ods explain --resume`.
    pub fn pending(&self) -> Result<Vec<RunRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, language, target_lang, target_mod, target_sym, stage, spent_usd,
                    started_at, updated_at, finished_at, status, artifact
             FROM runs WHERE status = 'in-progress' ORDER BY started_at ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_record(r)?);
        }
        Ok(out)
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<RunRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, language, target_lang, target_mod, target_sym, stage, spent_usd,
                    started_at, updated_at, finished_at, status, artifact
             FROM runs ORDER BY updated_at DESC LIMIT ?1",
        )?;
        let mut rows = stmt.query(params![limit as i64])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_record(r)?);
        }
        Ok(out)
    }
}

fn stage_str(stage: LoopStage) -> &'static str {
    match stage {
        LoopStage::TargetSelect => "target-select",
        LoopStage::Profile => "profile",
        LoopStage::RecipeRetrieve => "recipe-retrieve",
        LoopStage::Hypothesize => "hypothesize",
        LoopStage::Transform => "transform",
        LoopStage::Verify => "verify",
        LoopStage::Bench => "bench",
        LoopStage::Explain => "explain",
        LoopStage::Harvest => "harvest",
    }
}

fn parse_stage(s: &str) -> LoopStage {
    match s {
        "target-select" => LoopStage::TargetSelect,
        "profile" => LoopStage::Profile,
        "recipe-retrieve" => LoopStage::RecipeRetrieve,
        "hypothesize" => LoopStage::Hypothesize,
        "transform" => LoopStage::Transform,
        "verify" => LoopStage::Verify,
        "bench" => LoopStage::Bench,
        "explain" => LoopStage::Explain,
        "harvest" => LoopStage::Harvest,
        _ => LoopStage::TargetSelect,
    }
}

fn row_to_record(r: &rusqlite::Row<'_>) -> Result<RunRecord> {
    Ok(RunRecord {
        id: r.get(0)?,
        language: r.get(1)?,
        target: (r.get(2)?, r.get(3)?, r.get(4)?),
        stage: parse_stage(&r.get::<_, String>(5)?),
        spent_usd: r.get(6)?,
        started_at: r.get(7)?,
        updated_at: r.get(8)?,
        finished_at: r.get(9)?,
        status: RunStatus::from_str(&r.get::<_, String>(10)?),
        artifact_json: r.get(11)?,
    })
}

fn now_rfc3339() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RunId;

    fn fixture() -> RunRecord {
        RunRecord {
            id: RunId::new().to_string(),
            language: "rust".into(),
            target: ("rust".into(), "std::fs".into(), "read_dir".into()),
            stage: LoopStage::TargetSelect,
            spent_usd: 0.0,
            started_at: "2026-04-19T00:00:00Z".into(),
            updated_at: "2026-04-19T00:00:00Z".into(),
            finished_at: None,
            status: RunStatus::InProgress,
            artifact_json: "{}".into(),
        }
    }

    #[test]
    fn insert_update_finish_roundtrip() {
        let store = RunStore::in_memory().unwrap();
        let r = fixture();
        store.insert(&r).unwrap();
        let id = RunId(uuid::Uuid::parse_str(&r.id).unwrap());
        store
            .update_stage(&id, LoopStage::Verify, 0.12, "{\"partial\":true}")
            .unwrap();
        store
            .finish(&id, RunStatus::Completed, "{\"final\":true}")
            .unwrap();
        let got = store.get(&id).unwrap().unwrap();
        assert_eq!(got.status, RunStatus::Completed);
        assert_eq!(got.stage, LoopStage::Verify);
        assert!((got.spent_usd - 0.12).abs() < 1e-9);
    }

    #[test]
    fn pending_only_returns_in_progress() {
        let store = RunStore::in_memory().unwrap();
        let mut a = fixture();
        a.id = RunId::new().to_string();
        let mut b = fixture();
        b.id = RunId::new().to_string();
        store.insert(&a).unwrap();
        store.insert(&b).unwrap();
        let bid = RunId(uuid::Uuid::parse_str(&b.id).unwrap());
        store.finish(&bid, RunStatus::Completed, "{}").unwrap();
        let pending = store.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, a.id);
    }

    #[test]
    fn events_are_sequenced() {
        let store = RunStore::in_memory().unwrap();
        let r = fixture();
        store.insert(&r).unwrap();
        let id = RunId(uuid::Uuid::parse_str(&r.id).unwrap());
        store
            .append_event(&id, LoopStage::Profile, "start", None)
            .unwrap();
        store
            .append_event(&id, LoopStage::Profile, "done", Some("syscalls=42"))
            .unwrap();
        // Verify via raw SQL (we don't expose an events reader yet).
        let n: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM run_events WHERE run_id = ?1",
                params![r.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
    }
}
