use crate::schema::{PromotionState, Recipe, RecipeId};
use anyhow::{Context, Result};
use ods_core::OptimizationCategory;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::OnceLock;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS recipes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    language    TEXT NOT NULL,
    promotion   TEXT NOT NULL,
    body        TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recipes_lang_cat
    ON recipes(language, category);

CREATE INDEX IF NOT EXISTS idx_recipes_promotion
    ON recipes(promotion);

-- Bridge from text recipe ids to the integer rowids that sqlite-vec's
-- vec0 virtual table requires. Populated in lock-step with recipe_vec.
CREATE TABLE IF NOT EXISTS recipe_rowid (
    id    TEXT PRIMARY KEY,
    rowid INTEGER NOT NULL UNIQUE
);
"#;

// Issued separately from SCHEMA because sqlite-vec must be registered as an
// extension BEFORE the first Connection opens; see `ensure_vec_extension`.
const VEC_SCHEMA: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS recipe_vec USING vec0(
    embedding float[128] distance_metric=cosine
);
"#;

static VEC_INIT: OnceLock<()> = OnceLock::new();

/// Register the sqlite-vec extension ONCE, before any `Connection::open(…)`
/// call. The crate ships a statically-compiled extension init symbol that
/// SQLite loads via its auto-extension hook - we don't need `load_extension`
/// runtime support (which isn't enabled on rusqlite's `bundled` feature).
fn ensure_vec_extension() {
    VEC_INIT.get_or_init(|| unsafe {
        // `sqlite3_vec_init` is declared with a parameterless signature in
        // the sqlite-vec crate's FFI binding, but SQLite's auto-extension
        // API expects a function that takes (db, pzErrMsg, pApi). This is
        // the standard pattern for loading a statically-linked extension -
        // the extension's own prologue ignores the args.
        let fp: unsafe extern "C" fn(
            *mut rusqlite::ffi::sqlite3,
            *mut *mut std::os::raw::c_char,
            *const rusqlite::ffi::sqlite3_api_routines,
        ) -> std::os::raw::c_int = std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ());
        rusqlite::ffi::sqlite3_auto_extension(Some(fp));
    });
}

/// Structured query for the corpus. Vector similarity lives behind the
/// `embedding` column (populated once `sqlite-vec` is wired in stage 1);
/// the MVP uses the symbolic filter only.
#[derive(Debug, Clone, Default)]
pub struct RecipeQuery {
    pub language: Option<String>,
    pub category: Option<OptimizationCategory>,
    pub min_promotion: Option<PromotionState>,
    pub limit: Option<usize>,
}

pub struct Store {
    conn: Connection,
}

pub(crate) fn promotion_str(p: PromotionState) -> &'static str {
    match p {
        PromotionState::Hypothesized => "hypothesized",
        PromotionState::Seed => "seed",
        PromotionState::Candidate => "candidate",
        PromotionState::Validated => "validated",
        PromotionState::Corpus => "corpus",
        PromotionState::AntiPattern => "anti-pattern",
    }
}

/// Ranker weight for a promotion state. Higher is "trust more" during
/// retrieval. Hypothesized is surfaced but heavily down-weighted relative
/// to gate-validated states; AntiPattern-only records never drive
/// application (the Discoverer uses them as target-surfacing signals).
pub(crate) fn promotion_weight(p: PromotionState) -> f64 {
    match p {
        PromotionState::Corpus => 4.0,
        PromotionState::Validated => 3.0,
        PromotionState::Candidate => 2.0,
        PromotionState::Seed => 1.5,
        PromotionState::Hypothesized => 0.4,
        PromotionState::AntiPattern => 0.0,
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        ensure_vec_extension();
        let conn = Connection::open(path).context("open recipe store")?;
        conn.execute_batch(SCHEMA).context("initialise schema")?;
        conn.execute_batch(VEC_SCHEMA)
            .context("initialise vec schema")?;
        let store = Self { conn };
        store.backfill_vec_index_if_empty()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self> {
        ensure_vec_extension();
        let conn = Connection::open_in_memory().context("open in-memory store")?;
        conn.execute_batch(SCHEMA).context("initialise schema")?;
        conn.execute_batch(VEC_SCHEMA)
            .context("initialise vec schema")?;
        Ok(Self { conn })
    }

    /// One-shot migration for existing on-disk stores upgraded from the
    /// pre-Stage-7 schema: `recipes` has rows but `recipe_rowid` is empty,
    /// meaning we've never populated the vec0 index. Iterate every row and
    /// backfill both tables so subsequent retrievals use the KNN path.
    fn backfill_vec_index_if_empty(&self) -> Result<()> {
        let recipe_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM recipes", [], |r| r.get(0))?;
        let rowid_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM recipe_rowid", [], |r| r.get(0))?;
        if recipe_count == 0 || rowid_count > 0 {
            return Ok(());
        }
        tracing::info!(
            recipe_count,
            "backfilling sqlite-vec index from legacy recipe table"
        );
        let mut stmt = self.conn.prepare("SELECT body FROM recipes")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for body in rows {
            let recipe: Recipe = serde_json::from_str(&body)?;
            self.upsert_vec_only(&recipe)?;
        }
        Ok(())
    }

    /// Write the recipe's embedding into `recipe_vec` + `recipe_rowid` without
    /// touching the main `recipes` row. Used by the legacy-store backfill.
    fn upsert_vec_only(&self, recipe: &Recipe) -> Result<()> {
        let emb = recipe
            .embedding
            .clone()
            .unwrap_or_else(|| crate::embed::embed_recipe(recipe));
        self.write_vec_row(&recipe.id, &emb)
    }

    /// Allocate (or reuse) a stable integer rowid for a text recipe id and
    /// upsert its embedding into vec0.
    fn write_vec_row(&self, id: &RecipeId, embedding: &[f32]) -> Result<()> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT rowid FROM recipe_rowid WHERE id = ?1",
                params![id.0],
                |r| r.get(0),
            )
            .optional()?;
        let rowid = match existing {
            Some(r) => r,
            None => {
                let next: i64 = self.conn.query_row(
                    "SELECT COALESCE(MAX(rowid), 0) + 1 FROM recipe_rowid",
                    [],
                    |r| r.get(0),
                )?;
                self.conn.execute(
                    "INSERT INTO recipe_rowid(id, rowid) VALUES(?1, ?2)",
                    params![id.0, next],
                )?;
                next
            }
        };
        let bytes = f32_slice_to_bytes(embedding);
        // vec0 doesn't support ON CONFLICT / UPSERT; delete then insert.
        self.conn
            .execute("DELETE FROM recipe_vec WHERE rowid = ?1", params![rowid])?;
        self.conn.execute(
            "INSERT INTO recipe_vec(rowid, embedding) VALUES(?1, ?2)",
            params![rowid, bytes],
        )?;
        Ok(())
    }

    pub fn upsert(&self, recipe: &Recipe) -> Result<()> {
        // Always (re)populate the embedding so downstream cosine search is
        // consistent regardless of whether the recipe YAML shipped one.
        let mut recipe = recipe.clone();
        let embedding = crate::embed::embed_recipe(&recipe);
        recipe.embedding = Some(embedding.clone());
        let body = serde_json::to_string(&recipe)?;
        let updated_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?;
        self.conn
            .execute(
                "INSERT INTO recipes(id, name, category, language, promotion, body, updated_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                     name       = excluded.name,
                     category   = excluded.category,
                     language   = excluded.language,
                     promotion  = excluded.promotion,
                     body       = excluded.body,
                     updated_at = excluded.updated_at",
                params![
                    recipe.id.0,
                    recipe.name,
                    recipe.category.to_string(),
                    recipe.language,
                    promotion_str(recipe.promotion),
                    body,
                    updated_at,
                ],
            )
            .context("upsert recipe")?;
        // Keep the KNN index in sync with the canonical row.
        self.write_vec_row(&recipe.id, &embedding)
            .context("upsert vec row")?;
        Ok(())
    }

    /// Combined retrieval: symbolic pre-filter (language + promotion floor)
    /// then vector ranking against a free-form query, then a down-weight
    /// pass for recipes with accumulated negative history. Replaces the
    /// raw `search` call in most retrieval paths.
    ///
    /// The final score for each candidate is:
    ///   `cosine(query_emb, recipe_emb) * retrieval_score(recipe, 5)`
    /// with a small floor so non-matching but cheap-promotion recipes
    /// can still surface if nothing else ranks.
    pub fn retrieve(
        &self,
        language: Option<&str>,
        query_text: &str,
        limit: usize,
    ) -> Result<Vec<(Recipe, f32)>> {
        let q_emb = crate::embed::embed_query(query_text);
        match self.retrieve_via_vec(language, &q_emb, limit) {
            Ok(hits) if !hits.is_empty() => Ok(hits),
            // Fallback: vec0 was empty (fresh store before first upsert), or
            // the KNN returned fewer than expected because every vector got
            // post-filtered away. In either case fall back to the legacy
            // linear cosine over the symbolic candidate set so the caller
            // still sees something ranked sensibly.
            _ => self.retrieve_linear(language, &q_emb, limit),
        }
    }

    /// KNN path via sqlite-vec. Over-fetches by 5× the final limit so the
    /// post-filter (language + promotion floor + negative-history penalty)
    /// has room to drop irrelevant hits without leaving the final list short.
    fn retrieve_via_vec(
        &self,
        language: Option<&str>,
        q_emb: &[f32],
        limit: usize,
    ) -> Result<Vec<(Recipe, f32)>> {
        let knn_limit = limit.max(10).saturating_mul(5);
        let q_bytes = f32_slice_to_bytes(q_emb);
        let mut stmt = self.conn.prepare(
            "SELECT rowid, distance FROM recipe_vec \
             WHERE embedding MATCH ?1 \
             ORDER BY distance LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![q_bytes, knn_limit as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        if rows.is_empty() {
            return Ok(vec![]);
        }
        let mut scored: Vec<(Recipe, f32)> = Vec::with_capacity(rows.len());
        for (rowid, distance) in rows {
            let body: Option<String> = self
                .conn
                .query_row(
                    "SELECT r.body FROM recipe_rowid m \
                     JOIN recipes r ON r.id = m.id \
                     WHERE m.rowid = ?1",
                    params![rowid],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(body) = body else { continue };
            let recipe: Recipe = serde_json::from_str(&body)?;
            if let Some(lang) = language {
                if recipe.language != lang {
                    continue;
                }
            }
            // With distance_metric=cosine, distance = 1 - cosine_similarity,
            // so cosine ∈ [-1, 1] ⇒ distance ∈ [0, 2]. Recover similarity.
            let sim = (1.0 - distance as f32).clamp(-1.0, 1.0);
            let neg_weight = retrieval_score(&recipe, 5) as f32;
            scored.push((recipe, sim * neg_weight));
        }
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored.truncate(limit);
        Ok(scored)
    }

    /// In-memory linear cosine. Retained as the fallback and as a behavioural
    /// oracle for the KNN path's correctness test.
    fn retrieve_linear(
        &self,
        language: Option<&str>,
        q_emb: &[f32],
        limit: usize,
    ) -> Result<Vec<(Recipe, f32)>> {
        let candidates = self.search(&RecipeQuery {
            language: language.map(String::from),
            category: None,
            min_promotion: Some(PromotionState::Hypothesized),
            limit: Some(10_000),
        })?;
        if candidates.is_empty() {
            return Ok(vec![]);
        }
        let mut scored: Vec<(Recipe, f32)> = candidates
            .into_iter()
            .map(|r| {
                let emb = r
                    .embedding
                    .clone()
                    .unwrap_or_else(|| crate::embed::embed_recipe(&r));
                let sim = crate::embed::cosine(q_emb, &emb);
                let neg_weight = retrieval_score(&r, 5) as f32;
                (r, sim * neg_weight)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored.truncate(limit);
        Ok(scored)
    }

    pub fn get(&self, id: &RecipeId) -> Result<Option<Recipe>> {
        let mut stmt = self
            .conn
            .prepare("SELECT body FROM recipes WHERE id = ?1")?;
        let mut rows = stmt.query(params![id.0])?;
        if let Some(row) = rows.next()? {
            let body: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&body)?))
        } else {
            Ok(None)
        }
    }

    pub fn search(&self, query: &RecipeQuery) -> Result<Vec<Recipe>> {
        let mut sql = String::from("SELECT body FROM recipes WHERE 1=1");
        let mut args: Vec<String> = Vec::new();
        if let Some(lang) = &query.language {
            sql.push_str(" AND language = ?");
            args.push(lang.clone());
        }
        if let Some(cat) = &query.category {
            sql.push_str(" AND category = ?");
            args.push(cat.to_string());
        }
        // Promotion ordering:
        //   Hypothesized < Seed < Candidate < Validated < Corpus.
        // AntiPattern is outside the ordering - only fetched when explicitly
        // requested via `min_promotion = AntiPattern`.
        if let Some(min) = query.min_promotion {
            let accepted: &[PromotionState] = match min {
                PromotionState::Hypothesized => &[
                    PromotionState::Hypothesized,
                    PromotionState::Seed,
                    PromotionState::Candidate,
                    PromotionState::Validated,
                    PromotionState::Corpus,
                ],
                PromotionState::Seed => &[
                    PromotionState::Seed,
                    PromotionState::Candidate,
                    PromotionState::Validated,
                    PromotionState::Corpus,
                ],
                PromotionState::Candidate => &[
                    PromotionState::Candidate,
                    PromotionState::Validated,
                    PromotionState::Corpus,
                ],
                PromotionState::Validated => &[PromotionState::Validated, PromotionState::Corpus],
                PromotionState::Corpus => &[PromotionState::Corpus],
                PromotionState::AntiPattern => &[PromotionState::AntiPattern],
            };
            sql.push_str(" AND promotion IN (");
            for (i, s) in accepted.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push('?');
                args.push(promotion_str(*s).to_string());
            }
            sql.push(')');
        }
        sql.push_str(" ORDER BY updated_at DESC");
        if let Some(limit) = query.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            r.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for body in rows {
            let body = body?;
            out.push(serde_json::from_str(&body)?);
        }
        Ok(out)
    }

    pub fn count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM recipes", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn delete(&self, id: &RecipeId) -> Result<bool> {
        let rowid: Option<i64> = self
            .conn
            .query_row(
                "SELECT rowid FROM recipe_rowid WHERE id = ?1",
                params![id.0],
                |r| r.get(0),
            )
            .optional()?;
        let affected = self
            .conn
            .execute("DELETE FROM recipes WHERE id = ?1", params![id.0])?;
        if let Some(r) = rowid {
            self.conn
                .execute("DELETE FROM recipe_vec WHERE rowid = ?1", params![r])?;
            self.conn
                .execute("DELETE FROM recipe_rowid WHERE id = ?1", params![id.0])?;
        }
        Ok(affected > 0)
    }
}

/// Pack a slice of `f32` into a little-endian byte blob, the wire format
/// sqlite-vec expects for `float[N]` columns. Zero-dep: each float becomes
/// four consecutive bytes in little-endian order.
fn f32_slice_to_bytes(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for f in v {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

/// Retrieval score combining promotion strength with a negative-history
/// penalty. `neg_window` caps how many recent negatives can depress the
/// score, so one bad repo doesn't permanently silence an otherwise-good
/// recipe. Returned score is clamped to a minimum of 0.1× so even
/// heavily-penalised recipes remain surfaceable.
pub fn retrieval_score(recipe: &Recipe, neg_window: usize) -> f64 {
    let base = promotion_weight(recipe.promotion);
    let negatives = recipe.negative_history.len().min(neg_window) as f64;
    let penalty = 1.0 - (negatives / (neg_window as f64 + 1.0));
    (base * penalty.max(0.1)).max(0.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Transformation, Trigger, VerificationRecipe};

    fn fixture() -> Recipe {
        Recipe {
            id: RecipeId("rust-readdir-dtype".into()),
            name: "avoid stat when readdir d_type is sufficient".into(),
            category: OptimizationCategory::SyscallElimination,
            language: "rust".into(),
            promotion: PromotionState::Seed,
            trigger: Trigger {
                ast_pattern:
                    "(call function: (field_expression field: (field_identifier) @f) @call)".into(),
                profile_signature: vec!["syscall:stat>N/readdir-entry".into()],
                naive_alt_ratio_min: Some(1.2),
            },
            transformation: Transformation {
                steps: vec!["use DirEntry::file_type() before falling back to metadata()".into()],
            },
            verification: VerificationRecipe {
                test_selectors: vec![],
                property_seeds: vec![0xC0FFEE],
                fuzz_minutes: 5,
                semver_check: true,
            },
            benchmark_template: "criterion: bench_readdir".into(),
            success_history: vec![],
            negative_history: vec![],
            generalized_from: None,
            generalized_as: None,
            source_patch_ref: None,
            embedding: None,
        }
    }

    #[test]
    fn roundtrip_upsert_get() {
        let store = Store::in_memory().unwrap();
        let r = fixture();
        store.upsert(&r).unwrap();
        let got = store.get(&r.id).unwrap().unwrap();
        assert_eq!(got.name, r.name);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn filter_by_language_and_category() {
        let store = Store::in_memory().unwrap();
        store.upsert(&fixture()).unwrap();
        let hits = store
            .search(&RecipeQuery {
                language: Some("rust".into()),
                category: Some(OptimizationCategory::SyscallElimination),
                min_promotion: Some(PromotionState::Seed),
                limit: Some(10),
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn cli_list_all_defaults() {
        let store = Store::in_memory().unwrap();
        store.upsert(&fixture()).unwrap();
        // Mirrors the CLI's `recipes list` with no flags.
        let hits = store
            .search(&RecipeQuery {
                language: None,
                category: None,
                min_promotion: Some(PromotionState::Seed),
                limit: Some(200),
            })
            .unwrap();
        assert_eq!(hits.len(), 1, "expected 1 hit, got {}", hits.len());
    }

    fn mk_recipe(id: &str, text: &str) -> Recipe {
        Recipe {
            id: RecipeId(id.into()),
            name: text.into(),
            category: OptimizationCategory::SyscallElimination,
            language: "rust".into(),
            promotion: PromotionState::Seed,
            trigger: Trigger {
                ast_pattern: "".into(),
                profile_signature: vec![text.into()],
                naive_alt_ratio_min: None,
            },
            transformation: Transformation {
                steps: vec![text.into()],
            },
            verification: VerificationRecipe {
                test_selectors: vec![],
                property_seeds: vec![],
                fuzz_minutes: 0,
                semver_check: false,
            },
            benchmark_template: "".into(),
            success_history: vec![],
            negative_history: vec![],
            generalized_from: None,
            generalized_as: None,
            source_patch_ref: None,
            embedding: None,
        }
    }

    #[test]
    fn knn_agrees_with_linear_oracle() {
        // Populate 200 synthetic recipes, then for several queries assert
        // that the KNN path and the linear-cosine path return the same top-5
        // (order may reorder within a tie but the *set* must match).
        let store = Store::in_memory().unwrap();
        for i in 0..200 {
            let text = format!("synthetic optimisation pattern number {i} rust");
            store.upsert(&mk_recipe(&format!("r{i}"), &text)).unwrap();
        }
        let queries = [
            "optimisation pattern number 42",
            "rust synthetic",
            "number 17 rust",
            "pattern 150",
        ];
        for q in queries {
            let knn_hits = store.retrieve(Some("rust"), q, 5).unwrap();
            let q_emb = crate::embed::embed_query(q);
            let linear_hits = store.retrieve_linear(Some("rust"), &q_emb, 5).unwrap();
            let knn_ids: std::collections::HashSet<String> =
                knn_hits.iter().map(|(r, _)| r.id.0.clone()).collect();
            let lin_ids: std::collections::HashSet<String> =
                linear_hits.iter().map(|(r, _)| r.id.0.clone()).collect();
            assert_eq!(
                knn_ids, lin_ids,
                "KNN and linear disagreed on top-5 for query {q:?}: knn={knn_ids:?} linear={lin_ids:?}"
            );
        }
    }

    #[test]
    fn delete_removes_vec_row() {
        let store = Store::in_memory().unwrap();
        store.upsert(&fixture()).unwrap();
        // Sanity: the KNN path finds it.
        let hits = store.retrieve(Some("rust"), "readdir stat", 3).unwrap();
        assert!(!hits.is_empty());
        assert!(store.delete(&fixture().id).unwrap());
        let after = store.retrieve(Some("rust"), "readdir stat", 3).unwrap();
        assert!(
            after.is_empty(),
            "expected empty after delete, got {after:?}"
        );
    }
}
