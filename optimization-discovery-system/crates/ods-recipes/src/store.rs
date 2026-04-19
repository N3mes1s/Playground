use crate::schema::{PromotionState, Recipe, RecipeId};
use anyhow::{Context, Result};
use ods_core::OptimizationCategory;
use rusqlite::{params, Connection};
use std::path::Path;

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
"#;

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

fn promotion_str(p: PromotionState) -> &'static str {
    match p {
        PromotionState::Seed => "seed",
        PromotionState::Candidate => "candidate",
        PromotionState::Validated => "validated",
        PromotionState::Corpus => "corpus",
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open recipe store")?;
        conn.execute_batch(SCHEMA).context("initialise schema")?;
        Ok(Self { conn })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("open in-memory store")?;
        conn.execute_batch(SCHEMA).context("initialise schema")?;
        Ok(Self { conn })
    }

    pub fn upsert(&self, recipe: &Recipe) -> Result<()> {
        // Always (re)populate the embedding so downstream cosine search is
        // consistent regardless of whether the recipe YAML shipped one.
        let mut recipe = recipe.clone();
        recipe.embedding = Some(crate::embed::embed_recipe(&recipe));
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
        Ok(())
    }

    /// Cosine-similarity vector search. Uses the hash-based embedding in
    /// `ods_recipes::embed` and returns recipes sorted by descending score.
    /// Callers can pre-filter with [`Self::search`] first for language /
    /// category symbolic constraints.
    pub fn vector_search(
        &self,
        query: &str,
        candidates: &[Recipe],
        limit: usize,
    ) -> Vec<(Recipe, f32)> {
        let q = crate::embed::embed_query(query);
        let mut scored: Vec<(Recipe, f32)> = candidates
            .iter()
            .map(|r| {
                let emb = r
                    .embedding
                    .clone()
                    .unwrap_or_else(|| crate::embed::embed_recipe(r));
                let sim = crate::embed::cosine(&q, &emb);
                (r.clone(), sim)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored.truncate(limit);
        scored
    }

    pub fn get(&self, id: &RecipeId) -> Result<Option<Recipe>> {
        let mut stmt = self.conn.prepare("SELECT body FROM recipes WHERE id = ?1")?;
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
        // Promotion ordering: seed < candidate < validated < corpus.
        if let Some(min) = query.min_promotion {
            let accepted: &[PromotionState] = match min {
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
                PromotionState::Validated => {
                    &[PromotionState::Validated, PromotionState::Corpus]
                }
                PromotionState::Corpus => &[PromotionState::Corpus],
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
        let rows = stmt.query_map(
            rusqlite::params_from_iter(args.iter()),
            |r| r.get::<_, String>(0),
        )?;
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
                ast_pattern: "(call function: (field_expression field: (field_identifier) @f) @call)"
                    .into(),
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
}
