//! End-to-end smoke test for the orchestrator.
//!
//! Constructs a minimal Rust crate in a tempdir, runs the orchestrator in
//! dev mode (no LLM), and verifies:
//!   * a SQLite row lands in `.ods/runs.db` with status=Completed
//!   * the mirrored JSON artifact is written
//!   * `stages_completed` includes every stage
//!   * an imported seed recipe is retrieved and reflected in
//!     `recipes_applied`
//!
//! The test only shells out to `cargo` (build + test + bench). It falls back
//! gracefully when subprocess steps fail (noisy CI); the invariants it
//! cares about are the state machine advancing through every stage and
//! the SQLite + JSON artifacts being present.

use ods_agents::Orchestrator;
use ods_core::{LoopStage, Mode, RunStore, TargetSig};
use ods_lang_rust::RustAdapter;
use ods_recipes::{
    schema::{PromotionState, Recipe, RecipeId, Transformation, Trigger, VerificationRecipe},
    Store,
};
use std::sync::Arc;

fn write_min_crate(dir: &std::path::Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "ods-smoke"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n\
         #[cfg(test)] mod t { #[test] fn add_works() { assert_eq!(super::add(1, 2), 3); } }\n",
    )
    .unwrap();
}

fn seed_recipe() -> Recipe {
    Recipe {
        id: RecipeId("rust-smoke-seed".into()),
        name: "smoke seed".into(),
        category: ods_core::OptimizationCategory::SyscallElimination,
        language: "rust".into(),
        promotion: PromotionState::Seed,
        trigger: Trigger {
            ast_pattern: "".into(),
            profile_signature: vec!["syscall:read".into()],
            naive_alt_ratio_min: None,
        },
        transformation: Transformation {
            steps: vec!["noop".into()],
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

#[tokio::test]
async fn orchestrator_end_to_end_dev_mode() {
    let dir = tempfile::tempdir().unwrap();
    write_min_crate(dir.path());

    let store_path = dir.path().join(".ods/recipes.db");
    std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
    let store = Arc::new(Store::open(&store_path).unwrap());
    store.upsert(&seed_recipe()).unwrap();

    let adapter = Arc::new(RustAdapter::new());
    let target = TargetSig {
        language: "rust".into(),
        module: "smoke".into(),
        symbol: "add".into(),
        arity: Some(2),
    };
    let orch = Orchestrator::new(adapter, store, dir.path().to_path_buf(), Mode::Dev);
    // Don't invoke the LLM path - we're exercising the pure measurement loop.
    let art = orch.run(target, false).await.expect("orchestrator ok");

    // Every stage should have been reached.
    for stage in [
        LoopStage::TargetSelect,
        LoopStage::Profile,
        LoopStage::RecipeRetrieve,
        LoopStage::Hypothesize,
        LoopStage::Transform,
        LoopStage::Verify,
        LoopStage::Bench,
        LoopStage::Explain,
        LoopStage::Harvest,
    ] {
        assert!(
            art.stages_completed.contains(&stage),
            "missing stage {:?}",
            stage
        );
    }

    // Seed recipe should surface (planner routes via category).
    assert!(
        art.recipes_applied.iter().any(|id| id == "rust-smoke-seed"),
        "expected seed recipe to be retrieved, got {:?}",
        art.recipes_applied
    );

    // SQLite mirror.
    let runs_db = dir.path().join(".ods/runs.db");
    assert!(runs_db.exists(), "runs.db was not created");
    let rs = RunStore::open(&runs_db).unwrap();
    let recent = rs.recent(5).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].status, ods_core::RunStatus::Completed);

    // JSON mirror.
    let runs_dir = dir.path().join(".ods/runs");
    assert!(runs_dir.exists());
    let entries: Vec<_> = std::fs::read_dir(&runs_dir).unwrap().collect();
    assert!(!entries.is_empty(), "no JSON artifact written");
}
