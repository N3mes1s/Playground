//! Benchmark proving the BM25 optimization the ods dogfood agent spotted.
//!
//! Pre-change cost model: for each of N docs and each of T query terms, we
//!   (a) linearly scan the doc's token list to count tf,
//!   (b) linearly scan *all* docs' token lists to count df.
//! -> O(N² · T · L).
//!
//! Post-change: per-doc TF maps (built once) + per-unique-query-term IDF
//! (computed once).
//! -> O(N · (L + T_unique)).
//!
//! This bench picks a corpus size where the asymptotic difference is
//! visible without making the test suite slow.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ods_core::OptimizationCategory;
use ods_recipes::{
    schema::{PromotionState, RecipeId, Transformation, Trigger, VerificationRecipe},
    score_recipes, Recipe,
};

fn make_corpus(n: usize) -> Vec<Recipe> {
    let catalog = [
        "avoid stat on readdir entries",
        "fast path for ascii path join",
        "cache regex compilation",
        "eliminate intermediate vec allocation",
        "hoist loop invariant encoding",
        "replace forward scan with backward scan",
        "skip validation under ascii",
        "memoize pure function call",
    ];
    (0..n)
        .map(|i| Recipe {
            id: RecipeId(format!("r{i}")),
            name: format!("{} {}", catalog[i % catalog.len()], i),
            category: OptimizationCategory::SyscallElimination,
            language: "rust".into(),
            promotion: PromotionState::Seed,
            trigger: Trigger {
                ast_pattern: String::new(),
                profile_signature: vec![format!("syscall:stat tag{}", i % 4)],
                naive_alt_ratio_min: None,
            },
            transformation: Transformation {
                steps: vec![format!("step with extra vocabulary token{}", i % 32)],
            },
            verification: VerificationRecipe {
                test_selectors: vec![],
                property_seeds: vec![],
                fuzz_minutes: 0,
                semver_check: false,
            },
            benchmark_template: String::new(),
            success_history: vec![],
            embedding: None,
        })
        .collect()
}

fn bench_score_recipes(c: &mut Criterion) {
    for n in [32usize, 256, 1024] {
        let corpus = make_corpus(n);
        c.bench_function(&format!("score_recipes/{n}_docs"), |b| {
            b.iter(|| {
                let r = score_recipes(
                    black_box(&corpus),
                    black_box("readdir stat syscall ascii path"),
                );
                black_box(r);
            });
        });
    }
}

criterion_group!(benches, bench_score_recipes);
criterion_main!(benches);
