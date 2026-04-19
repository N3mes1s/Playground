//! Recipe corpus: storage, retrieval, promotion.
//!
//! Recipes are the unit of accumulated knowledge. Each successful run harvests
//! a candidate recipe; repeated successes across independent repositories
//! promote it into the default corpus.

pub mod embed;
pub mod promote;
pub mod schema;
pub mod score;
pub mod store;

pub use embed::{cosine, embed_query, embed_recipe, EMBED_DIM};
pub use promote::{
    promote_on_negative, promote_on_success, PromotionOutcome, PromotionRules,
};
pub use schema::{
    NegativeOutcome, NegativeRecord, PromotionState, Recipe, RecipeId, SuccessRecord,
    Transformation, Trigger, VerificationRecipe,
};
pub use score::{score_recipes, ScoredRecipe};
pub use store::{retrieval_score, RecipeQuery, Store};
