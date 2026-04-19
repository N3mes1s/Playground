//! Recipe corpus: storage, retrieval, promotion.
//!
//! Recipes are the unit of accumulated knowledge. Each successful run harvests
//! a candidate recipe; repeated successes across independent repositories
//! promote it into the default corpus.

pub mod promote;
pub mod schema;
pub mod score;
pub mod store;

pub use promote::{promote_on_success, PromotionOutcome, PromotionRules};
pub use schema::{
    PromotionState, Recipe, RecipeId, SuccessRecord, Transformation, Trigger, VerificationRecipe,
};
pub use score::{score_recipes, ScoredRecipe};
pub use store::{RecipeQuery, Store};
