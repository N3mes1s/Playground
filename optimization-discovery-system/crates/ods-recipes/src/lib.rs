//! Recipe corpus: storage, retrieval, promotion.
//!
//! Recipes are the unit of accumulated knowledge. Each successful run harvests
//! a candidate recipe; repeated successes across independent repositories
//! promote it into the default corpus.

pub mod schema;
pub mod store;

pub use schema::{
    PromotionState, Recipe, RecipeId, SuccessRecord, Transformation, Trigger, VerificationRecipe,
};
pub use store::{RecipeQuery, Store};
