use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub completed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateTask {
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateTask {
    #[validate(length(min = 1, max = 255))]
    pub title: Option<String>,
    pub description: Option<String>,
    pub completed: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_per_page")]
    pub per_page: i64,
}

fn default_page() -> i64 {
    1
}

fn default_per_page() -> i64 {
    10
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
}
