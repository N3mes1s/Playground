use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;
use validator::Validate;

use crate::{
    error::{AppError, Result},
    models::{CreateTask, PaginatedResponse, PaginationParams, Task, UpdateTask},
};

// Health check handler
pub async fn health_check() -> &'static str {
    "OK"
}

// Create a new task
pub async fn create_task(
    State(pool): State<SqlitePool>,
    Json(payload): Json<CreateTask>,
) -> Result<(StatusCode, Json<Task>)> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let task = sqlx::query_as::<_, Task>(
        r#"
        INSERT INTO tasks (id, title, description, completed, created_at, updated_at)
        VALUES (?, ?, ?, 0, ?, ?)
        RETURNING id, title, description, completed, created_at, updated_at
        "#,
    )
    .bind(&id)
    .bind(&payload.title)
    .bind(&payload.description)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .fetch_one(&pool)
    .await?;

    Ok((StatusCode::CREATED, Json(task)))
}

// Get all tasks with pagination
pub async fn get_tasks(
    State(pool): State<SqlitePool>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<Task>>> {
    let page = params.page.max(1);
    let per_page = params.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tasks")
        .fetch_one(&pool)
        .await?;

    let tasks = sqlx::query_as::<_, Task>(
        "SELECT id, title, description, completed, created_at, updated_at
         FROM tasks
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await?;

    Ok(Json(PaginatedResponse {
        data: tasks,
        page,
        per_page,
        total: total.0,
    }))
}

// Get a single task by ID
pub async fn get_task(
    State(pool): State<SqlitePool>,
    Path(id): Path<String>,
) -> Result<Json<Task>> {
    let task = sqlx::query_as::<_, Task>(
        "SELECT id, title, description, completed, created_at, updated_at
         FROM tasks
         WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Task with id {} not found", id)))?;

    Ok(Json(task))
}

// Update a task
pub async fn update_task(
    State(pool): State<SqlitePool>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateTask>,
) -> Result<Json<Task>> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Check if task exists
    let existing = sqlx::query_as::<_, Task>(
        "SELECT id, title, description, completed, created_at, updated_at FROM tasks WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Task with id {} not found", id)))?;

    let title = payload.title.unwrap_or(existing.title);
    let description = payload.description.or(existing.description);
    let completed = payload.completed.unwrap_or(existing.completed);
    let now = Utc::now();

    let task = sqlx::query_as::<_, Task>(
        r#"
        UPDATE tasks
        SET title = ?, description = ?, completed = ?, updated_at = ?
        WHERE id = ?
        RETURNING id, title, description, completed, created_at, updated_at
        "#,
    )
    .bind(&title)
    .bind(&description)
    .bind(completed)
    .bind(now.to_rfc3339())
    .bind(&id)
    .fetch_one(&pool)
    .await?;

    Ok(Json(task))
}

// Delete a task
pub async fn delete_task(
    State(pool): State<SqlitePool>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let result = sqlx::query("DELETE FROM tasks WHERE id = ?")
        .bind(&id)
        .execute(&pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Task with id {} not found", id)));
    }

    Ok(StatusCode::NO_CONTENT)
}
