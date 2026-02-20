use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

pub async fn create_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            completed BOOLEAN NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    tracing::info!("Database migrations completed");
    Ok(())
}
