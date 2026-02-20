mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;

use axum::{
    routing::{get, post},
    Router,
};
use std::time::Duration;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::Config;
use handlers::{create_task, delete_task, get_task, get_tasks, health_check, update_task};
use middleware::{create_cors_layer, create_trace_layer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_service_sandbox=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenv::dotenv().ok();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Starting server on {}", config.addr());

    // Create database pool
    let pool = db::create_pool(&config.database_url).await?;
    tracing::info!("Database connection established");

    // Run migrations
    db::run_migrations(&pool).await?;

    // Build application routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/tasks", post(create_task).get(get_tasks))
        .route(
            "/api/tasks/:id",
            get(get_task).put(update_task).delete(delete_task),
        )
        .layer(create_trace_layer())
        .layer(create_cors_layer())
        .with_state(pool);

    // Create server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(&config.addr()).await?;
    tracing::info!("Listening on {}", config.addr());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            tracing::info!("Received terminate signal");
        },
    }

    tracing::info!("Starting graceful shutdown");
    tokio::time::sleep(Duration::from_secs(1)).await;
}
