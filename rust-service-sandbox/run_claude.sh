#!/bin/sh
export HOME=/tmp
unset CLAUDECODE
unset CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR
exec /opt/node22/bin/node /opt/node22/bin/claude \
  -p "You are in an empty directory at /home/user/Playground/rust-service-sandbox. Create a full-featured Rust REST API service. Use axum, tokio, serde, sqlx with SQLite, tower-http. Task management API: CRUD /api/tasks, GET /health, error handling, logging middleware, CORS, graceful shutdown, DB migrations, env config, validation, pagination. Create Cargo.toml and all src/ files. Run cargo init first, then write the code. Run cargo check at the end." \
  --allowedTools "Bash,Write,Edit,Read,Glob,Grep" \
  --output-format text
