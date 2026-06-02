//! Observability setup.
//!
//! `carve` instruments the whole pipeline with `tracing` spans. By default it
//! prints human-readable logs to stderr; `--log-json` switches to structured
//! NDJSON so an agent run can be ingested and replayed. The `RUST_LOG` env var
//! (e.g. `RUST_LOG=carve=debug`) controls verbosity.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init(verbose: bool, json: bool) {
    let default = if verbose { "carve=debug,info" } else { "carve=info,warn" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    if json {
        let layer = fmt::layer()
            .json()
            .with_current_span(true)
            .with_writer(std::io::stderr);
        tracing_subscriber::registry().with(filter).with(layer).init();
    } else {
        let layer = fmt::layer()
            .with_target(false)
            .with_writer(std::io::stderr);
        tracing_subscriber::registry().with(filter).with(layer).init();
    }
}
