//! Project-level policy, read from `carve.toml` (or `.carve.toml`) next to the
//! product's `Cargo.toml`. CLI flags override config; config overrides built-in
//! defaults.
//!
//! ```toml
//! # carve.toml
//! transitive    = true     # vendor/slice the whole closure (deps of deps)
//! min_reduction = 10.0     # revert a slice below this LOC % to upstream
//! budget        = 0        # per-crate item-slice refinement checks
//!
//! # Never vendor or slice these — keep them as normal upstream dependencies.
//! # (e.g. crates you'd rather track upstream, or ones that don't slice well.)
//! exclude = ["openssl-sys", "ring"]
//! ```

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub transitive: Option<bool>,
    pub min_reduction: Option<f64>,
    pub budget: Option<usize>,
    /// Crate names that carve must leave on the upstream registry.
    pub exclude: Vec<String>,
}

impl Config {
    /// Load `carve.toml` / `.carve.toml` from the project root, if present.
    pub fn load(root: &Path) -> Self {
        for name in ["carve.toml", ".carve.toml"] {
            let p = root.join(name);
            match std::fs::read_to_string(&p) {
                Ok(text) => match toml::from_str::<Config>(&text) {
                    Ok(cfg) => {
                        tracing::info!(config = %p.display(), exclude = cfg.exclude.len(), "loaded carve config");
                        return cfg;
                    }
                    Err(e) => tracing::warn!(error = %e, "ignoring malformed {name}"),
                },
                Err(_) => continue,
            }
        }
        Config::default()
    }
}
