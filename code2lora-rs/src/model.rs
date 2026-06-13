//! Target base-model description. Code2LoRA generates an adapter for a *frozen*
//! base LLM; to emit a PEFT-compatible adapter we only need that model's
//! projection dimensions, which we read from its HuggingFace `config.json`.
//!
//! The paper's backbone is Qwen2.5-Coder-1.5B; its real dimensions are baked in
//! as the default so the crate works offline, but `ModelSpec::from_config` can
//! target any standard dense-attention transformer.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// The seven LoRA-targeted projection types (paper §3.2: all attention + MLP
/// projections, not just Q/V). Order is fixed and used everywhere.
pub const MODULE_TYPES: [ModuleType; 7] = [
    ModuleType::Q,
    ModuleType::K,
    ModuleType::V,
    ModuleType::O,
    ModuleType::Gate,
    ModuleType::Up,
    ModuleType::Down,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleType {
    Q,
    K,
    V,
    O,
    Gate,
    Up,
    Down,
}

impl ModuleType {
    /// HuggingFace projection name, e.g. `q_proj`.
    pub fn proj_name(&self) -> &'static str {
        match self {
            ModuleType::Q => "q_proj",
            ModuleType::K => "k_proj",
            ModuleType::V => "v_proj",
            ModuleType::O => "o_proj",
            ModuleType::Gate => "gate_proj",
            ModuleType::Up => "up_proj",
            ModuleType::Down => "down_proj",
        }
    }

    /// Submodule the projection lives in: `self_attn` or `mlp`.
    pub fn block(&self) -> &'static str {
        match self {
            ModuleType::Q | ModuleType::K | ModuleType::V | ModuleType::O => "self_attn",
            ModuleType::Gate | ModuleType::Up | ModuleType::Down => "mlp",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModelSpec {
    pub name: String,
    pub hidden_size: usize,
    pub intermediate_size: usize,
    pub num_layers: usize,
    pub num_heads: usize,
    pub num_kv_heads: usize,
    pub head_dim: usize,
}

impl ModelSpec {
    /// Real dimensions of Qwen2.5-Coder-1.5B (the paper's frozen backbone).
    pub fn qwen25_coder_1_5b() -> Self {
        let hidden = 1536;
        let heads = 12;
        ModelSpec {
            name: "Qwen/Qwen2.5-Coder-1.5B".to_string(),
            hidden_size: hidden,
            intermediate_size: 8960,
            num_layers: 28,
            num_heads: heads,
            num_kv_heads: 2,
            head_dim: hidden / heads, // 128
        }
    }

    pub fn from_config(path: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        struct Cfg {
            #[serde(default)]
            _name_or_path: Option<String>,
            hidden_size: usize,
            intermediate_size: usize,
            num_hidden_layers: usize,
            num_attention_heads: usize,
            #[serde(default)]
            num_key_value_heads: Option<usize>,
            #[serde(default)]
            head_dim: Option<usize>,
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Cfg = serde_json::from_str(&text).context("parsing config.json")?;
        let head_dim = cfg
            .head_dim
            .unwrap_or(cfg.hidden_size / cfg.num_attention_heads);
        Ok(ModelSpec {
            name: path
                .parent()
                .and_then(|p| p.file_name())
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "custom".to_string()),
            hidden_size: cfg.hidden_size,
            intermediate_size: cfg.intermediate_size,
            num_layers: cfg.num_hidden_layers,
            num_heads: cfg.num_attention_heads,
            num_kv_heads: cfg.num_key_value_heads.unwrap_or(cfg.num_attention_heads),
            head_dim,
        })
    }

    /// LoRA matrix dimensions for a module type.
    ///
    /// PEFT convention: for a linear layer with weight `W ∈ [out, in]`,
    /// `lora_A ∈ [r, in]` and `lora_B ∈ [out, r]`, with `ΔW = (α/r)·B·A`.
    /// Returns `(in_features, out_features)`.
    pub fn lora_dims(&self, m: ModuleType) -> (usize, usize) {
        let q_out = self.num_heads * self.head_dim;
        let kv_out = self.num_kv_heads * self.head_dim;
        match m {
            ModuleType::Q => (self.hidden_size, q_out),
            ModuleType::K => (self.hidden_size, kv_out),
            ModuleType::V => (self.hidden_size, kv_out),
            ModuleType::O => (q_out, self.hidden_size),
            ModuleType::Gate => (self.hidden_size, self.intermediate_size),
            ModuleType::Up => (self.hidden_size, self.intermediate_size),
            ModuleType::Down => (self.intermediate_size, self.hidden_size),
        }
    }
}
