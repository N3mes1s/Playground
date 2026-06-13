//! Real neural repository embedder (paper §3.1 uses a frozen
//! Qwen3-Embedding-0.6B). This is the semantic counterpart to the default
//! feature-hashing `HashEmbedder`: it loads a frozen BERT-family sentence
//! embedder via `candle` and produces contextual embeddings, so the generated
//! LoRA is conditioned on the *meaning* of the code, not just token statistics.
//!
//! Gated behind the `neural` cargo feature to keep the default build dependency-
//! free and offline. Default model is `BAAI/bge-large-en-v1.5` (1024-dim, which
//! matches `EMBED_DIM`).

use crate::embedder::Embedder;
use crate::tensor::l2_normalize;
use anyhow::{Context, Result};
use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use tokenizers::Tokenizer;

const MAX_TOKENS: usize = 512;

pub struct NeuralEmbedder {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
    dim: usize,
}

impl NeuralEmbedder {
    /// Load a frozen BERT embedder. `model_id` may be a HuggingFace Hub id
    /// (downloaded + cached) or a local directory containing `config.json`,
    /// `tokenizer.json`, and `model.safetensors`.
    pub fn load(model_id: &str) -> Result<Self> {
        let dir = std::path::Path::new(model_id);
        let (cfg_path, tok_path, weights) = if dir.is_dir() {
            (
                dir.join("config.json"),
                dir.join("tokenizer.json"),
                dir.join("model.safetensors"),
            )
        } else {
            use hf_hub::api::sync::Api;
            let api = Api::new().context("init hf-hub api")?;
            let repo = api.model(model_id.to_string());
            (
                repo.get("config.json").context("download config.json")?,
                repo.get("tokenizer.json").context("download tokenizer.json")?,
                repo.get("model.safetensors").context("download model.safetensors")?,
            )
        };

        let config: Config =
            serde_json::from_slice(&std::fs::read(&cfg_path)?).context("parse bert config")?;
        let tokenizer = Tokenizer::from_file(&tok_path).map_err(anyhow::Error::msg)?;
        let device = Device::Cpu;
        let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[weights], DTYPE, &device)? };
        let model = BertModel::load(vb, &config).context("load bert model")?;
        let dim = config.hidden_size;
        Ok(NeuralEmbedder {
            model,
            tokenizer,
            device,
            dim,
        })
    }

    pub fn load_default() -> Result<Self> {
        Self::load("BAAI/bge-large-en-v1.5")
    }

    fn embed_inner(&self, text: &str) -> Result<Vec<f32>> {
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(anyhow::Error::msg)?;
        let mut ids: Vec<u32> = enc.get_ids().to_vec();
        let mut mask: Vec<u32> = enc.get_attention_mask().to_vec();
        ids.truncate(MAX_TOKENS);
        mask.truncate(MAX_TOKENS);
        if ids.is_empty() {
            return Ok(vec![0.0; self.dim]);
        }
        let t = ids.len();
        let input_ids = Tensor::new(ids.as_slice(), &self.device)?.unsqueeze(0)?; // [1,T]
        let type_ids = input_ids.zeros_like()?;
        let attn = Tensor::new(mask.as_slice(), &self.device)?.unsqueeze(0)?; // [1,T]

        let hidden = self.model.forward(&input_ids, &type_ids, Some(&attn))?; // [1,T,H]
        // attention-masked mean pooling (mask has >=1 set token here)
        let mask_f = attn.to_dtype(DTYPE)?.unsqueeze(2)?; // [1,T,1]
        let summed = hidden.broadcast_mul(&mask_f)?.sum(1)?; // [1,H]
        let counts = mask_f.sum(1)?; // [1,1]
        let mean = summed.broadcast_div(&counts)?; // [1,H]
        let mut v = mean.flatten_all()?.to_vec1::<f32>()?;
        let _ = t;
        l2_normalize(&mut v);
        Ok(v)
    }
}

impl Embedder for NeuralEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        self.embed_inner(text).unwrap_or_else(|_| vec![0.0; self.dim])
    }
    fn dim(&self) -> usize {
        self.dim
    }
}
