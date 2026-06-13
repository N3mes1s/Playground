//! Export a generated [`LoraAdapter`] to a standard HuggingFace **PEFT** adapter
//! directory (`adapter_config.json` + `adapter_model.safetensors`) that loads
//! directly with `PeftModel.from_pretrained`, vLLM `--lora-modules`, or SGLang.
//!
//! The hypernetwork emits one (A, B) pair per module type, *shared across all
//! layers* (paper §3.2). PEFT stores per-layer tensors, so we replicate each
//! shared pair into every transformer layer under the HF key convention:
//!   base_model.model.model.layers.{i}.{block}.{proj}.lora_{A,B}.weight

use crate::hypernet::LoraAdapter;
use crate::model::ModelSpec;
use anyhow::{Context, Result};
use safetensors::tensor::{Dtype, TensorView};
use std::collections::HashMap;
use std::path::Path;

fn f32_to_le_bytes(data: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 4);
    for &x in data {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// Write a PEFT adapter directory for `adapter` targeting `spec`.
/// Returns the number of tensors written.
pub fn export_peft(adapter: &LoraAdapter, spec: &ModelSpec, out_dir: &Path) -> Result<usize> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating {}", out_dir.display()))?;

    // Build owned byte buffers + shapes first; TensorViews borrow them.
    let mut names: Vec<String> = Vec::new();
    let mut shapes: Vec<Vec<usize>> = Vec::new();
    let mut buffers: Vec<Vec<u8>> = Vec::new();

    for layer in 0..spec.num_layers {
        for (m, a, b) in &adapter.mats {
            let prefix = format!(
                "base_model.model.model.layers.{}.{}.{}",
                layer,
                m.block(),
                m.proj_name()
            );
            // lora_A: [r, in]
            names.push(format!("{prefix}.lora_A.weight"));
            shapes.push(vec![a.rows, a.cols]);
            buffers.push(f32_to_le_bytes(&a.data));
            // lora_B: [out, r]
            names.push(format!("{prefix}.lora_B.weight"));
            shapes.push(vec![b.rows, b.cols]);
            buffers.push(f32_to_le_bytes(&b.data));
        }
    }

    let tensors: Vec<(String, TensorView)> = names
        .iter()
        .zip(shapes.iter())
        .zip(buffers.iter())
        .map(|((name, shape), buf)| {
            let tv = TensorView::new(Dtype::F32, shape.clone(), buf)
                .expect("valid tensor view");
            (name.clone(), tv)
        })
        .collect();

    let n = tensors.len();
    let st_path = out_dir.join("adapter_model.safetensors");
    safetensors::serialize_to_file(tensors, &None, &st_path)
        .with_context(|| format!("writing {}", st_path.display()))?;

    write_adapter_config(adapter, spec, out_dir)?;
    Ok(n)
}

fn write_adapter_config(adapter: &LoraAdapter, spec: &ModelSpec, out_dir: &Path) -> Result<()> {
    let target_modules: Vec<String> = adapter
        .mats
        .iter()
        .map(|(m, _, _)| m.proj_name().to_string())
        .collect();

    let cfg = serde_json::json!({
        "alpha_pattern": {},
        "auto_mapping": null,
        "base_model_name_or_path": spec.name,
        "bias": "none",
        "fan_in_fan_out": false,
        "inference_mode": true,
        "init_lora_weights": true,
        "layers_pattern": null,
        "layers_to_transform": null,
        "lora_alpha": adapter.alpha as i64,
        "lora_dropout": 0.0,
        "modules_to_save": null,
        "peft_type": "LORA",
        "r": adapter.rank,
        "rank_pattern": {},
        "revision": null,
        "target_modules": target_modules,
        "task_type": "CAUSAL_LM",
        "use_dora": false,
        "use_rslora": false,
    });

    let path = out_dir.join("adapter_config.json");
    std::fs::write(&path, serde_json::to_string_pretty(&cfg)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read back a PEFT safetensors file into a map of name -> (shape, data).
/// Used by `verify` to prove the artifact round-trips and matches the model.
pub fn load_peft_safetensors(path: &Path) -> Result<HashMap<String, (Vec<usize>, Vec<f32>)>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let st = safetensors::SafeTensors::deserialize(&bytes)
        .with_context(|| format!("parsing {}", path.display()))?;
    let mut out = HashMap::new();
    for (name, view) in st.tensors() {
        let shape = view.shape().to_vec();
        let raw = view.data();
        let mut data = Vec::with_capacity(raw.len() / 4);
        for chunk in raw.chunks_exact(4) {
            data.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        out.insert(name.to_string(), (shape, data));
    }
    Ok(out)
}
