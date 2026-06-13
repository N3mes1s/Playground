//! End-to-end proofs for the Code2LoRA Rust pipeline. These are the offline,
//! GPU-free guarantees: the artifact is structurally a valid PEFT adapter for
//! the real model, it round-trips, it is reproducible, and it is genuinely
//! conditioned on the repository (different repos -> different adapters).

use std::path::PathBuf;

use code2lora::embedder::{encode_repo, HashEmbedder};
use code2lora::hypernet::{HyperNet, HyperNetConfig};
use code2lora::lora::{export_peft, load_peft_safetensors};
use code2lora::model::{ModelSpec, MODULE_TYPES};

fn sample_repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/sample_repo")
}

fn make_repo(files: &[(&str, &str)]) -> tempdir::TempDir {
    let dir = tempdir::TempDir::new();
    for (rel, content) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    dir
}

fn gen_adapter(repo: &std::path::Path, seed: u64, out: &std::path::Path) -> ModelSpec {
    let spec = ModelSpec::qwen25_coder_1_5b();
    let emb = HashEmbedder::default();
    let (e, _) = encode_repo(repo, &emb).unwrap();
    let net = HyperNet::new(
        spec.clone(),
        HyperNetConfig {
            seed,
            ..Default::default()
        },
        e.len(),
    );
    let adapter = net.generate(&e);
    export_peft(&adapter, &spec, out).unwrap();
    spec
}

#[test]
fn shapes_match_real_model() {
    let out = tempdir::TempDir::new();
    let spec = gen_adapter(&sample_repo(), 0, out.path());
    let tensors = load_peft_safetensors(&out.path().join("adapter_model.safetensors")).unwrap();

    // 28 layers * 7 module types * 2 (A,B) tensors.
    assert_eq!(tensors.len(), spec.num_layers * MODULE_TYPES.len() * 2);

    for &m in MODULE_TYPES.iter() {
        let (in_f, out_f) = spec.lora_dims(m);
        let key_a = format!(
            "base_model.model.model.layers.0.{}.{}.lora_A.weight",
            m.block(),
            m.proj_name()
        );
        let key_b = format!(
            "base_model.model.model.layers.0.{}.{}.lora_B.weight",
            m.block(),
            m.proj_name()
        );
        let (sa, _) = &tensors[&key_a];
        let (sb, _) = &tensors[&key_b];
        assert_eq!(sa, &vec![16, in_f], "A shape for {}", m.proj_name());
        assert_eq!(sb, &vec![out_f, 16], "B shape for {}", m.proj_name());
    }
}

#[test]
fn weights_finite_and_near_identity() {
    let out = tempdir::TempDir::new();
    gen_adapter(&sample_repo(), 0, out.path());
    let tensors = load_peft_safetensors(&out.path().join("adapter_model.safetensors")).unwrap();
    let mut max_abs = 0.0f32;
    for (_, data) in tensors.values() {
        for &v in data {
            assert!(v.is_finite());
            max_abs = max_abs.max(v.abs());
        }
    }
    // log-scale init = -3.5 keeps the adapter small (near-identity at init).
    assert!(max_abs < 0.5, "max |w| = {max_abs}");
    assert!(max_abs > 0.0);
}

#[test]
fn deterministic_same_repo_same_adapter() {
    let out1 = tempdir::TempDir::new();
    let out2 = tempdir::TempDir::new();
    gen_adapter(&sample_repo(), 7, out1.path());
    gen_adapter(&sample_repo(), 7, out2.path());
    let a = std::fs::read(out1.path().join("adapter_model.safetensors")).unwrap();
    let b = std::fs::read(out2.path().join("adapter_model.safetensors")).unwrap();
    assert_eq!(a, b, "same repo + seed must produce identical bytes");
}

#[test]
fn conditioned_different_repos_differ() {
    let repo_a = make_repo(&[
        ("src/net.py", "import socket\n\ndef serve(port):\n    return socket.socket()\n"),
        ("README.md", "# webserver\nA networking library.\n"),
    ]);
    let repo_b = make_repo(&[
        ("src/math.py", "import numpy as np\n\ndef solve(A, b):\n    return np.linalg.solve(A, b)\n"),
        ("README.md", "# linalg\nA numerical linear algebra library.\n"),
    ]);
    let oa = tempdir::TempDir::new();
    let ob = tempdir::TempDir::new();
    gen_adapter(repo_a.path(), 0, oa.path());
    gen_adapter(repo_b.path(), 0, ob.path());

    let ta = load_peft_safetensors(&oa.path().join("adapter_model.safetensors")).unwrap();
    let tb = load_peft_safetensors(&ob.path().join("adapter_model.safetensors")).unwrap();
    let key = "base_model.model.model.layers.0.self_attn.q_proj.lora_A.weight";
    let (_, da) = &ta[key];
    let (_, db) = &tb[key];
    let diff: f32 = da.iter().zip(db).map(|(x, y)| (x - y).abs()).sum();
    assert!(diff > 1e-3, "different repos must yield different adapters (diff={diff})");
}

/// Minimal tempdir helper (avoids an external dev-dependency).
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            let mut p = std::env::temp_dir();
            let id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            p.push(format!("code2lora-test-{}-{:p}", id, &id as *const _));
            std::fs::create_dir_all(&p).unwrap();
            TempDir { path: p }
        }
        pub fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
