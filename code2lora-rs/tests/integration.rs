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

// ---- Code2LoRA-Evo (§3.3) ----

use code2lora::embedder::encode_text;
use code2lora::evo::EvoHyperNet;

fn diff_embeds() -> (Vec<f32>, Vec<Vec<f32>>) {
    let emb = HashEmbedder::default();
    let e0 = encode_text(&emb, "initial snapshot: a small library with utils");
    let diffs = vec![
        encode_text(&emb, "+def parse(x):\n+    return int(x)\n"),
        encode_text(&emb, "+class Cache:\n+    def get(self): ...\n-def parse(x): ...\n"),
        encode_text(&emb, "+import socket\n+def serve(): pass\n"),
    ];
    (e0, diffs)
}

#[test]
fn evo_trajectory_evolves_and_is_ordered() {
    let spec = ModelSpec::qwen25_coder_1_5b();
    let (e0, diffs) = diff_embeds();
    let net = EvoHyperNet::new(spec, 0);

    let (traj, _z) = net.run(&e0, &diffs);
    assert_eq!(traj.len(), diffs.len());

    // adapters change across commits
    let a1 = &traj[0].mats[0].1.data;
    let a2 = &traj[1].mats[0].1.data;
    let moved: f32 = a1.iter().zip(a2).map(|(x, y)| (x - y).abs()).sum();
    assert!(moved > 1e-4, "adapter should evolve across commits");

    // order matters: reversed diff stream -> different final adapter
    let mut rev = diffs.clone();
    rev.reverse();
    let (traj_rev, _) = net.run(&e0, &rev);
    let fa = &traj.last().unwrap().mats[0].1.data;
    let fr = &traj_rev.last().unwrap().mats[0].1.data;
    let diff: f32 = fa.iter().zip(fr).map(|(x, y)| (x - y).abs()).sum();
    assert!(diff > 1e-3, "commit order should affect the adapter (diff={diff})");
}

#[test]
fn evo_deterministic_and_exportable() {
    let spec = ModelSpec::qwen25_coder_1_5b();
    let (e0, diffs) = diff_embeds();
    let net = EvoHyperNet::new(spec.clone(), 3);
    let (t1, _) = net.run(&e0, &diffs);
    let (t2, _) = net.run(&e0, &diffs);
    assert_eq!(t1.last().unwrap().mats[0].1.data, t2.last().unwrap().mats[0].1.data);

    // final adapter exports as a valid PEFT artifact for the real model
    let out = tempdir::TempDir::new();
    export_peft(t1.last().unwrap(), &spec, out.path()).unwrap();
    let tensors = load_peft_safetensors(&out.path().join("adapter_model.safetensors")).unwrap();
    assert_eq!(tensors.len(), spec.num_layers * MODULE_TYPES.len() * 2);
}

// ---- hypernetwork training (§3.4) ----

use code2lora::train::{run_demo, TrainConfig};

#[test]
fn hypernetwork_trains_and_generalizes() {
    // small, fast config that still crosses the convergence transition
    let cfg = TrainConfig {
        demb: 16,
        din: 4,
        dout: 4,
        trunk_h: 32,
        d_h: 32,
        rank: 4,
        true_rank: 2,
        alpha: 4.0,
        n_train: 400,
        n_test: 64,
        x_per_repo: 16,
        steps: 3500,
        lr: 8e-3,
        weight_decay: 2e-4,
        log_scale_init: -1.5,
        seed: 0,
    };
    let r = run_demo(&cfg);
    // untrained ~ no-adaptation baseline
    assert!((r.init_loss - r.baseline_loss).abs() / r.baseline_loss < 0.1);
    // trained generalizes to unseen repos: large error reduction on held-out
    assert!(
        r.trained_loss < 0.5 * r.baseline_loss,
        "trained {} should be < half of baseline {}",
        r.trained_loss,
        r.baseline_loss
    );
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
