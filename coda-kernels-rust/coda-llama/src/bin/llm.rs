//! `coda-llm` - run a real pretrained model (Llama-2-7B-chat) on the CUDA backend.
//!
//! The CODA backend implements the LLaMA architecture, so a converted
//! Llama-2-7B-chat checkpoint runs inference on it unchanged. This binary loads
//! the flat model produced by `modal/prepare_llm.py`, verifies its own forward
//! pass against reference logits from a genuine HuggingFace forward, and then
//! autoregressively generates text with the device-resident decode loop (the
//! 27 GB weight set is uploaded once, not per token). Build with `--features cuda`.

#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!("coda-llm requires the CUDA backend: rebuild with `--features cuda`.");
    std::process::exit(1);
}

#[cfg(feature = "cuda")]
fn read_ids(path: &str) -> Vec<usize> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("missing {path}"))
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect()
}

/// Load the flat model written by `prepare_llm.py` (header + fp32 tensors).
#[cfg(feature = "cuda")]
fn load_model() -> coda_llama::model::Model {
    use coda::tensor::Mat;
    use coda_llama::model::{Config, Layer, Model};

    let bytes = std::fs::read("/work/model.bin").expect("missing /work/model.bin");
    let mut o = 0usize;
    let u32_at = |o: &mut usize| {
        let v = u32::from_le_bytes(bytes[*o..*o + 4].try_into().unwrap());
        *o += 4;
        v
    };
    let f32_at = |o: &mut usize| {
        let v = f32::from_le_bytes(bytes[*o..*o + 4].try_into().unwrap());
        *o += 4;
        v
    };
    assert_eq!(u32_at(&mut o), 0x4144_4F43, "bad magic in model.bin");
    let vocab = u32_at(&mut o) as usize;
    let d = u32_at(&mut o) as usize;
    let nl = u32_at(&mut o) as usize;
    let nh = u32_at(&mut o) as usize;
    let hd = u32_at(&mut o) as usize;
    let dff = u32_at(&mut o) as usize;
    let eps = f32_at(&mut o);
    let rope_base = f32_at(&mut o);
    let cfg = Config {
        vocab,
        d_model: d,
        n_layers: nl,
        n_heads: nh,
        head_dim: hd,
        d_ff: dff,
        eps,
        rope_base,
    };
    println!(
        "loaded model: d_model={d}, layers={nl}, heads={nh}, head_dim={hd}, \
         d_ff={dff}, vocab={vocab}"
    );

    let mut take = |n: usize| -> Vec<f32> {
        let slice = &bytes[o..o + n * 4];
        o += n * 4;
        slice
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    };
    let embed = Mat::from_vec(vocab, d, take(vocab * d));
    let mut layers = Vec::with_capacity(nl);
    for _ in 0..nl {
        layers.push(Layer {
            gamma_attn: take(d),
            wqkv: Mat::from_vec(d, 3 * d, take(d * 3 * d)),
            wo: Mat::from_vec(d, d, take(d * d)),
            gamma_ffn: take(d),
            wgu: Mat::from_vec(d, 2 * dff, take(d * 2 * dff)),
            wdown: Mat::from_vec(dff, d, take(dff * d)),
        });
    }
    let gamma_final = take(d);
    let lm_head = Mat::from_vec(d, vocab, take(d * vocab));
    Model { cfg, embed, layers, gamma_final, lm_head }
}

#[cfg(feature = "cuda")]
fn main() {
    use coda_llama::cuda;

    println!("CODA-rs : running Llama-2-7B-chat on the CUDA GEMM-plus-epilogue backend\n");
    let model = load_model();
    let vocab = model.cfg.vocab;
    let argmax = |v: &[f32]| {
        (0..v.len())
            .max_by(|&a, &b| v[a].partial_cmp(&v[b]).unwrap())
            .unwrap()
    };

    // ---- Verify the CUDA forward against HuggingFace reference logits. ----
    let ver = read_ids("/work/ver_ids.txt");
    let logits = cuda::model_forward(&model, &ver);
    let last = logits.rows - 1;
    let mine: Vec<f32> = (0..vocab).map(|j| logits.get(last, j)).collect();
    let reference: Vec<f32> = std::fs::read("/work/ref_logits.bin")
        .expect("missing ref_logits.bin")
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let n = vocab as f32;
    let (mmean, rmean) = (mine.iter().sum::<f32>() / n, reference.iter().sum::<f32>() / n);
    let (mut cov, mut vm, mut vr) = (0.0f32, 0.0f32, 0.0f32);
    for j in 0..vocab {
        let (a, b) = (mine[j] - mmean, reference[j] - rmean);
        cov += a * b;
        vm += a * a;
        vr += b * b;
    }
    let corr = cov / (vm.sqrt() * vr.sqrt());
    let (my_arg, ref_arg) = (argmax(&mine), argmax(&reference));
    println!("\n== Verification: CUDA forward vs HuggingFace reference ==");
    println!("    next-token argmax : CUDA {my_arg}  |  HuggingFace {ref_arg}");
    println!("    logits correlation with HuggingFace : {corr:.5}");
    println!(
        "    --> weight conversion {}",
        if my_arg == ref_arg && corr > 0.98 { "VERIFIED" } else { "MISMATCH" }
    );

    // ---- Batched generation: B prompts decoded in lockstep. ----
    let prompt = read_ids("/work/gen_ids.txt");
    let batch = 64;
    let n_gen = 200;
    let prompts: Vec<Vec<usize>> = (0..batch).map(|_| prompt.clone()).collect();
    println!("\n== Batched generation: B={batch} prompts, {n_gen} tokens each ==");
    println!("    one shared weight upload + KV-cached decode; each step's");
    println!("    projections become a real GEMM with M={batch}");
    let t0 = std::time::Instant::now();
    let outs = cuda::generate_batch(&model, &prompts, n_gen);
    let elapsed = t0.elapsed().as_secs_f64();
    let total_tokens = batch * n_gen;
    let tps = total_tokens as f64 / elapsed;
    println!(
        "    done in {:.1}s  ({} tokens total -> {:.0} tokens/s wall-clock\n     including one-time setup; see steady-state decode line above)",
        elapsed, total_tokens, tps
    );

    // Save the first request's output for the decode step (all are identical
    // since the prompts and the decode are deterministic).
    let mut seq = prompt.clone();
    seq.extend(outs[0].iter().copied());
    let ids: Vec<String> = seq.iter().map(|x| x.to_string()).collect();
    std::fs::write("/work/out_ids.txt", ids.join(" ")).unwrap();
    println!("    wrote {} token ids to /work/out_ids.txt", seq.len());
}
