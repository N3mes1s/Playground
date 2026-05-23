//! GPU backend: safe Rust wrappers over the CUDA kernels in
//! `cuda/coda_kernels.cu`.
//!
//! This module exists only when the crate is built with `--features cuda`.
//! Each function mirrors a kernel in [`crate::kernels`] but runs the
//! GEMM-plus-epilogue on an NVIDIA GPU. The CUDA host wrappers own all device
//! memory; these wrappers just marshal [`Mat`] buffers across the FFI
//! boundary and panic with the kernel name if CUDA reports an error.

use crate::model::{Config, Model};
use crate::tensor::Mat;
use crate::train::{Grads, LayerGrad};
use std::os::raw::{c_char, c_int};

extern "C" {
    fn coda_cuda_device_count() -> c_int;
    fn coda_cuda_device_name(buf: *mut c_char, len: c_int);
    fn coda_cuda_gemm(a: *const f32, b: *const f32, d: *mut f32, m: c_int, n: c_int, k: c_int)
        -> c_int;
    fn coda_cuda_gemm_residual_partial_rms(
        a: *const f32,
        b: *const f32,
        c: *const f32,
        gamma: *const f32,
        d: *mut f32,
        o: *mut f32,
        r: *mut f32,
        m: c_int,
        n: c_int,
        k: c_int,
        eps: f32,
    ) -> c_int;
    fn coda_cuda_gemm_rmsnorm(
        a: *const f32,
        b: *const f32,
        r: *const f32,
        o: *mut f32,
        m: c_int,
        n: c_int,
        k: c_int,
    ) -> c_int;
    fn coda_cuda_gemm_rmsnorm_swiglu(
        a: *const f32,
        b: *const f32,
        r: *const f32,
        o: *mut f32,
        d_prime: *mut f32,
        m: c_int,
        n: c_int,
        k: c_int,
    ) -> c_int;
    fn coda_cuda_gemm_rope(
        a: *const f32,
        b: *const f32,
        cos: *const f32,
        sin: *const f32,
        o: *mut f32,
        m: c_int,
        n: c_int,
        k: c_int,
    ) -> c_int;
    fn coda_cuda_gemm_swiglu(
        a: *const f32,
        b: *const f32,
        o: *mut f32,
        m: c_int,
        n: c_int,
        k: c_int,
    ) -> c_int;
    fn coda_cuda_gemm_rmsnorm_ce(
        a: *const f32,
        b: *const f32,
        r: *const f32,
        tgt: *const c_int,
        lse: *mut f32,
        loss: *mut f32,
        m: c_int,
        n: c_int,
        k: c_int,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn coda_cuda_model_forward(
        x0: *const f32,
        cos: *const f32,
        sin: *const f32,
        t: c_int,
        d: c_int,
        n_layers: c_int,
        n_heads: c_int,
        head_dim: c_int,
        d_ff: c_int,
        vocab: c_int,
        eps: f32,
        gamma_attn: *const f32,
        wqkv: *const f32,
        wo: *const f32,
        gamma_ffn: *const f32,
        wgu: *const f32,
        wdown: *const f32,
        gamma_final: *const f32,
        lm_head: *const f32,
        logits: *mut f32,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn coda_cuda_grads(
        t: c_int, d: c_int, nl: c_int, nh: c_int, hd: c_int, dff: c_int,
        vocab: c_int, eps: f32,
        embed: *const f32, ga: *const f32, wqkv: *const f32, wo: *const f32,
        gf: *const f32, wgu: *const f32, wd: *const f32, gfin: *const f32,
        lm: *const f32, cos: *const f32, sin: *const f32,
        tokens: *const c_int, targets: *const c_int,
        g_embed: *mut f32, g_ga: *mut f32, g_wqkv: *mut f32, g_wo: *mut f32,
        g_gf: *mut f32, g_wgu: *mut f32, g_wd: *mut f32, g_gfin: *mut f32,
        g_lm: *mut f32, loss: *mut f32,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn coda_cuda_train(
        t: c_int, d: c_int, nl: c_int, nh: c_int, hd: c_int, dff: c_int,
        vocab: c_int, eps: f32,
        embed: *mut f32, ga: *mut f32, wqkv: *mut f32, wo: *mut f32,
        gf: *mut f32, wgu: *mut f32, wd: *mut f32, gfin: *mut f32, lm: *mut f32,
        cos: *const f32, sin: *const f32,
        tokens: *const c_int, targets: *const c_int,
        n_steps: c_int, lr: f32, loss_curve: *mut f32,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn coda_cuda_train_random(
        t: c_int, d: c_int, nl: c_int, nh: c_int, hd: c_int, dff: c_int,
        vocab: c_int, eps: f32,
        cos: *const f32, sin: *const f32,
        tokens: *const c_int, targets: *const c_int,
        n_steps: c_int, lr: f32, seed: u32, loss_curve: *mut f32,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn coda_cuda_train_corpus(
        t: c_int, d: c_int, nl: c_int, nh: c_int, hd: c_int, dff: c_int,
        vocab: c_int, eps: f32,
        embed: *mut f32, ga: *mut f32, wqkv: *mut f32, wo: *mut f32,
        gf: *mut f32, wgu: *mut f32, wd: *mut f32, gfin: *mut f32, lm: *mut f32,
        cos: *const f32, sin: *const f32,
        corpus: *const c_int, corpus_len: c_int,
        window_starts: *const c_int, n_steps: c_int, batch: c_int, lr: f32,
        loss_curve: *mut f32,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn coda_cuda_generate(
        tmax: c_int, d: c_int, nl: c_int, nh: c_int, hd: c_int, dff: c_int,
        vocab: c_int, eps: f32,
        embed: *const f32, ga: *const f32, wqkv: *const f32, wo: *const f32,
        gf: *const f32, wgu: *const f32, wd: *const f32, gfin: *const f32,
        lm: *const f32, cos: *const f32, sin: *const f32,
        prompt: *const c_int, prompt_len: c_int, n_new: c_int,
        out_ids: *mut c_int,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn coda_cuda_generate_batch(
        tmax: c_int, d: c_int, nl: c_int, nh: c_int, hd: c_int, dff: c_int,
        vocab: c_int, eps: f32, batch: c_int,
        embed: *const f32, ga: *const f32, wqkv: *const f32, wo: *const f32,
        gf: *const f32, wgu: *const f32, wd: *const f32, gfin: *const f32,
        lm: *const f32, cos: *const f32, sin: *const f32,
        prompts: *const c_int, prompt_len: c_int, n_new: c_int,
        out_ids: *mut c_int,
    ) -> c_int;
}

/// The nine weight tensors flattened into contiguous `[n_layers, ...]` buffers,
/// in the order the CUDA training entry points expect.
struct FlatWeights {
    embed: Vec<f32>,
    ga: Vec<f32>,
    wqkv: Vec<f32>,
    wo: Vec<f32>,
    gf: Vec<f32>,
    wgu: Vec<f32>,
    wd: Vec<f32>,
    gfin: Vec<f32>,
    lm: Vec<f32>,
}

fn flatten_weights(model: &Model) -> FlatWeights {
    let cat = |f: &dyn Fn(&crate::model::Layer) -> Vec<f32>| -> Vec<f32> {
        model.layers.iter().flat_map(|l| f(l)).collect()
    };
    FlatWeights {
        embed: model.embed.data.clone(),
        ga: cat(&|l| l.gamma_attn.clone()),
        wqkv: cat(&|l| l.wqkv.data.clone()),
        wo: cat(&|l| l.wo.data.clone()),
        gf: cat(&|l| l.gamma_ffn.clone()),
        wgu: cat(&|l| l.wgu.data.clone()),
        wd: cat(&|l| l.wdown.data.clone()),
        gfin: model.gamma_final.clone(),
        lm: model.lm_head.data.clone(),
    }
}

/// Number of visible CUDA devices (0 if none / no driver).
pub fn device_count() -> i32 {
    unsafe { coda_cuda_device_count() as i32 }
}

/// Name of CUDA device 0.
pub fn device_name() -> String {
    let mut buf = [0u8; 256];
    unsafe { coda_cuda_device_name(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn check(status: c_int, kernel: &str) {
    assert_eq!(status, 0, "CUDA kernel `{kernel}` failed (see stderr)");
}

/// Plain GEMM `A @ B` on the GPU.
pub fn gemm(a: &Mat, b: &Mat) -> Mat {
    let (m, k, n) = (a.rows, a.cols, b.cols);
    assert_eq!(a.cols, b.rows);
    let mut d = Mat::zeros(m, n);
    let s = unsafe {
        coda_cuda_gemm(
            a.data.as_ptr(),
            b.data.as_ptr(),
            d.data.as_mut_ptr(),
            m as c_int,
            n as c_int,
            k as c_int,
        )
    };
    check(s, "gemm");
    d
}

/// Kernel 4 on the GPU: returns `(D = AB+C, O = D⊙γ, r)`.
pub fn gemm_residual_partial_rms(
    a: &Mat,
    b: &Mat,
    c: &Mat,
    gamma: &[f32],
    eps: f32,
) -> (Mat, Mat, Vec<f32>) {
    let (m, k, n) = (a.rows, a.cols, b.cols);
    assert_eq!((c.rows, c.cols), (m, n));
    assert_eq!(gamma.len(), n);
    let mut d = Mat::zeros(m, n);
    let mut o = Mat::zeros(m, n);
    let mut r = vec![0.0f32; m];
    let s = unsafe {
        coda_cuda_gemm_residual_partial_rms(
            a.data.as_ptr(),
            b.data.as_ptr(),
            c.data.as_ptr(),
            gamma.as_ptr(),
            d.data.as_mut_ptr(),
            o.data.as_mut_ptr(),
            r.as_mut_ptr(),
            m as c_int,
            n as c_int,
            k as c_int,
            eps,
        )
    };
    check(s, "gemm_residual_partial_rms");
    (d, o, r)
}

/// Kernel 5 on the GPU: `O = (A@B) ⊙ r`.
pub fn gemm_rmsnorm(a: &Mat, b: &Mat, r: &[f32]) -> Mat {
    let (m, k, n) = (a.rows, a.cols, b.cols);
    assert_eq!(r.len(), m);
    let mut o = Mat::zeros(m, n);
    let s = unsafe {
        coda_cuda_gemm_rmsnorm(
            a.data.as_ptr(),
            b.data.as_ptr(),
            r.as_ptr(),
            o.data.as_mut_ptr(),
            m as c_int,
            n as c_int,
            k as c_int,
        )
    };
    check(s, "gemm_rmsnorm");
    o
}

/// Kernel 6 on the GPU: returns `(O = SwiGLU(D'), D' = (A@B)⊙r)`.
pub fn gemm_rmsnorm_swiglu(a: &Mat, b: &Mat, r: &[f32]) -> (Mat, Mat) {
    let (m, k, n) = (a.rows, a.cols, b.cols);
    assert!(n % 2 == 0, "SwiGLU GEMM needs an even output width");
    assert_eq!(r.len(), m);
    let mut o = Mat::zeros(m, n / 2);
    let mut d_prime = Mat::zeros(m, n);
    let s = unsafe {
        coda_cuda_gemm_rmsnorm_swiglu(
            a.data.as_ptr(),
            b.data.as_ptr(),
            r.as_ptr(),
            o.data.as_mut_ptr(),
            d_prime.data.as_mut_ptr(),
            m as c_int,
            n as c_int,
            k as c_int,
        )
    };
    check(s, "gemm_rmsnorm_swiglu");
    (o, d_prime)
}

/// Kernel 1 on the GPU: `O = RoPE(A@B)`.
pub fn gemm_rope(a: &Mat, b: &Mat, cos: &Mat, sin: &Mat) -> Mat {
    let (m, k, n) = (a.rows, a.cols, b.cols);
    assert!(n % 2 == 0, "RoPE GEMM needs an even output width");
    assert_eq!((cos.rows, cos.cols), (m, n));
    assert_eq!((sin.rows, sin.cols), (m, n));
    let mut o = Mat::zeros(m, n);
    let s = unsafe {
        coda_cuda_gemm_rope(
            a.data.as_ptr(),
            b.data.as_ptr(),
            cos.data.as_ptr(),
            sin.data.as_ptr(),
            o.data.as_mut_ptr(),
            m as c_int,
            n as c_int,
            k as c_int,
        )
    };
    check(s, "gemm_rope");
    o
}

/// Kernel 2 on the GPU: `O = SwiGLU(A@B)`.
pub fn gemm_swiglu(a: &Mat, b: &Mat) -> Mat {
    let (m, k, n) = (a.rows, a.cols, b.cols);
    assert!(n % 2 == 0, "SwiGLU GEMM needs an even output width");
    let mut o = Mat::zeros(m, n / 2);
    let s = unsafe {
        coda_cuda_gemm_swiglu(
            a.data.as_ptr(),
            b.data.as_ptr(),
            o.data.as_mut_ptr(),
            m as c_int,
            n as c_int,
            k as c_int,
        )
    };
    check(s, "gemm_swiglu");
    o
}

/// Kernel 8 on the GPU: `Z = (A@B)⊙r`; returns `(lse, per_token_loss)`.
pub fn gemm_rmsnorm_ce(a: &Mat, b: &Mat, r: &[f32], targets: &[usize]) -> (Vec<f32>, Vec<f32>) {
    let (m, k, n) = (a.rows, a.cols, b.cols);
    assert_eq!(r.len(), m);
    assert_eq!(targets.len(), m);
    assert!(
        targets.iter().all(|&t| t < n),
        "cross-entropy target index outside [0, vocab)"
    );
    let tgt: Vec<c_int> = targets.iter().map(|&t| t as c_int).collect();
    let mut lse = vec![0.0f32; m];
    let mut loss = vec![0.0f32; m];
    let s = unsafe {
        coda_cuda_gemm_rmsnorm_ce(
            a.data.as_ptr(),
            b.data.as_ptr(),
            r.as_ptr(),
            tgt.as_ptr(),
            lse.as_mut_ptr(),
            loss.as_mut_ptr(),
            m as c_int,
            n as c_int,
            k as c_int,
        )
    };
    check(s, "gemm_rmsnorm_ce");
    (lse, loss)
}

/// Run the **entire Transformer forward pass on the GPU**.
///
/// Embeds the tokens and builds the RoPE tables on the host, uploads the
/// weights once, and runs every layer device-resident (the GEMM-Residual-
/// RMSNorm-GEMM chain plus attention) - only the logits come back. This is
/// the GPU counterpart of [`Model::forward`].
pub fn model_forward(model: &Model, tokens: &[usize]) -> Mat {
    let cfg = &model.cfg;
    let t = tokens.len();
    let d = cfg.d_model;
    assert!(cfg.head_dim <= 256, "CUDA attention caps head_dim at 256");
    assert_eq!(cfg.n_heads * cfg.head_dim, d, "n_heads * head_dim must equal d_model");

    // Embedding gather + RoPE tables on the host (cheap, embedding-excluded).
    let mut x0 = Mat::zeros(t, d);
    for (i, &tok) in tokens.iter().enumerate() {
        x0.row_mut(i).copy_from_slice(model.embed.row(tok));
    }
    let (cos, sin) = model.rope_tables(t);

    // Flatten the per-layer weights into contiguous [n_layers, ...] buffers.
    let cat = |f: &dyn Fn(&crate::model::Layer) -> Vec<f32>| -> Vec<f32> {
        model.layers.iter().flat_map(|l| f(l)).collect()
    };
    let gamma_attn = cat(&|l| l.gamma_attn.clone());
    let wqkv = cat(&|l| l.wqkv.data.clone());
    let wo = cat(&|l| l.wo.data.clone());
    let gamma_ffn = cat(&|l| l.gamma_ffn.clone());
    let wgu = cat(&|l| l.wgu.data.clone());
    let wdown = cat(&|l| l.wdown.data.clone());

    let mut logits = Mat::zeros(t, cfg.vocab);
    let s = unsafe {
        coda_cuda_model_forward(
            x0.data.as_ptr(),
            cos.data.as_ptr(),
            sin.data.as_ptr(),
            t as c_int,
            d as c_int,
            cfg.n_layers as c_int,
            cfg.n_heads as c_int,
            cfg.head_dim as c_int,
            cfg.d_ff as c_int,
            cfg.vocab as c_int,
            cfg.eps,
            gamma_attn.as_ptr(),
            wqkv.as_ptr(),
            wo.as_ptr(),
            gamma_ffn.as_ptr(),
            wgu.as_ptr(),
            wdown.as_ptr(),
            model.gamma_final.as_ptr(),
            model.lm_head.data.as_ptr(),
            logits.data.as_mut_ptr(),
        )
    };
    check(s, "model_forward");
    logits
}

/// Autoregressively generate `n_new` tokens from `prompt`, **device-resident**.
///
/// [`model_forward`] re-uploads every weight on each call; for a
/// multi-billion-parameter model that transfer dwarfs the compute and makes
/// per-token decoding unusably slow. This entry point uploads the full weight
/// set to the GPU *once* and runs the whole greedy decode loop on the resident
/// weights - only the new token id crosses the PCIe bus between steps.
///
/// Sampling is greedy (argmax). Returns the `n_new` generated token ids.
pub fn generate(model: &Model, prompt: &[usize], n_new: usize) -> Vec<usize> {
    let cfg = &model.cfg;
    let d = cfg.d_model;
    assert!(cfg.head_dim <= 256, "CUDA attention caps head_dim at 256");
    assert_eq!(cfg.n_heads * cfg.head_dim, d, "n_heads * head_dim must equal d_model");
    let tmax = prompt.len() + n_new;
    assert!(tmax <= 1024, "CUDA attention supports T <= 1024");

    let (cos, sin) = model.rope_tables(tmax);
    let w = flatten_weights(model);
    let prompt_i: Vec<c_int> = prompt.iter().map(|&x| x as c_int).collect();
    let mut out = vec![0 as c_int; n_new];

    let s = unsafe {
        coda_cuda_generate(
            tmax as c_int, d as c_int, cfg.n_layers as c_int,
            cfg.n_heads as c_int, cfg.head_dim as c_int, cfg.d_ff as c_int,
            cfg.vocab as c_int, cfg.eps,
            w.embed.as_ptr(), w.ga.as_ptr(), w.wqkv.as_ptr(), w.wo.as_ptr(),
            w.gf.as_ptr(), w.wgu.as_ptr(), w.wd.as_ptr(), w.gfin.as_ptr(),
            w.lm.as_ptr(), cos.data.as_ptr(), sin.data.as_ptr(),
            prompt_i.as_ptr(), prompt_i.len() as c_int, n_new as c_int,
            out.as_mut_ptr(),
        )
    };
    check(s, "generate");
    out.into_iter().map(|x| x as usize).collect()
}

/// Batched greedy decode: run `batch` prompts in lockstep, sharing one weight
/// upload. Aggregate throughput scales with `batch` until the GEMMs become
/// compute-bound; the projection "GEMMs" stop being M=1 matrix-vector
/// products and have real M-tile work to do, so the weight read amortizes
/// across `batch` tokens per step.
///
/// `prompts` is the per-request prompt slice (all of the same length).
/// Returns a `[batch, n_new]` row-major vector of generated token ids.
pub fn generate_batch(
    model: &Model,
    prompts: &[Vec<usize>],
    n_new: usize,
) -> Vec<Vec<usize>> {
    let batch = prompts.len();
    assert!(batch > 0, "batch must be non-empty");
    let prompt_len = prompts[0].len();
    assert!(
        prompts.iter().all(|p| p.len() == prompt_len),
        "all prompts must have the same length",
    );
    let cfg = &model.cfg;
    let d = cfg.d_model;
    assert!(cfg.head_dim <= 256, "CUDA attention caps head_dim at 256");
    assert_eq!(cfg.n_heads * cfg.head_dim, d, "n_heads * head_dim must equal d_model");
    let tmax = prompt_len + n_new;
    assert!(tmax <= 1024, "CUDA attention supports T <= 1024");

    let (cos, sin) = model.rope_tables(tmax);
    let w = flatten_weights(model);

    // Flatten all prompts into one `[batch, prompt_len]` int buffer.
    let mut prompts_flat: Vec<c_int> = Vec::with_capacity(batch * prompt_len);
    for p in prompts {
        prompts_flat.extend(p.iter().map(|&x| x as c_int));
    }
    let mut out = vec![0 as c_int; batch * n_new];

    let s = unsafe {
        coda_cuda_generate_batch(
            tmax as c_int, d as c_int, cfg.n_layers as c_int,
            cfg.n_heads as c_int, cfg.head_dim as c_int, cfg.d_ff as c_int,
            cfg.vocab as c_int, cfg.eps, batch as c_int,
            w.embed.as_ptr(), w.ga.as_ptr(), w.wqkv.as_ptr(), w.wo.as_ptr(),
            w.gf.as_ptr(), w.wgu.as_ptr(), w.wd.as_ptr(), w.gfin.as_ptr(),
            w.lm.as_ptr(), cos.data.as_ptr(), sin.data.as_ptr(),
            prompts_flat.as_ptr(), prompt_len as c_int, n_new as c_int,
            out.as_mut_ptr(),
        )
    };
    check(s, "generate_batch");

    // Split out into per-request id lists.
    out.chunks(n_new)
        .map(|c| c.iter().map(|&x| x as usize).collect())
        .collect()
}

/// Run **one forward + backward on the GPU** and return the gradients.
///
/// The GPU computes the same canonical computation graph as the CPU
/// [`crate::train::backward`]; comparing the two is the correctness check for
/// the device-resident training path.
pub fn grads(model: &Model, tokens: &[usize], targets: &[usize]) -> (Grads, f32) {
    let cfg = &model.cfg;
    let (t, d, nl, dff, v) = (tokens.len(), cfg.d_model, cfg.n_layers, cfg.d_ff, cfg.vocab);
    let w = flatten_weights(model);
    let (cos, sin) = model.rope_tables(t);
    let tok: Vec<c_int> = tokens.iter().map(|&x| x as c_int).collect();
    let tgt: Vec<c_int> = targets.iter().map(|&x| x as c_int).collect();

    let mut g_embed = vec![0.0f32; v * d];
    let mut g_ga = vec![0.0f32; nl * d];
    let mut g_wqkv = vec![0.0f32; nl * d * 3 * d];
    let mut g_wo = vec![0.0f32; nl * d * d];
    let mut g_gf = vec![0.0f32; nl * d];
    let mut g_wgu = vec![0.0f32; nl * d * 2 * dff];
    let mut g_wd = vec![0.0f32; nl * dff * d];
    let mut g_gfin = vec![0.0f32; d];
    let mut g_lm = vec![0.0f32; d * v];
    let mut loss = 0.0f32;

    let s = unsafe {
        coda_cuda_grads(
            t as c_int, d as c_int, nl as c_int, cfg.n_heads as c_int,
            cfg.head_dim as c_int, dff as c_int, v as c_int, cfg.eps,
            w.embed.as_ptr(), w.ga.as_ptr(), w.wqkv.as_ptr(), w.wo.as_ptr(),
            w.gf.as_ptr(), w.wgu.as_ptr(), w.wd.as_ptr(), w.gfin.as_ptr(),
            w.lm.as_ptr(), cos.data.as_ptr(), sin.data.as_ptr(),
            tok.as_ptr(), tgt.as_ptr(),
            g_embed.as_mut_ptr(), g_ga.as_mut_ptr(), g_wqkv.as_mut_ptr(),
            g_wo.as_mut_ptr(), g_gf.as_mut_ptr(), g_wgu.as_mut_ptr(),
            g_wd.as_mut_ptr(), g_gfin.as_mut_ptr(), g_lm.as_mut_ptr(), &mut loss,
        )
    };
    check(s, "grads");

    let layers = (0..nl)
        .map(|l| LayerGrad {
            d_gamma_attn: g_ga[l * d..(l + 1) * d].to_vec(),
            d_wqkv: Mat::from_vec(d, 3 * d, g_wqkv[l * d * 3 * d..(l + 1) * d * 3 * d].to_vec()),
            d_wo: Mat::from_vec(d, d, g_wo[l * d * d..(l + 1) * d * d].to_vec()),
            d_gamma_ffn: g_gf[l * d..(l + 1) * d].to_vec(),
            d_wgu: Mat::from_vec(d, 2 * dff, g_wgu[l * d * 2 * dff..(l + 1) * d * 2 * dff].to_vec()),
            d_wdown: Mat::from_vec(dff, d, g_wd[l * dff * d..(l + 1) * dff * d].to_vec()),
        })
        .collect();

    let grads = Grads {
        d_embed: Mat::from_vec(v, d, g_embed),
        layers,
        d_gamma_final: g_gfin,
        d_lm_head: Mat::from_vec(d, v, g_lm),
    };
    (grads, loss)
}

/// Train the model **entirely on the GPU**: weights and Adam state stay
/// device-resident for all `n_steps`. Returns the trained model and the
/// per-step loss curve.
pub fn train(
    model: &Model,
    tokens: &[usize],
    targets: &[usize],
    n_steps: usize,
    lr: f32,
) -> (Model, Vec<f32>) {
    let cfg = &model.cfg;
    let (t, d, nl, dff, v) = (tokens.len(), cfg.d_model, cfg.n_layers, cfg.d_ff, cfg.vocab);
    let mut w = flatten_weights(model);
    let (cos, sin) = model.rope_tables(t);
    let tok: Vec<c_int> = tokens.iter().map(|&x| x as c_int).collect();
    let tgt: Vec<c_int> = targets.iter().map(|&x| x as c_int).collect();
    let mut loss_curve = vec![0.0f32; n_steps];

    let s = unsafe {
        coda_cuda_train(
            t as c_int, d as c_int, nl as c_int, cfg.n_heads as c_int,
            cfg.head_dim as c_int, dff as c_int, v as c_int, cfg.eps,
            w.embed.as_mut_ptr(), w.ga.as_mut_ptr(), w.wqkv.as_mut_ptr(),
            w.wo.as_mut_ptr(), w.gf.as_mut_ptr(), w.wgu.as_mut_ptr(),
            w.wd.as_mut_ptr(), w.gfin.as_mut_ptr(), w.lm.as_mut_ptr(),
            cos.data.as_ptr(), sin.data.as_ptr(), tok.as_ptr(), tgt.as_ptr(),
            n_steps as c_int, lr, loss_curve.as_mut_ptr(),
        )
    };
    check(s, "train");

    // Write the trained flat weights back into a fresh model.
    let mut m = model.clone();
    m.embed.data = w.embed;
    m.gamma_final = w.gfin;
    m.lm_head.data = w.lm;
    for l in 0..nl {
        m.layers[l].gamma_attn = w.ga[l * d..(l + 1) * d].to_vec();
        m.layers[l].wqkv.data = w.wqkv[l * d * 3 * d..(l + 1) * d * 3 * d].to_vec();
        m.layers[l].wo.data = w.wo[l * d * d..(l + 1) * d * d].to_vec();
        m.layers[l].gamma_ffn = w.gf[l * d..(l + 1) * d].to_vec();
        m.layers[l].wgu.data = w.wgu[l * d * 2 * dff..(l + 1) * d * 2 * dff].to_vec();
        m.layers[l].wdown.data = w.wd[l * dff * d..(l + 1) * dff * d].to_vec();
    }
    (m, loss_curve)
}

/// Train a model **whose weights are generated and kept entirely on the GPU**.
///
/// For a multi-billion-parameter model the host cannot hold the weights, and
/// Adam's two moment tensors would not fit in GPU memory either. This entry
/// point initializes the weights in place on the device, optimizes with plain
/// SGD, and returns only the per-step loss curve - the model never touches
/// host memory. Used for the `--scale big` run.
pub fn train_random(
    cfg: &Config,
    tokens: &[usize],
    targets: &[usize],
    n_steps: usize,
    lr: f32,
    seed: u32,
) -> Vec<f32> {
    let t = tokens.len();
    assert!(t <= 1024, "CUDA attention supports T <= 1024");
    assert_eq!(cfg.n_heads * cfg.head_dim, cfg.d_model);
    let (cos, sin) = crate::model::rope_tables(cfg, t);
    let tok: Vec<c_int> = tokens.iter().map(|&x| x as c_int).collect();
    let tgt: Vec<c_int> = targets.iter().map(|&x| x as c_int).collect();
    let mut loss_curve = vec![0.0f32; n_steps];
    let s = unsafe {
        coda_cuda_train_random(
            t as c_int,
            cfg.d_model as c_int,
            cfg.n_layers as c_int,
            cfg.n_heads as c_int,
            cfg.head_dim as c_int,
            cfg.d_ff as c_int,
            cfg.vocab as c_int,
            cfg.eps,
            cos.data.as_ptr(),
            sin.data.as_ptr(),
            tok.as_ptr(),
            tgt.as_ptr(),
            n_steps as c_int,
            lr,
            seed,
            loss_curve.as_mut_ptr(),
        )
    };
    check(s, "train_random");
    loss_curve
}

/// Train a model on a **real text corpus** by stochastic windowed training.
///
/// The corpus is uploaded to the GPU once; each of `n_steps` steps trains on a
/// different randomly-placed length-`t_window` window of it. Because every step
/// sees fresh text, the model learns the corpus distribution rather than
/// memorizing one sequence. Returns the trained model and the loss curve.
pub fn train_corpus(
    model: &Model,
    corpus: &[usize],
    t_window: usize,
    n_steps: usize,
    batch: usize,
    lr: f32,
    seed: u64,
) -> (Model, Vec<f32>) {
    let cfg = &model.cfg;
    let (d, nl, dff, v) = (cfg.d_model, cfg.n_layers, cfg.d_ff, cfg.vocab);
    assert!(t_window <= 1024, "CUDA attention supports T <= 1024");
    assert!(corpus.len() > t_window + 1, "corpus shorter than the window");
    let mut w = flatten_weights(model);
    let (cos, sin) = crate::model::rope_tables(cfg, t_window);

    // One random window start per (step, batch element); kept in bounds for
    // the input and the shifted target.
    let mut rng = crate::model::Rng::new(seed);
    let span = (corpus.len() - t_window - 1) as u32;
    let starts: Vec<c_int> = (0..n_steps * batch)
        .map(|_| ((rng.uniform() * span as f32) as u32 % span) as c_int)
        .collect();
    let corpus_i: Vec<c_int> = corpus.iter().map(|&x| x as c_int).collect();
    let mut loss_curve = vec![0.0f32; n_steps];

    let s = unsafe {
        coda_cuda_train_corpus(
            t_window as c_int,
            d as c_int,
            nl as c_int,
            cfg.n_heads as c_int,
            cfg.head_dim as c_int,
            dff as c_int,
            v as c_int,
            cfg.eps,
            w.embed.as_mut_ptr(),
            w.ga.as_mut_ptr(),
            w.wqkv.as_mut_ptr(),
            w.wo.as_mut_ptr(),
            w.gf.as_mut_ptr(),
            w.wgu.as_mut_ptr(),
            w.wd.as_mut_ptr(),
            w.gfin.as_mut_ptr(),
            w.lm.as_mut_ptr(),
            cos.data.as_ptr(),
            sin.data.as_ptr(),
            corpus_i.as_ptr(),
            corpus_i.len() as c_int,
            starts.as_ptr(),
            n_steps as c_int,
            batch as c_int,
            lr,
            loss_curve.as_mut_ptr(),
        )
    };
    check(s, "train_corpus");

    let mut m = model.clone();
    m.embed.data = w.embed;
    m.gamma_final = w.gfin;
    m.lm_head.data = w.lm;
    for l in 0..nl {
        m.layers[l].gamma_attn = w.ga[l * d..(l + 1) * d].to_vec();
        m.layers[l].wqkv.data = w.wqkv[l * d * 3 * d..(l + 1) * d * 3 * d].to_vec();
        m.layers[l].wo.data = w.wo[l * d * d..(l + 1) * d * d].to_vec();
        m.layers[l].gamma_ffn = w.gf[l * d..(l + 1) * d].to_vec();
        m.layers[l].wgu.data = w.wgu[l * d * 2 * dff..(l + 1) * d * 2 * dff].to_vec();
        m.layers[l].wdown.data = w.wd[l * dff * d..(l + 1) * dff * d].to_vec();
    }
    (m, loss_curve)
}
