//! GPU backend: safe Rust wrappers over the CUDA kernels in
//! `cuda/coda_kernels.cu`.
//!
//! This module exists only when the crate is built with `--features cuda`.
//! Each function mirrors a kernel in [`crate::kernels`] but runs the
//! GEMM-plus-epilogue on an NVIDIA GPU. The CUDA host wrappers own all device
//! memory; these wrappers just marshal [`Mat`] buffers across the FFI
//! boundary and panic with the kernel name if CUDA reports an error.

use crate::model::Model;
use crate::tensor::Mat;
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
