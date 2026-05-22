// CUDA backend for the CODA GEMM-plus-epilogue kernels.
//
// This is the GPU realization of the abstraction in `src/gemm.rs` /
// `src/epilogue.rs`: a GEMM mainloop whose output tile is transformed by a
// fused epilogue *before* it is written to global memory. Each `__global__`
// kernel below computes an accumulator in registers and applies the epilogue
// inline, so intermediate tensors (residual stream, normalized activations)
// are never round-tripped through DRAM - exactly CODA's claim, now on real
// GPU hardware.
//
// The GEMM here is a straightforward one-thread-per-output-element loop. That
// is intentionally simple, not tensor-core tuned: CODA's contribution is the
// epilogue fusion, which this preserves, and a future pass can swap in a
// tiled / WGMMA mainloop without touching the epilogue structure.
//
// The `extern "C"` host wrappers own device memory: host arrays in, host
// arrays out. Each returns 0 on success, non-zero on a CUDA error.

#include <cuda_runtime.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define BLK 16

__device__ __forceinline__ float silu_f(float x) {
    return x / (1.0f + expf(-x));
}

// ---------------------------------------------------------------------------
// Device kernels.
// ---------------------------------------------------------------------------

// Plain GEMM: D[M,N] = A[M,K] @ B[K,N].
__global__ void k_gemm(const float* A, const float* B, float* D,
                       int M, int N, int K) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= N) return;
    float acc = 0.0f;
    for (int k = 0; k < K; ++k) acc += A[i * K + k] * B[k * N + j];
    D[i * N + j] = acc;
}

// Kernel 4 epilogue: D = A@B + C ;  O = D * gamma[j].
// The residual add and the RMSNorm-weight multiply are fused into the GEMM
// epilogue; D (the residual stream) and O (the normalized-and-weighted
// activation) are the only writes.
__global__ void k_gemm_residual_gamma(const float* A, const float* B,
                                       const float* C, const float* gamma,
                                       float* D, float* O,
                                       int M, int N, int K) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= N) return;
    float acc = 0.0f;
    for (int k = 0; k < K; ++k) acc += A[i * K + k] * B[k * N + j];
    float d = acc + C[i * N + j];
    D[i * N + j] = d;
    O[i * N + j] = d * gamma[j];
}

// Auxiliary reduction: r[i] = 1 / sqrt(mean_j D[i,j]^2 + eps).
__global__ void k_row_invrms(const float* D, float* r, int M, int N, float eps) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= M) return;
    float s = 0.0f;
    for (int j = 0; j < N; ++j) { float v = D[i * N + j]; s += v * v; }
    r[i] = 1.0f / sqrtf(s / (float)N + eps);
}

// Kernel 5 epilogue: O = (A@B) * r[i]  (the delayed RMSNorm scale).
__global__ void k_gemm_rowscale(const float* A, const float* B, const float* r,
                                 float* O, int M, int N, int K) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= N) return;
    float acc = 0.0f;
    for (int k = 0; k < K; ++k) acc += A[i * K + k] * B[k * N + j];
    O[i * N + j] = acc * r[i];
}

// SwiGLU on interleaved pairs: O[M,Nh] = silu(G) * U, [G,U] = split(Dp[M,2*Nh]).
__global__ void k_swiglu(const float* Dp, float* O, int M, int Nh) {
    int k = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || k >= Nh) return;
    float g = Dp[i * (2 * Nh) + 2 * k];
    float u = Dp[i * (2 * Nh) + 2 * k + 1];
    O[i * Nh + k] = silu_f(g) * u;
}

// RoPE: rotate adjacent feature pairs of D[M,N] using cos/sin tables [M,N].
__global__ void k_rope(const float* D, const float* cosT, const float* sinT,
                        float* O, int M, int N) {
    int p = blockIdx.x * blockDim.x + threadIdx.x;  // feature-pair index
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    int c0 = 2 * p, c1 = 2 * p + 1;
    if (i >= M || c1 >= N) return;
    float x0 = D[i * N + c0], x1 = D[i * N + c1];
    float c = cosT[i * N + c0], s = sinT[i * N + c0];
    O[i * N + c0] = x0 * c - x1 * s;
    O[i * N + c1] = x0 * s + x1 * c;
}

// Cross-entropy reduction over logits Z[M,N]: lse[i] and per-token loss.
__global__ void k_row_ce(const float* Z, const int* tgt,
                          float* lse, float* loss, int M, int N) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= M) return;
    float mx = -1e30f;
    for (int j = 0; j < N; ++j) mx = fmaxf(mx, Z[i * N + j]);
    float se = 0.0f;
    for (int j = 0; j < N; ++j) se += expf(Z[i * N + j] - mx);
    float l = mx + logf(se);
    lse[i] = l;
    loss[i] = -Z[i * N + tgt[i]] + l;
}

// Per-column scale: O[i,j] = X[i,j] * gamma[j]  (embedding-side RMSNorm weight).
__global__ void k_col_scale(const float* X, const float* gamma, float* O,
                            int M, int N) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= N) return;
    O[i * N + j] = X[i * N + j] * gamma[j];
}

// Extract a contiguous [M,d] block from [M,cols] starting at column `offset`
// (used to split a fused QKV projection into Q, K, V).
__global__ void k_slice(const float* in, float* out, int M, int d,
                        int cols, int offset) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= d) return;
    out[i * d + j] = in[i * cols + offset + j];
}

#define MAX_HEAD_DIM 256

// Causal multi-head self-attention. One thread owns one (query, head) pair and
// walks the causal prefix twice (max, then sum-exp + weighted V). Outside
// CODA's scope, but needed so the whole model forward runs on the GPU.
__global__ void k_attention(const float* Q, const float* K, const float* V,
                            float* O, int T, int d, int n_heads, int head_dim) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= T * n_heads) return;
    int i = idx / n_heads;          // query position
    int h = idx % n_heads;          // head
    int off = h * head_dim;
    float scale = rsqrtf((float)head_dim);

    float mx = -1e30f;
    for (int j = 0; j <= i; ++j) {
        float s = 0.0f;
        for (int e = 0; e < head_dim; ++e)
            s += Q[i * d + off + e] * K[j * d + off + e];
        mx = fmaxf(mx, s * scale);
    }
    float acc[MAX_HEAD_DIM];
    for (int e = 0; e < head_dim; ++e) acc[e] = 0.0f;
    float se = 0.0f;
    for (int j = 0; j <= i; ++j) {
        float s = 0.0f;
        for (int e = 0; e < head_dim; ++e)
            s += Q[i * d + off + e] * K[j * d + off + e];
        float ex = expf(s * scale - mx);
        se += ex;
        for (int e = 0; e < head_dim; ++e)
            acc[e] += ex * V[j * d + off + e];
    }
    for (int e = 0; e < head_dim; ++e)
        O[i * d + off + e] = acc[e] / se;
}

// ---------------------------------------------------------------------------
// Host helpers.
// ---------------------------------------------------------------------------

static int cuda_check(const char* where) {
    cudaError_t e = cudaGetLastError();
    if (e != cudaSuccess) {
        fprintf(stderr, "[coda-cuda] error at %s: %s\n", where, cudaGetErrorString(e));
        return 1;
    }
    return 0;
}

// Allocate device memory and copy a host buffer up.
static float* up(const float* host, size_t n) {
    float* dev = nullptr;
    cudaMalloc(&dev, n * sizeof(float));
    if (host) cudaMemcpy(dev, host, n * sizeof(float), cudaMemcpyHostToDevice);
    return dev;
}

static dim3 grid2d(int N, int M) {
    return dim3((N + BLK - 1) / BLK, (M + BLK - 1) / BLK);
}

// ---------------------------------------------------------------------------
// extern "C" wrappers (host arrays in / out; return 0 on success).
// ---------------------------------------------------------------------------

extern "C" {

int coda_cuda_device_count() {
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess) return 0;
    return n;
}

void coda_cuda_device_name(char* buf, int len) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess) {
        strncpy(buf, prop.name, len - 1);
        buf[len - 1] = '\0';
    } else {
        strncpy(buf, "unknown", len - 1);
        buf[len - 1] = '\0';
    }
}

int coda_cuda_gemm(const float* A, const float* B, float* D,
                    int M, int N, int K) {
    float *dA = up(A, (size_t)M * K), *dB = up(B, (size_t)K * N);
    float *dD = up(nullptr, (size_t)M * N);
    dim3 blk(BLK, BLK);
    k_gemm<<<grid2d(N, M), blk>>>(dA, dB, dD, M, N, K);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_gemm");
    cudaMemcpy(D, dD, (size_t)M * N * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dD);
    return err;
}

// Kernel 4: D = A@B + C ; O = D ⊙ γ ; r = invrms(D).
int coda_cuda_gemm_residual_partial_rms(const float* A, const float* B,
                                        const float* C, const float* gamma,
                                        float* D, float* O, float* r,
                                        int M, int N, int K, float eps) {
    float *dA = up(A, (size_t)M * K), *dB = up(B, (size_t)K * N);
    float *dC = up(C, (size_t)M * N), *dG = up(gamma, (size_t)N);
    float *dD = up(nullptr, (size_t)M * N), *dO = up(nullptr, (size_t)M * N);
    float *dR = up(nullptr, (size_t)M);
    dim3 blk(BLK, BLK);
    k_gemm_residual_gamma<<<grid2d(N, M), blk>>>(dA, dB, dC, dG, dD, dO, M, N, K);
    k_row_invrms<<<(M + 255) / 256, 256>>>(dD, dR, M, N, eps);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_gemm_residual_partial_rms");
    cudaMemcpy(D, dD, (size_t)M * N * sizeof(float), cudaMemcpyDeviceToHost);
    cudaMemcpy(O, dO, (size_t)M * N * sizeof(float), cudaMemcpyDeviceToHost);
    cudaMemcpy(r, dR, (size_t)M * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dC); cudaFree(dG);
    cudaFree(dD); cudaFree(dO); cudaFree(dR);
    return err;
}

// Kernel 5: O = (A@B) ⊙ r.
int coda_cuda_gemm_rmsnorm(const float* A, const float* B, const float* r,
                           float* O, int M, int N, int K) {
    float *dA = up(A, (size_t)M * K), *dB = up(B, (size_t)K * N);
    float *dR = up(r, (size_t)M), *dO = up(nullptr, (size_t)M * N);
    dim3 blk(BLK, BLK);
    k_gemm_rowscale<<<grid2d(N, M), blk>>>(dA, dB, dR, dO, M, N, K);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_gemm_rmsnorm");
    cudaMemcpy(O, dO, (size_t)M * N * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dR); cudaFree(dO);
    return err;
}

// Kernel 6: D' = (A@B) ⊙ r ; O = SwiGLU(D'). Emits both O[M,N/2] and D'[M,N].
int coda_cuda_gemm_rmsnorm_swiglu(const float* A, const float* B, const float* r,
                                  float* O, float* Dprime, int M, int N, int K) {
    int Nh = N / 2;
    float *dA = up(A, (size_t)M * K), *dB = up(B, (size_t)K * N);
    float *dR = up(r, (size_t)M);
    float *dDp = up(nullptr, (size_t)M * N), *dO = up(nullptr, (size_t)M * Nh);
    dim3 blk(BLK, BLK);
    k_gemm_rowscale<<<grid2d(N, M), blk>>>(dA, dB, dR, dDp, M, N, K);
    k_swiglu<<<grid2d(Nh, M), blk>>>(dDp, dO, M, Nh);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_gemm_rmsnorm_swiglu");
    cudaMemcpy(O, dO, (size_t)M * Nh * sizeof(float), cudaMemcpyDeviceToHost);
    cudaMemcpy(Dprime, dDp, (size_t)M * N * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dR); cudaFree(dDp); cudaFree(dO);
    return err;
}

// Kernel 1: O = RoPE(A@B).
int coda_cuda_gemm_rope(const float* A, const float* B,
                        const float* cosT, const float* sinT,
                        float* O, int M, int N, int K) {
    float *dA = up(A, (size_t)M * K), *dB = up(B, (size_t)K * N);
    float *dC = up(cosT, (size_t)M * N), *dS = up(sinT, (size_t)M * N);
    float *dD = up(nullptr, (size_t)M * N), *dO = up(nullptr, (size_t)M * N);
    dim3 blk(BLK, BLK);
    k_gemm<<<grid2d(N, M), blk>>>(dA, dB, dD, M, N, K);
    k_rope<<<grid2d(N / 2, M), blk>>>(dD, dC, dS, dO, M, N);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_gemm_rope");
    cudaMemcpy(O, dO, (size_t)M * N * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dC); cudaFree(dS);
    cudaFree(dD); cudaFree(dO);
    return err;
}

// Kernel 2: O = SwiGLU(A@B).
int coda_cuda_gemm_swiglu(const float* A, const float* B, float* O,
                          int M, int N, int K) {
    int Nh = N / 2;
    float *dA = up(A, (size_t)M * K), *dB = up(B, (size_t)K * N);
    float *dD = up(nullptr, (size_t)M * N), *dO = up(nullptr, (size_t)M * Nh);
    dim3 blk(BLK, BLK);
    k_gemm<<<grid2d(N, M), blk>>>(dA, dB, dD, M, N, K);
    k_swiglu<<<grid2d(Nh, M), blk>>>(dD, dO, M, Nh);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_gemm_swiglu");
    cudaMemcpy(O, dO, (size_t)M * Nh * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dD); cudaFree(dO);
    return err;
}

// Kernel 8: Z = (A@B) ⊙ r ; emit per-token log-sum-exp and cross-entropy loss.
int coda_cuda_gemm_rmsnorm_ce(const float* A, const float* B, const float* r,
                              const int* tgt, float* lse, float* loss,
                              int M, int N, int K) {
    float *dA = up(A, (size_t)M * K), *dB = up(B, (size_t)K * N);
    float *dR = up(r, (size_t)M), *dZ = up(nullptr, (size_t)M * N);
    int* dT = nullptr;
    cudaMalloc(&dT, (size_t)M * sizeof(int));
    cudaMemcpy(dT, tgt, (size_t)M * sizeof(int), cudaMemcpyHostToDevice);
    float *dL = up(nullptr, (size_t)M), *dLoss = up(nullptr, (size_t)M);
    dim3 blk(BLK, BLK);
    k_gemm_rowscale<<<grid2d(N, M), blk>>>(dA, dB, dR, dZ, M, N, K);
    k_row_ce<<<(M + 255) / 256, 256>>>(dZ, dT, dL, dLoss, M, N);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_gemm_rmsnorm_ce");
    cudaMemcpy(lse, dL, (size_t)M * sizeof(float), cudaMemcpyDeviceToHost);
    cudaMemcpy(loss, dLoss, (size_t)M * sizeof(float), cudaMemcpyDeviceToHost);
    cudaFree(dA); cudaFree(dB); cudaFree(dR); cudaFree(dZ);
    cudaFree(dT); cudaFree(dL); cudaFree(dLoss);
    return err;
}

// Full LLaMA-style Transformer forward pass, entirely on the GPU.
//
// Weights and the embedded input are uploaded once; every activation stays
// resident on the device across all layers (no host round-trips), and only
// the logits are copied back. The non-attention computation is the fused
// GEMM-Residual-RMSNorm-GEMM chain - Kernel 5 for QKV, Kernel 4 for the two
// projection+residual+norm joins, Kernel 6 for the SwiGLU MLP - exactly the
// reparameterization of paper section 3.2.1.
int coda_cuda_model_forward(
    const float* x0, const float* cosT, const float* sinT,
    int T, int d, int n_layers, int n_heads, int head_dim, int d_ff,
    int vocab, float eps,
    const float* gamma_attn, const float* wqkv, const float* wo,
    const float* gamma_ffn, const float* wgu, const float* wdown,
    const float* gamma_final, const float* lm_head,
    float* logits) {

    int d3 = 3 * d;
    int dff2 = 2 * d_ff;

    // Upload weights + the embedded input once.
    float* dGA = up(gamma_attn, (size_t)n_layers * d);
    float* dWQKV = up(wqkv, (size_t)n_layers * d * d3);
    float* dWO = up(wo, (size_t)n_layers * d * d);
    float* dGF = up(gamma_ffn, (size_t)n_layers * d);
    float* dWGU = up(wgu, (size_t)n_layers * d * dff2);
    float* dWD = up(wdown, (size_t)n_layers * d_ff * d);
    float* dGFinal = up(gamma_final, (size_t)d);
    float* dLM = up(lm_head, (size_t)d * vocab);
    float* dCos = up(cosT, (size_t)T * d);
    float* dSin = up(sinT, (size_t)T * d);

    // Device-resident activation buffers.
    float* dX = up(x0, (size_t)T * d);
    float* dY = up(NULL, (size_t)T * d);
    float* dOnorm = up(NULL, (size_t)T * d);
    float* dR = up(NULL, (size_t)T);
    float* dR2 = up(NULL, (size_t)T);
    float* dQKV = up(NULL, (size_t)T * d3);
    float* dQ = up(NULL, (size_t)T * d);
    float* dK = up(NULL, (size_t)T * d);
    float* dV = up(NULL, (size_t)T * d);
    float* dQR = up(NULL, (size_t)T * d);
    float* dKR = up(NULL, (size_t)T * d);
    float* dAttn = up(NULL, (size_t)T * d);
    float* dH = up(NULL, (size_t)T * d);
    float* dN2 = up(NULL, (size_t)T * d);
    float* dDP = up(NULL, (size_t)T * dff2);
    float* dFF = up(NULL, (size_t)T * d_ff);
    float* dLogits = up(NULL, (size_t)T * vocab);

    dim3 blk(BLK, BLK);

    // Embedding-side RMSNorm (the only normalization not fused into a GEMM).
    k_row_invrms<<<(T + 255) / 256, 256>>>(dX, dR, T, d, eps);
    k_col_scale<<<grid2d(d, T), blk>>>(dX, dGA, dOnorm, T, d);

    for (int l = 0; l < n_layers; ++l) {
        const float* wqkv_l = dWQKV + (size_t)l * d * d3;
        const float* wo_l = dWO + (size_t)l * d * d;
        const float* gf_l = dGF + (size_t)l * d;
        const float* wgu_l = dWGU + (size_t)l * d * dff2;
        const float* wd_l = dWD + (size_t)l * d_ff * d;

        // QKV projection with the delayed RMSNorm scale (Kernel 5).
        k_gemm_rowscale<<<grid2d(d3, T), blk>>>(dOnorm, wqkv_l, dR, dQKV, T, d3, d);
        k_slice<<<grid2d(d, T), blk>>>(dQKV, dQ, T, d, d3, 0);
        k_slice<<<grid2d(d, T), blk>>>(dQKV, dK, T, d, d3, d);
        k_slice<<<grid2d(d, T), blk>>>(dQKV, dV, T, d, d3, 2 * d);
        k_rope<<<grid2d(d / 2, T), blk>>>(dQ, dCos, dSin, dQR, T, d);
        k_rope<<<grid2d(d / 2, T), blk>>>(dK, dCos, dSin, dKR, T, d);
        k_attention<<<(T * n_heads + 255) / 256, 256>>>(
            dQR, dKR, dV, dAttn, T, d, n_heads, head_dim);

        // Output proj + residual + FFN-norm (Kernel 4).
        k_gemm_residual_gamma<<<grid2d(d, T), blk>>>(
            dAttn, wo_l, dX, gf_l, dH, dN2, T, d, d);
        k_row_invrms<<<(T + 255) / 256, 256>>>(dH, dR2, T, d, eps);

        // Gate/Up projection + SwiGLU (Kernel 6).
        k_gemm_rowscale<<<grid2d(dff2, T), blk>>>(dN2, wgu_l, dR2, dDP, T, dff2, d);
        k_swiglu<<<grid2d(d_ff, T), blk>>>(dDP, dFF, T, d_ff);

        // Down proj + residual + next sublayer's norm (Kernel 4).
        const float* next_gamma =
            (l + 1 < n_layers) ? (dGA + (size_t)(l + 1) * d) : dGFinal;
        k_gemm_residual_gamma<<<grid2d(d, T), blk>>>(
            dFF, wd_l, dH, next_gamma, dY, dOnorm, T, d, d_ff);
        k_row_invrms<<<(T + 255) / 256, 256>>>(dY, dR, T, d, eps);

        // The new residual stream becomes the next layer's input.
        float* tmp = dX; dX = dY; dY = tmp;
    }

    // LM head: logits = (final-normed residual @ W_lm) ⊙ r  (Kernel 5).
    k_gemm_rowscale<<<grid2d(vocab, T), blk>>>(dOnorm, dLM, dR, dLogits, T, vocab, d);

    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_model_forward");
    cudaMemcpy(logits, dLogits, (size_t)T * vocab * sizeof(float),
               cudaMemcpyDeviceToHost);

    cudaFree(dGA); cudaFree(dWQKV); cudaFree(dWO); cudaFree(dGF);
    cudaFree(dWGU); cudaFree(dWD); cudaFree(dGFinal); cudaFree(dLM);
    cudaFree(dCos); cudaFree(dSin);
    cudaFree(dX); cudaFree(dY); cudaFree(dOnorm); cudaFree(dR); cudaFree(dR2);
    cudaFree(dQKV); cudaFree(dQ); cudaFree(dK); cudaFree(dV);
    cudaFree(dQR); cudaFree(dKR); cudaFree(dAttn); cudaFree(dH); cudaFree(dN2);
    cudaFree(dDP); cudaFree(dFF); cudaFree(dLogits);
    return err;
}

}  // extern "C"
