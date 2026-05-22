// CUDA backend for the CODA GEMM-plus-epilogue kernels.
//
// This is the GPU realization of the abstraction in `src/gemm.rs` /
// `src/epilogue.rs`: a GEMM mainloop whose output tile is transformed by a
// fused epilogue *before* it is written to global memory.
//
// The mainloop is a **register-blocked** shared-memory GEMM (`k_gemm_epi`):
// each thread block stages BM x BK / BK x BN slabs through shared memory and
// every thread keeps a TM x TN micro-tile of the result in registers. The
// epilogue is selected by a compile-time template parameter, so the same
// fixed mainloop serves the plain GEMM, the residual+RMSNorm-weight join
// (Kernel 4) and the delayed RMSNorm scale (Kernels 5/6/8) - CODA's "fixed
// mainloop, programmable epilogue" design.
//
// The `extern "C"` host wrappers own device memory: host arrays in, host
// arrays out. Each returns 0 on success, non-zero on a CUDA error.

#include <cuda_runtime.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define BLK 16
#define MAX_HEAD_DIM 256

__device__ __forceinline__ float silu_f(float x) {
    return x / (1.0f + expf(-x));
}

// Epilogue modes for the templated tiled GEMM.
enum { EPI_PLAIN = 0, EPI_RESGAMMA = 1, EPI_ROWSCALE = 2 };

// ---------------------------------------------------------------------------
// The fixed GEMM mainloop: a **register-blocked** shared-memory tiled GEMM
// with a fused epilogue.
//
// A thread block computes a BM x BN output tile; the K dimension is streamed
// in BK-deep slabs through shared memory, and each of the 256 threads keeps a
// TM x TN micro-tile of the result in registers (an outer-product update per
// k step). This is the standard high-arithmetic-intensity SGEMM; the epilogue
// (selected by the compile-time MODE) is applied to the register accumulators
// before the single global-memory store, exactly as in the CPU port.
//
//   EPI_PLAIN    : D = A @ B
//   EPI_RESGAMMA : D = A@B + C ;  O = D * gamma[col]      (Kernel 4)
//   EPI_ROWSCALE : O = (A@B) * r[row]                     (Kernels 5/6/8)
//
// Unused epilogue operands are passed as nullptr; the dead template branches
// are eliminated at compile time.
// ---------------------------------------------------------------------------
#define BM 64
#define BN 64
#define BK 8
#define TM 4
#define TN 4
#define GEMM_THREADS 256  // (BM/TM) * (BN/TN)

template <int MODE>
__global__ void k_gemm_epi(const float* A, const float* B, const float* C,
                           const float* gamma, const float* r,
                           float* D, float* O, int M, int N, int K) {
    __shared__ float As[BK * BM];  // As[k*BM + m]
    __shared__ float Bs[BK * BN];  // Bs[k*BN + n]

    int c_row = blockIdx.y;  // output tile row (along M)
    int c_col = blockIdx.x;  // output tile col (along N)
    int tid = threadIdx.x;   // 0 .. 255
    int t_row = tid / (BN / TN);  // 0 .. 15
    int t_col = tid % (BN / TN);  // 0 .. 15

    float acc[TM * TN];
#pragma unroll
    for (int i = 0; i < TM * TN; ++i) acc[i] = 0.0f;
    float a_reg[TM], b_reg[TN];

    for (int k0 = 0; k0 < K; k0 += BK) {
        // Cooperatively stage the BM x BK slab of A and BK x BN slab of B.
        for (int ld = 0; ld < (BM * BK) / GEMM_THREADS; ++ld) {
            int idx = tid + ld * GEMM_THREADS;  // 0 .. BM*BK-1
            int m = idx / BK, k = idx % BK;
            int gm = c_row * BM + m, gk = k0 + k;
            As[k * BM + m] = (gm < M && gk < K) ? A[gm * K + gk] : 0.0f;
        }
        for (int ld = 0; ld < (BK * BN) / GEMM_THREADS; ++ld) {
            int idx = tid + ld * GEMM_THREADS;  // 0 .. BK*BN-1
            int k = idx / BN, n = idx % BN;
            int gk = k0 + k, gn = c_col * BN + n;
            Bs[k * BN + n] = (gk < K && gn < N) ? B[gk * N + gn] : 0.0f;
        }
        __syncthreads();
#pragma unroll
        for (int kk = 0; kk < BK; ++kk) {
#pragma unroll
            for (int i = 0; i < TM; ++i) a_reg[i] = As[kk * BM + t_row * TM + i];
#pragma unroll
            for (int j = 0; j < TN; ++j) b_reg[j] = Bs[kk * BN + t_col * TN + j];
#pragma unroll
            for (int i = 0; i < TM; ++i)
#pragma unroll
                for (int j = 0; j < TN; ++j)
                    acc[i * TN + j] += a_reg[i] * b_reg[j];
        }
        __syncthreads();
    }

    // Fused epilogue on the register accumulators, then a single store.
    for (int i = 0; i < TM; ++i) {
        int row = c_row * BM + t_row * TM + i;
        if (row >= M) continue;
        for (int j = 0; j < TN; ++j) {
            int col = c_col * BN + t_col * TN + j;
            if (col >= N) continue;
            float a = acc[i * TN + j];
            if (MODE == EPI_PLAIN) {
                D[row * N + col] = a;
            } else if (MODE == EPI_RESGAMMA) {
                float d = a + C[row * N + col];
                D[row * N + col] = d;
                O[row * N + col] = d * gamma[col];
            } else if (MODE == EPI_ROWSCALE) {
                O[row * N + col] = a * r[row];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tensor-core mainloop: a TF32 WMMA GEMM with the same fused epilogue.
//
// On Ampere+ (sm_80) each warp computes a 16x16 output tile with the TF32
// tensor cores (16x16x8 fragments, fp32 accumulate). TF32 keeps ~10 mantissa
// bits, so results stay within ~1e-3 of fp32 - well inside the verification
// tolerances - while running on the tensor-core datapath. The accumulator is
// staged through shared memory so the *same* fused epilogue runs before the
// global store. Compiled out below sm_80; the host dispatch never calls it
// there. Used only when M,N are multiples of 16 and K of 8 (the model's GEMM
// shapes); ragged shapes fall back to the register-blocked kernel.
// ---------------------------------------------------------------------------
#include <mma.h>

#define TC_WARPS 8  // warps per block

template <int MODE>
__global__ void k_gemm_tc(const float* A, const float* B, const float* C,
                          const float* gamma, const float* r,
                          float* D, float* O, int M, int N, int K) {
#if __CUDA_ARCH__ >= 800
    using namespace nvcuda;
    int warp = (blockIdx.x * blockDim.x + threadIdx.x) / 32;
    int lane = threadIdx.x & 31;
    int tiles_n = N / 16;
    int tile_m = warp / tiles_n;
    int tile_n = warp % tiles_n;
    if (tile_m * 16 >= M) return;

    wmma::fragment<wmma::accumulator, 16, 16, 8, float> acc;
    wmma::fill_fragment(acc, 0.0f);
    for (int k0 = 0; k0 < K; k0 += 8) {
        wmma::fragment<wmma::matrix_a, 16, 16, 8, wmma::precision::tf32,
                       wmma::row_major> af;
        wmma::fragment<wmma::matrix_b, 16, 16, 8, wmma::precision::tf32,
                       wmma::row_major> bf;
        wmma::load_matrix_sync(af, A + (tile_m * 16) * K + k0, K);
        wmma::load_matrix_sync(bf, B + k0 * N + tile_n * 16, N);
#pragma unroll
        for (int i = 0; i < af.num_elements; ++i)
            af.x[i] = wmma::__float_to_tf32(af.x[i]);
#pragma unroll
        for (int i = 0; i < bf.num_elements; ++i)
            bf.x[i] = wmma::__float_to_tf32(bf.x[i]);
        wmma::mma_sync(acc, af, bf, acc);
    }

    // Stage the 16x16 tile in shared memory, then run the fused epilogue.
    extern __shared__ float sh[];
    float* tile = sh + (threadIdx.x / 32) * 256;
    wmma::store_matrix_sync(tile, acc, 16, wmma::mem_row_major);
    for (int idx = lane; idx < 256; idx += 32) {
        int row = tile_m * 16 + idx / 16;
        int col = tile_n * 16 + idx % 16;
        float a = tile[idx];
        if (MODE == EPI_PLAIN) {
            D[row * N + col] = a;
        } else if (MODE == EPI_RESGAMMA) {
            float d = a + C[row * N + col];
            D[row * N + col] = d;
            O[row * N + col] = d * gamma[col];
        } else if (MODE == EPI_ROWSCALE) {
            O[row * N + col] = a * r[row];
        }
    }
#endif
}

// True when device 0 has tensor cores (compute capability >= 8.0).
static bool tensor_cores_available() {
    static int cached = -1;
    if (cached < 0) {
        cudaDeviceProp p;
        cached = (cudaGetDeviceProperties(&p, 0) == cudaSuccess && p.major >= 8)
                     ? 1 : 0;
    }
    return cached == 1;
}

// Launch the GEMM: TF32 tensor cores on Ampere+ for aligned shapes, otherwise
// the register-blocked kernel. Both apply the same fused epilogue.
template <int MODE>
static void launch_gemm(const float* A, const float* B, const float* C,
                        const float* gamma, const float* r, float* D, float* O,
                        int M, int N, int K) {
    if (tensor_cores_available() && M % 16 == 0 && N % 16 == 0 && K % 8 == 0) {
        int total_warps = (M / 16) * (N / 16);
        int blocks = (total_warps + TC_WARPS - 1) / TC_WARPS;
        size_t shmem = (size_t)TC_WARPS * 256 * sizeof(float);
        k_gemm_tc<MODE><<<blocks, TC_WARPS * 32, shmem>>>(
            A, B, C, gamma, r, D, O, M, N, K);
    } else {
        dim3 grid((N + BN - 1) / BN, (M + BM - 1) / BM);
        k_gemm_epi<MODE><<<grid, GEMM_THREADS>>>(A, B, C, gamma, r, D, O, M, N, K);
    }
}

// ---------------------------------------------------------------------------
// Auxiliary / elementwise kernels (memory-bound, no tiling needed).
// ---------------------------------------------------------------------------

// Auxiliary reduction: r[i] = 1 / sqrt(mean_j D[i,j]^2 + eps).
__global__ void k_row_invrms(const float* D, float* r, int M, int N, float eps) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= M) return;
    float s = 0.0f;
    for (int j = 0; j < N; ++j) { float v = D[i * N + j]; s += v * v; }
    r[i] = 1.0f / sqrtf(s / (float)N + eps);
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

// Extract a contiguous [M,d] block from [M,cols] starting at column `offset`.
__global__ void k_slice(const float* in, float* out, int M, int d,
                        int cols, int offset) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= d) return;
    out[i * d + j] = in[i * cols + offset + j];
}

// Causal multi-head self-attention - one thread BLOCK per (query, head).
//
// The block's threads cooperatively compute the causal score row, reduce it
// (max, sum-exp) through shared memory, then thread `e` writes output feature
// `e`. This launches T*n_heads blocks (vs. that many *threads* before), so the
// GPU is actually filled. If `P` is non-null the softmax row is also written
// out, so the backward pass need not recompute it.
#define ATTN_THREADS 256
#define ATTN_TMAX 1024  // maximum supported sequence length

__global__ void k_attention(const float* Q, const float* K, const float* V,
                            float* O, float* P, int T, int d, int n_heads,
                            int head_dim) {
    int i = blockIdx.x / n_heads;   // query position
    int h = blockIdx.x % n_heads;   // head
    int off = h * head_dim;
    int t = threadIdx.x;
    float scale = rsqrtf((float)head_dim);

    __shared__ float sc[ATTN_TMAX];   // scores -> probs for this row
    __shared__ float red[ATTN_THREADS];

    for (int j = t; j <= i; j += ATTN_THREADS) {
        float s = 0.0f;
        for (int e = 0; e < head_dim; ++e)
            s += Q[i * d + off + e] * K[j * d + off + e];
        sc[j] = s * scale;
    }
    __syncthreads();

    // Row max.
    float m = -1e30f;
    for (int j = t; j <= i; j += ATTN_THREADS) m = fmaxf(m, sc[j]);
    red[t] = m;
    __syncthreads();
    for (int s = ATTN_THREADS / 2; s > 0; s >>= 1) {
        if (t < s) red[t] = fmaxf(red[t], red[t + s]);
        __syncthreads();
    }
    float mx = red[0];
    __syncthreads();

    // Exp + row sum.
    float partial = 0.0f;
    for (int j = t; j <= i; j += ATTN_THREADS) {
        float e = expf(sc[j] - mx);
        sc[j] = e;
        partial += e;
    }
    red[t] = partial;
    __syncthreads();
    for (int s = ATTN_THREADS / 2; s > 0; s >>= 1) {
        if (t < s) red[t] += red[t + s];
        __syncthreads();
    }
    float se = red[0];
    __syncthreads();

    // Normalize to probabilities; optionally save the row for the backward pass.
    for (int j = t; j <= i; j += ATTN_THREADS) {
        float p = sc[j] / se;
        sc[j] = p;
        if (P) P[((size_t)h * T + i) * T + j] = p;
    }
    __syncthreads();

    // Output: thread `e` reduces the weighted value column.
    if (t < head_dim) {
        float acc = 0.0f;
        for (int j = 0; j <= i; ++j) acc += sc[j] * V[j * d + off + t];
        O[i * d + off + t] = acc;
    }
}

// ---------------------------------------------------------------------------
// Backward-pass kernels (paper Theorem 1: tile-local backward rules + GEMMs).
// ---------------------------------------------------------------------------

// Embedding gather: x0[i,j] = embed[tokens[i], j].
__global__ void k_embed_gather(const float* embed, const int* tokens,
                               float* x0, int T, int d) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= T || j >= d) return;
    x0[i * d + j] = embed[tokens[i] * d + j];
}

// Cross-entropy gradient + per-token loss: d_logits = (softmax - onehot)/T.
__global__ void k_ce_grad(const float* logits, const int* tgt,
                          float* dlog, float* loss_row, int T, int V) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= T) return;
    float mx = -1e30f;
    for (int j = 0; j < V; ++j) mx = fmaxf(mx, logits[i * V + j]);
    float se = 0.0f;
    for (int j = 0; j < V; ++j) se += expf(logits[i * V + j] - mx);
    float lse = mx + logf(se);
    loss_row[i] = lse - logits[i * V + tgt[i]];
    float inv_t = 1.0f / (float)T;
    for (int j = 0; j < V; ++j) {
        float p = expf(logits[i * V + j] - mx) / se;
        dlog[i * V + j] = (p - (j == tgt[i] ? 1.0f : 0.0f)) * inv_t;
    }
}

// C[M,N] = A @ Bᵀ, with A [M,K] and B [N,K]  (activation-gradient GEMM).
// Register-blocked, same scheme as k_gemm_epi; only the B load is transposed.
__global__ void k_gemm_nt(const float* A, const float* B, float* C,
                          int M, int N, int K) {
    __shared__ float As[BK * BM];
    __shared__ float Bs[BK * BN];
    int c_row = blockIdx.y, c_col = blockIdx.x;
    int tid = threadIdx.x;
    int t_row = tid / (BN / TN), t_col = tid % (BN / TN);
    float acc[TM * TN];
#pragma unroll
    for (int i = 0; i < TM * TN; ++i) acc[i] = 0.0f;
    float a_reg[TM], b_reg[TN];
    for (int k0 = 0; k0 < K; k0 += BK) {
        for (int ld = 0; ld < (BM * BK) / GEMM_THREADS; ++ld) {
            int idx = tid + ld * GEMM_THREADS;
            int m = idx / BK, k = idx % BK;
            int gm = c_row * BM + m, gk = k0 + k;
            As[k * BM + m] = (gm < M && gk < K) ? A[gm * K + gk] : 0.0f;
        }
        for (int ld = 0; ld < (BK * BN) / GEMM_THREADS; ++ld) {
            int idx = tid + ld * GEMM_THREADS;
            int k = idx / BN, n = idx % BN;
            int gk = k0 + k, gn = c_col * BN + n;
            Bs[k * BN + n] = (gk < K && gn < N) ? B[gn * K + gk] : 0.0f;
        }
        __syncthreads();
#pragma unroll
        for (int kk = 0; kk < BK; ++kk) {
#pragma unroll
            for (int i = 0; i < TM; ++i) a_reg[i] = As[kk * BM + t_row * TM + i];
#pragma unroll
            for (int j = 0; j < TN; ++j) b_reg[j] = Bs[kk * BN + t_col * TN + j];
#pragma unroll
            for (int i = 0; i < TM; ++i)
#pragma unroll
                for (int j = 0; j < TN; ++j)
                    acc[i * TN + j] += a_reg[i] * b_reg[j];
        }
        __syncthreads();
    }
    for (int i = 0; i < TM; ++i) {
        int row = c_row * BM + t_row * TM + i;
        if (row >= M) continue;
        for (int j = 0; j < TN; ++j) {
            int col = c_col * BN + t_col * TN + j;
            if (col < N) C[row * N + col] = acc[i * TN + j];
        }
    }
}

static void launch_gemm_nt(const float* A, const float* B, float* C,
                           int M, int N, int K) {
    dim3 grid((N + BN - 1) / BN, (M + BM - 1) / BM);
    k_gemm_nt<<<grid, GEMM_THREADS>>>(A, B, C, M, N, K);
}

// C[K,N] = Aᵀ @ B, with A [M,K] and B [M,N]  (weight-gradient GEMM).
// Register-blocked; the output is [K,N] and the contraction runs over M.
__global__ void k_gemm_tn(const float* A, const float* B, float* C,
                          int M, int K, int N) {
    __shared__ float As[BK * BM];  // As[slab][r], r over output rows (K)
    __shared__ float Bs[BK * BN];  // Bs[slab][c], c over output cols (N)
    int c_row = blockIdx.y, c_col = blockIdx.x;
    int tid = threadIdx.x;
    int t_row = tid / (BN / TN), t_col = tid % (BN / TN);
    float acc[TM * TN];
#pragma unroll
    for (int i = 0; i < TM * TN; ++i) acc[i] = 0.0f;
    float a_reg[TM], b_reg[TN];
    for (int m0 = 0; m0 < M; m0 += BK) {
        for (int ld = 0; ld < (BM * BK) / GEMM_THREADS; ++ld) {
            int idx = tid + ld * GEMM_THREADS;
            int r = idx / BK, k = idx % BK;
            int gr = c_row * BM + r, gm = m0 + k;
            As[k * BM + r] = (gr < K && gm < M) ? A[gm * K + gr] : 0.0f;
        }
        for (int ld = 0; ld < (BK * BN) / GEMM_THREADS; ++ld) {
            int idx = tid + ld * GEMM_THREADS;
            int k = idx / BN, c = idx % BN;
            int gm = m0 + k, gc = c_col * BN + c;
            Bs[k * BN + c] = (gm < M && gc < N) ? B[gm * N + gc] : 0.0f;
        }
        __syncthreads();
#pragma unroll
        for (int kk = 0; kk < BK; ++kk) {
#pragma unroll
            for (int i = 0; i < TM; ++i) a_reg[i] = As[kk * BM + t_row * TM + i];
#pragma unroll
            for (int j = 0; j < TN; ++j) b_reg[j] = Bs[kk * BN + t_col * TN + j];
#pragma unroll
            for (int i = 0; i < TM; ++i)
#pragma unroll
                for (int j = 0; j < TN; ++j)
                    acc[i * TN + j] += a_reg[i] * b_reg[j];
        }
        __syncthreads();
    }
    for (int i = 0; i < TM; ++i) {
        int row = c_row * BM + t_row * TM + i;
        if (row >= K) continue;
        for (int j = 0; j < TN; ++j) {
            int col = c_col * BN + t_col * TN + j;
            if (col < N) C[row * N + col] = acc[i * TN + j];
        }
    }
}

static void launch_gemm_tn(const float* A, const float* B, float* C,
                           int M, int K, int N) {
    dim3 grid((N + BN - 1) / BN, (K + BM - 1) / BM);
    k_gemm_tn<<<grid, GEMM_THREADS>>>(A, B, C, M, K, N);
}

// RMSNorm backward (local rule of Kernel 9). One thread per row.
//   d_nrm = d_n ⊙ γ ;  S = Σ d_nrm⊙x
//   d_x   = r·d_nrm - (r³/N)·x·S ;  d_γ += Σ_rows d_n⊙x·r
__global__ void k_rmsnorm_bwd(const float* x, const float* r, const float* gamma,
                              const float* dn, float* dx, float* dgamma,
                              int M, int N) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= M) return;
    float ri = r[i];
    float S = 0.0f;
    for (int j = 0; j < N; ++j) S += (dn[i * N + j] * gamma[j]) * x[i * N + j];
    float r3 = ri * ri * ri;
    for (int j = 0; j < N; ++j) {
        float d_nrm = dn[i * N + j] * gamma[j];
        dx[i * N + j] = ri * d_nrm - (r3 / (float)N) * x[i * N + j] * S;
        atomicAdd(&dgamma[j], dn[i * N + j] * x[i * N + j] * ri);
    }
}

// SwiGLU backward (epilogue of Kernel 10).
__global__ void k_swiglu_bwd(const float* gu, const float* dff, float* dgu,
                             int M, int F) {
    int k = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || k >= F) return;
    float g = gu[i * (2 * F) + 2 * k];
    float u = gu[i * (2 * F) + 2 * k + 1];
    float d_o = dff[i * F + k];
    float sg = silu_f(g);
    float sig = 1.0f / (1.0f + expf(-g));
    float d_silu = sig + sg * (1.0f - sig);
    dgu[i * (2 * F) + 2 * k] = d_o * u * d_silu;
    dgu[i * (2 * F) + 2 * k + 1] = d_o * sg;
}

// RoPE backward: rotation by the negated angle.
__global__ void k_rope_bwd(const float* dout, const float* cosT,
                           const float* sinT, float* din, int M, int N) {
    int p = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    int c0 = 2 * p, c1 = 2 * p + 1;
    if (i >= M || c1 >= N) return;
    float g0 = dout[i * N + c0], g1 = dout[i * N + c1];
    float c = cosT[i * N + c0], s = sinT[i * N + c0];
    din[i * N + c0] = g0 * c + g1 * s;
    din[i * N + c1] = -g0 * s + g1 * c;
}

// Attention backward, atomic-free. The saved softmax matrix P makes the three
// gradients independent reductions, each block-per-position so the GPU fills.
//
// 1. k_attn_dscore: block per (query i, head h) computes the score-gradient
//    row  DS[i,j] = P[i,j]·(dP[i,j] - Σ_j P[i,j]·dP[i,j]),  dP[i,j]=dO[i]·V[j].
__global__ void k_attn_dscore(const float* dO, const float* V, const float* P,
                              float* DS, int T, int d, int n_heads,
                              int head_dim) {
    int i = blockIdx.x / n_heads;
    int h = blockIdx.x % n_heads;
    int off = h * head_dim;
    int t = threadIdx.x;
    __shared__ float dp[ATTN_TMAX];
    __shared__ float red[ATTN_THREADS];

    for (int j = t; j <= i; j += ATTN_THREADS) {
        float s = 0.0f;
        for (int e = 0; e < head_dim; ++e)
            s += dO[i * d + off + e] * V[j * d + off + e];
        dp[j] = s;
    }
    __syncthreads();
    float partial = 0.0f;
    for (int j = t; j <= i; j += ATTN_THREADS)
        partial += P[((size_t)h * T + i) * T + j] * dp[j];
    red[t] = partial;
    __syncthreads();
    for (int s = ATTN_THREADS / 2; s > 0; s >>= 1) {
        if (t < s) red[t] += red[t + s];
        __syncthreads();
    }
    float dotsum = red[0];
    __syncthreads();
    for (int j = t; j <= i; j += ATTN_THREADS) {
        float p = P[((size_t)h * T + i) * T + j];
        DS[((size_t)h * T + i) * T + j] = p * (dp[j] - dotsum);
    }
}

// 2. k_attn_dq: block per (query i, head h), thread `e` owns dQ[i,h,e].
__global__ void k_attn_dq(const float* DS, const float* K, float* dQ,
                          int T, int d, int n_heads, int head_dim) {
    int i = blockIdx.x / n_heads;
    int h = blockIdx.x % n_heads;
    int off = h * head_dim;
    int e = threadIdx.x;
    if (e >= head_dim) return;
    float scale = rsqrtf((float)head_dim);
    float acc = 0.0f;
    for (int j = 0; j <= i; ++j)
        acc += DS[((size_t)h * T + i) * T + j] * K[j * d + off + e];
    dQ[i * d + off + e] = scale * acc;
}

// 3. k_attn_dkv: block per (key j, head h), thread `e` owns dK[j,h,e] and
//    dV[j,h,e]. Each is a reduction over the queries i >= j - no atomics.
__global__ void k_attn_dkv(const float* P, const float* DS, const float* dO,
                           const float* Q, float* dK, float* dV,
                           int T, int d, int n_heads, int head_dim) {
    int j = blockIdx.x / n_heads;
    int h = blockIdx.x % n_heads;
    int off = h * head_dim;
    int e = threadIdx.x;
    if (e >= head_dim) return;
    float scale = rsqrtf((float)head_dim);
    float dv = 0.0f, dk = 0.0f;
    for (int i = j; i < T; ++i) {
        dv += P[((size_t)h * T + i) * T + j] * dO[i * d + off + e];
        dk += DS[((size_t)h * T + i) * T + j] * Q[i * d + off + e];
    }
    dV[j * d + off + e] = dv;
    dK[j * d + off + e] = scale * dk;
}

// Embedding backward: scatter-add the input gradient into the table.
__global__ void k_embed_bwd(const float* dx0, const int* tokens,
                            float* dembed, int T, int d) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= T || j >= d) return;
    atomicAdd(&dembed[tokens[i] * d + j], dx0[i * d + j]);
}

// Recompute a normalized activation: out = (x ⊙ r) ⊙ γ.
__global__ void k_rmsnorm_apply(const float* x, const float* r,
                                const float* gamma, float* out, int M, int N) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= N) return;
    out[i * N + j] = x[i * N + j] * r[i] * gamma[j];
}

// In-place elementwise accumulate: a += b.
__global__ void k_add(float* a, const float* b, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) a[i] += b[i];
}

// Write a [M,d] block into a wider [M,cols] matrix at column `offset`.
__global__ void k_paste(const float* src, float* dst, int M, int d,
                        int cols, int offset) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= M || j >= d) return;
    dst[i * cols + offset + j] = src[i * d + j];
}

// One Adam step over a parameter tensor (64-bit element count: tensors of a
// multi-billion-parameter model exceed 2^31 elements).
__global__ void k_adam(float* p, const float* g, float* m, float* v, long n,
                       float lr, float b1, float b2, float eps, int t) {
    long i = (long)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    m[i] = b1 * m[i] + (1.0f - b1) * g[i];
    v[i] = b2 * v[i] + (1.0f - b2) * g[i] * g[i];
    float mhat = m[i] / (1.0f - powf(b1, (float)t));
    float vhat = v[i] / (1.0f - powf(b2, (float)t));
    p[i] -= lr * mhat / (sqrtf(vhat) + eps);
}

// One plain-SGD step. Used instead of Adam for multi-billion-parameter models,
// where Adam's two extra moment tensors would not fit in GPU memory.
__global__ void k_sgd(float* p, const float* g, long n, float lr) {
    long i = (long)blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) p[i] -= lr * g[i];
}

// Fill a tensor with a constant (used for the RMSNorm weights, initialized 1).
__global__ void k_fill(float* w, long n, float v) {
    long i = (long)blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) w[i] = v;
}

// Integer hash -> uniform [0,1); used for on-GPU weight initialization so a
// multi-billion-parameter model never has to be materialized on the host.
__device__ __forceinline__ float hashu(unsigned int x) {
    x ^= x >> 16; x *= 0x7feb352du;
    x ^= x >> 15; x *= 0x846ca68bu;
    x ^= x >> 16;
    return (float)(x >> 8) * (1.0f / 16777216.0f);
}

// Initialize a weight tensor in place: approx-normal (sum of 6 uniforms) * scale.
__global__ void k_init(float* w, long n, unsigned int seed, float scale) {
    long i = (long)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    float a = 0.0f;
    for (int k = 0; k < 6; ++k)
        a += hashu(seed + (unsigned int)i * 2654435761u + (unsigned int)k * 40503u);
    w[i] = (a - 3.0f) * 0.7071f * scale;
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

// Allocate device memory and (optionally) copy a host buffer up.
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

// ---------------------------------------------------------------------------
// Device-resident training: one forward (saving activations) + one backward
// fill every gradient buffer; an Adam step then runs entirely on the GPU.
// ---------------------------------------------------------------------------

// All device memory for a training run: weights, gradients, Adam moments,
// saved activations and scratch. Sized once from the model configuration.
struct Net {
    int T, d, nl, nh, hd, dff, vocab;
    float eps;
    int use_adam;  // 1: allocate + use Adam moments; 0: SGD (no m/v buffers).
    // Weights, gradients, and Adam first/second moments (matched shapes).
    float *embed, *ga, *wqkv, *wo, *gf, *wgu, *wd, *gfin, *lm;
    float *g_embed, *g_ga, *g_wqkv, *g_wo, *g_gf, *g_wgu, *g_wd, *g_gfin, *g_lm;
    float *m_embed, *v_embed, *m_ga, *v_ga, *m_wqkv, *v_wqkv, *m_wo, *v_wo;
    float *m_gf, *v_gf, *m_wgu, *v_wgu, *m_wd, *v_wd, *m_gfin, *v_gfin, *m_lm, *v_lm;
    // RoPE tables and token / target ids.
    float *cosT, *sinT;
    int *tokens, *targets;
    // Saved activations (per layer where noted). `probs` holds the softmax
    // matrices [n_layers, n_heads, T, T] for the attention backward.
    float *xr, *r1, *qrot, *krot, *vv, *aout, *hh, *r2, *gu, *ff, *rf, *logits;
    float *probs;
    // Forward scratch.
    float *onorm, *qkv_s, *qs, *ks, *n2s, *scratchO;
    // Backward scratch (`dscore` is the per-head attention score-gradient).
    float *dlog, *lossrow, *nf, *dgrad, *dh, *dff_, *dgu, *dn2, *dh2, *dattn;
    float *dqr, *dkr, *dvg, *dq, *dk, *dqkv, *dn1, *dx1, *n1r, *n2r, *dscore;
};

static void alloc_net(Net* n) {
    int T = n->T, d = n->d, nl = n->nl, dff = n->dff, V = n->vocab;
    int d3 = 3 * d, dff2 = 2 * dff;
    size_t W_embed = (size_t)V * d, W_ga = (size_t)nl * d;
    size_t W_wqkv = (size_t)nl * d * d3, W_wo = (size_t)nl * d * d;
    size_t W_wgu = (size_t)nl * d * dff2, W_wd = (size_t)nl * dff * d;
    size_t W_lm = (size_t)d * V;
    n->embed = up(0, W_embed); n->ga = up(0, W_ga); n->wqkv = up(0, W_wqkv);
    n->wo = up(0, W_wo); n->gf = up(0, W_ga); n->wgu = up(0, W_wgu);
    n->wd = up(0, W_wd); n->gfin = up(0, d); n->lm = up(0, W_lm);
    n->g_embed = up(0, W_embed); n->g_ga = up(0, W_ga); n->g_wqkv = up(0, W_wqkv);
    n->g_wo = up(0, W_wo); n->g_gf = up(0, W_ga); n->g_wgu = up(0, W_wgu);
    n->g_wd = up(0, W_wd); n->g_gfin = up(0, d); n->g_lm = up(0, W_lm);
    // Adam moments double the optimizer memory; skip them entirely for SGD
    // (multi-billion-parameter models would otherwise not fit).
    if (n->use_adam) {
        n->m_embed = up(0, W_embed); n->v_embed = up(0, W_embed);
        n->m_ga = up(0, W_ga); n->v_ga = up(0, W_ga);
        n->m_wqkv = up(0, W_wqkv); n->v_wqkv = up(0, W_wqkv);
        n->m_wo = up(0, W_wo); n->v_wo = up(0, W_wo);
        n->m_gf = up(0, W_ga); n->v_gf = up(0, W_ga);
        n->m_wgu = up(0, W_wgu); n->v_wgu = up(0, W_wgu);
        n->m_wd = up(0, W_wd); n->v_wd = up(0, W_wd);
        n->m_gfin = up(0, d); n->v_gfin = up(0, d);
        n->m_lm = up(0, W_lm); n->v_lm = up(0, W_lm);
    } else {
        n->m_embed = n->v_embed = n->m_ga = n->v_ga = n->m_wqkv = n->v_wqkv = 0;
        n->m_wo = n->v_wo = n->m_gf = n->v_gf = n->m_wgu = n->v_wgu = 0;
        n->m_wd = n->v_wd = n->m_gfin = n->v_gfin = n->m_lm = n->v_lm = 0;
    }
    n->cosT = up(0, (size_t)T * d); n->sinT = up(0, (size_t)T * d);
    cudaMalloc(&n->tokens, (size_t)T * sizeof(int));
    cudaMalloc(&n->targets, (size_t)T * sizeof(int));
    n->xr = up(0, (size_t)(nl + 1) * T * d);
    n->r1 = up(0, (size_t)nl * T); n->r2 = up(0, (size_t)nl * T);
    n->qrot = up(0, (size_t)nl * T * d); n->krot = up(0, (size_t)nl * T * d);
    n->vv = up(0, (size_t)nl * T * d); n->aout = up(0, (size_t)nl * T * d);
    n->hh = up(0, (size_t)nl * T * d);
    n->gu = up(0, (size_t)nl * T * dff2); n->ff = up(0, (size_t)nl * T * dff);
    n->rf = up(0, (size_t)T); n->logits = up(0, (size_t)T * V);
    n->probs = up(0, (size_t)nl * n->nh * T * T);
    n->dscore = up(0, (size_t)n->nh * T * T);
    n->onorm = up(0, (size_t)T * d); n->qkv_s = up(0, (size_t)T * d3);
    n->qs = up(0, (size_t)T * d); n->ks = up(0, (size_t)T * d);
    n->n2s = up(0, (size_t)T * d); n->scratchO = up(0, (size_t)T * d);
    n->dlog = up(0, (size_t)T * V); n->lossrow = up(0, (size_t)T);
    n->nf = up(0, (size_t)T * d); n->dgrad = up(0, (size_t)T * d);
    n->dh = up(0, (size_t)T * d); n->dff_ = up(0, (size_t)T * dff);
    n->dgu = up(0, (size_t)T * dff2); n->dn2 = up(0, (size_t)T * d);
    n->dh2 = up(0, (size_t)T * d); n->dattn = up(0, (size_t)T * d);
    n->dqr = up(0, (size_t)T * d); n->dkr = up(0, (size_t)T * d);
    n->dvg = up(0, (size_t)T * d); n->dq = up(0, (size_t)T * d);
    n->dk = up(0, (size_t)T * d); n->dqkv = up(0, (size_t)T * d3);
    n->dn1 = up(0, (size_t)T * d); n->dx1 = up(0, (size_t)T * d);
    n->n1r = up(0, (size_t)T * d); n->n2r = up(0, (size_t)T * d);
}

static void free_net(Net* n) {
    float* ptrs[] = {
        n->embed, n->ga, n->wqkv, n->wo, n->gf, n->wgu, n->wd, n->gfin, n->lm,
        n->g_embed, n->g_ga, n->g_wqkv, n->g_wo, n->g_gf, n->g_wgu, n->g_wd,
        n->g_gfin, n->g_lm, n->m_embed, n->v_embed, n->m_ga, n->v_ga, n->m_wqkv,
        n->v_wqkv, n->m_wo, n->v_wo, n->m_gf, n->v_gf, n->m_wgu, n->v_wgu,
        n->m_wd, n->v_wd, n->m_gfin, n->v_gfin, n->m_lm, n->v_lm, n->cosT,
        n->sinT, n->xr, n->r1, n->r2, n->qrot, n->krot, n->vv, n->aout, n->hh,
        n->gu, n->ff, n->rf, n->logits, n->onorm, n->qkv_s, n->qs, n->ks,
        n->n2s, n->scratchO, n->dlog, n->lossrow, n->nf, n->dgrad, n->dh,
        n->dff_, n->dgu, n->dn2, n->dh2, n->dattn, n->dqr, n->dkr, n->dvg,
        n->dq, n->dk, n->dqkv, n->dn1, n->dx1, n->n1r, n->n2r,
        n->probs, n->dscore};
    for (float* p : ptrs) cudaFree(p);
    cudaFree(n->tokens);
    cudaFree(n->targets);
}

// One forward (saving activations) + one backward; fills every g_* buffer.
// Returns the mean cross-entropy loss.
static float fwd_bwd(Net* n) {
    int T = n->T, d = n->d, nl = n->nl, dff = n->dff, V = n->vocab;
    int nh = n->nh, hd = n->hd, d3 = 3 * d, dff2 = 2 * dff;
    float eps = n->eps;
    dim3 blk(BLK, BLK);
    int rb = (T + 255) / 256;  // row-kernel grid

    // ---- Forward, saving every activation the backward pass needs. ----
    k_embed_gather<<<grid2d(d, T), blk>>>(n->embed, n->tokens, n->xr, T, d);
    for (int l = 0; l < nl; ++l) {
        float* x = n->xr + (size_t)l * T * d;
        float* r1 = n->r1 + (size_t)l * T;
        float* ga_l = n->ga + (size_t)l * d;
        float* wqkv_l = n->wqkv + (size_t)l * d * d3;
        float* wo_l = n->wo + (size_t)l * d * d;
        float* gf_l = n->gf + (size_t)l * d;
        float* wgu_l = n->wgu + (size_t)l * d * dff2;
        float* wd_l = n->wd + (size_t)l * dff * d;
        float* qrot_l = n->qrot + (size_t)l * T * d;
        float* krot_l = n->krot + (size_t)l * T * d;
        float* vv_l = n->vv + (size_t)l * T * d;
        float* aout_l = n->aout + (size_t)l * T * d;
        float* hh_l = n->hh + (size_t)l * T * d;
        float* r2 = n->r2 + (size_t)l * T;
        float* gu_l = n->gu + (size_t)l * T * dff2;
        float* ff_l = n->ff + (size_t)l * T * dff;

        k_row_invrms<<<rb, 256>>>(x, r1, T, d, eps);
        k_col_scale<<<grid2d(d, T), blk>>>(x, ga_l, n->onorm, T, d);
        launch_gemm<EPI_ROWSCALE>(
            n->onorm, wqkv_l, 0, 0, r1, 0, n->qkv_s, T, d3, d);
        k_slice<<<grid2d(d, T), blk>>>(n->qkv_s, n->qs, T, d, d3, 0);
        k_slice<<<grid2d(d, T), blk>>>(n->qkv_s, n->ks, T, d, d3, d);
        k_slice<<<grid2d(d, T), blk>>>(n->qkv_s, vv_l, T, d, d3, 2 * d);
        k_rope<<<grid2d(d / 2, T), blk>>>(n->qs, n->cosT, n->sinT, qrot_l, T, d);
        k_rope<<<grid2d(d / 2, T), blk>>>(n->ks, n->cosT, n->sinT, krot_l, T, d);
        k_attention<<<T * nh, ATTN_THREADS>>>(
            qrot_l, krot_l, vv_l, aout_l, n->probs + (size_t)l * nh * T * T,
            T, d, nh, hd);
        launch_gemm<EPI_RESGAMMA>(
            aout_l, wo_l, x, gf_l, 0, hh_l, n->n2s, T, d, d);
        k_row_invrms<<<rb, 256>>>(hh_l, r2, T, d, eps);
        launch_gemm<EPI_ROWSCALE>(
            n->n2s, wgu_l, 0, 0, r2, 0, gu_l, T, dff2, d);
        k_swiglu<<<grid2d(dff, T), blk>>>(gu_l, ff_l, T, dff);
        launch_gemm<EPI_RESGAMMA>(
            ff_l, wd_l, hh_l, n->gfin, 0, n->xr + (size_t)(l + 1) * T * d,
            n->scratchO, T, d, dff);
    }
    float* y_final = n->xr + (size_t)nl * T * d;
    k_row_invrms<<<rb, 256>>>(y_final, n->rf, T, d, eps);
    k_col_scale<<<grid2d(d, T), blk>>>(y_final, n->gfin, n->onorm, T, d);
    launch_gemm<EPI_ROWSCALE>(
        n->onorm, n->lm, 0, 0, n->rf, 0, n->logits, T, V, d);

    // ---- Backward. ----
    k_ce_grad<<<rb, 256>>>(n->logits, n->targets, n->dlog, n->lossrow, T, V);
    // LM head: logits = nf @ W_lm,  nf = rmsnorm(y_final) ⊙ γ_final.
    k_rmsnorm_apply<<<grid2d(d, T), blk>>>(y_final, n->rf, n->gfin, n->nf, T, d);
    launch_gemm_tn(n->nf, n->dlog, n->g_lm, T, d, V);
    launch_gemm_nt(n->dlog, n->lm, n->nf, T, d, V);  // nf reused as d_nf
    cudaMemsetAsync(n->g_gfin, 0, (size_t)d * sizeof(float), 0);
    k_rmsnorm_bwd<<<rb, 256>>>(y_final, n->rf, n->gfin, n->nf, n->dgrad,
                               n->g_gfin, T, d);

    for (int l = nl - 1; l >= 0; --l) {
        float* x = n->xr + (size_t)l * T * d;
        float* r1 = n->r1 + (size_t)l * T;
        float* ga_l = n->ga + (size_t)l * d;
        float* wqkv_l = n->wqkv + (size_t)l * d * d3;
        float* wo_l = n->wo + (size_t)l * d * d;
        float* gf_l = n->gf + (size_t)l * d;
        float* wgu_l = n->wgu + (size_t)l * d * dff2;
        float* wd_l = n->wd + (size_t)l * dff * d;
        float* qrot_l = n->qrot + (size_t)l * T * d;
        float* krot_l = n->krot + (size_t)l * T * d;
        float* vv_l = n->vv + (size_t)l * T * d;
        float* aout_l = n->aout + (size_t)l * T * d;
        float* hh_l = n->hh + (size_t)l * T * d;
        float* r2 = n->r2 + (size_t)l * T;
        float* gu_l = n->gu + (size_t)l * T * dff2;
        float* ff_l = n->ff + (size_t)l * T * dff;
        float* g_ga_l = n->g_ga + (size_t)l * d;
        float* g_wqkv_l = n->g_wqkv + (size_t)l * d * d3;
        float* g_wo_l = n->g_wo + (size_t)l * d * d;
        float* g_gf_l = n->g_gf + (size_t)l * d;
        float* g_wgu_l = n->g_wgu + (size_t)l * d * dff2;
        float* g_wd_l = n->g_wd + (size_t)l * dff * d;

        // y = ff @ W_down + h  (residual): grad flows to both ff-path and h.
        cudaMemcpyAsync(n->dh, n->dgrad, (size_t)T * d * sizeof(float),
                        cudaMemcpyDeviceToDevice, 0);
        launch_gemm_nt(n->dgrad, wd_l, n->dff_, T, dff, d);
        launch_gemm_tn(ff_l, n->dgrad, g_wd_l, T, dff, d);
        k_swiglu_bwd<<<grid2d(dff, T), blk>>>(gu_l, n->dff_, n->dgu, T, dff);
        k_rmsnorm_apply<<<grid2d(d, T), blk>>>(hh_l, r2, gf_l, n->n2r, T, d);
        launch_gemm_tn(n->n2r, n->dgu, g_wgu_l, T, d, dff2);
        launch_gemm_nt(n->dgu, wgu_l, n->dn2, T, d, dff2);
        cudaMemsetAsync(g_gf_l, 0, (size_t)d * sizeof(float), 0);
        k_rmsnorm_bwd<<<rb, 256>>>(hh_l, r2, gf_l, n->dn2, n->dh2, g_gf_l, T, d);
        k_add<<<(T * d + 255) / 256, 256>>>(n->dh, n->dh2, T * d);

        // h = attn_out @ W_o + x.
        launch_gemm_tn(aout_l, n->dh, g_wo_l, T, d, d);
        launch_gemm_nt(n->dh, wo_l, n->dattn, T, d, d);

        // Attention + RoPE backward.
        // Atomic-free attention backward: DS = score gradients, then the
        // three operand gradients as independent block-per-position reductions.
        const float* probs_l = n->probs + (size_t)l * nh * T * T;
        k_attn_dscore<<<T * nh, ATTN_THREADS>>>(
            n->dattn, vv_l, probs_l, n->dscore, T, d, nh, hd);
        k_attn_dq<<<T * nh, ATTN_THREADS>>>(
            n->dscore, krot_l, n->dqr, T, d, nh, hd);
        k_attn_dkv<<<T * nh, ATTN_THREADS>>>(
            probs_l, n->dscore, n->dattn, qrot_l, n->dkr, n->dvg, T, d, nh, hd);
        k_rope_bwd<<<grid2d(d / 2, T), blk>>>(n->dqr, n->cosT, n->sinT, n->dq, T, d);
        k_rope_bwd<<<grid2d(d / 2, T), blk>>>(n->dkr, n->cosT, n->sinT, n->dk, T, d);
        k_paste<<<grid2d(d, T), blk>>>(n->dq, n->dqkv, T, d, d3, 0);
        k_paste<<<grid2d(d, T), blk>>>(n->dk, n->dqkv, T, d, d3, d);
        k_paste<<<grid2d(d, T), blk>>>(n->dvg, n->dqkv, T, d, d3, 2 * d);

        // qkv = n1 @ W_qkv,  n1 = rmsnorm(x) ⊙ γ_attn.
        k_rmsnorm_apply<<<grid2d(d, T), blk>>>(x, r1, ga_l, n->n1r, T, d);
        launch_gemm_tn(n->n1r, n->dqkv, g_wqkv_l, T, d, d3);
        launch_gemm_nt(n->dqkv, wqkv_l, n->dn1, T, d, d3);
        cudaMemsetAsync(g_ga_l, 0, (size_t)d * sizeof(float), 0);
        k_rmsnorm_bwd<<<rb, 256>>>(x, r1, ga_l, n->dn1, n->dx1, g_ga_l, T, d);

        // x feeds both the RMSNorm and the residual: sum the two paths.
        k_add<<<(T * d + 255) / 256, 256>>>(n->dx1, n->dh, T * d);
        cudaMemcpyAsync(n->dgrad, n->dx1, (size_t)T * d * sizeof(float),
                        cudaMemcpyDeviceToDevice, 0);
    }

    // Embedding gradient: scatter the input-stream gradient into the table.
    cudaMemsetAsync(n->g_embed, 0, (size_t)V * d * sizeof(float), 0);
    k_embed_bwd<<<grid2d(d, T), blk>>>(n->dgrad, n->tokens, n->g_embed, T, d);

    cudaDeviceSynchronize();

    // Mean loss from the per-token losses.
    float* host_loss = (float*)malloc((size_t)T * sizeof(float));
    cudaMemcpy(host_loss, n->lossrow, (size_t)T * sizeof(float),
               cudaMemcpyDeviceToHost);
    float sum = 0.0f;
    for (int i = 0; i < T; ++i) sum += host_loss[i];
    free(host_loss);
    return sum / (float)T;
}

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
    launch_gemm<EPI_PLAIN>(
        dA, dB, nullptr, nullptr, nullptr, dD, nullptr, M, N, K);
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
    launch_gemm<EPI_RESGAMMA>(
        dA, dB, dC, dG, nullptr, dD, dO, M, N, K);
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
    launch_gemm<EPI_ROWSCALE>(
        dA, dB, nullptr, nullptr, dR, nullptr, dO, M, N, K);
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
    launch_gemm<EPI_ROWSCALE>(
        dA, dB, nullptr, nullptr, dR, nullptr, dDp, M, N, K);
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
    launch_gemm<EPI_PLAIN>(
        dA, dB, nullptr, nullptr, nullptr, dD, nullptr, M, N, K);
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
    launch_gemm<EPI_PLAIN>(
        dA, dB, nullptr, nullptr, nullptr, dD, nullptr, M, N, K);
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
    launch_gemm<EPI_ROWSCALE>(
        dA, dB, nullptr, nullptr, dR, nullptr, dZ, M, N, K);
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
// GEMM-Residual-RMSNorm-GEMM chain of paper section 3.2.1.
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

    k_row_invrms<<<(T + 255) / 256, 256>>>(dX, dR, T, d, eps);
    k_col_scale<<<grid2d(d, T), blk>>>(dX, dGA, dOnorm, T, d);

    for (int l = 0; l < n_layers; ++l) {
        const float* wqkv_l = dWQKV + (size_t)l * d * d3;
        const float* wo_l = dWO + (size_t)l * d * d;
        const float* gf_l = dGF + (size_t)l * d;
        const float* wgu_l = dWGU + (size_t)l * d * dff2;
        const float* wd_l = dWD + (size_t)l * d_ff * d;

        // QKV projection with the delayed RMSNorm scale (Kernel 5).
        launch_gemm<EPI_ROWSCALE>(
            dOnorm, wqkv_l, nullptr, nullptr, dR, nullptr, dQKV, T, d3, d);
        k_slice<<<grid2d(d, T), blk>>>(dQKV, dQ, T, d, d3, 0);
        k_slice<<<grid2d(d, T), blk>>>(dQKV, dK, T, d, d3, d);
        k_slice<<<grid2d(d, T), blk>>>(dQKV, dV, T, d, d3, 2 * d);
        k_rope<<<grid2d(d / 2, T), blk>>>(dQ, dCos, dSin, dQR, T, d);
        k_rope<<<grid2d(d / 2, T), blk>>>(dK, dCos, dSin, dKR, T, d);
        k_attention<<<T * n_heads, ATTN_THREADS>>>(
            dQR, dKR, dV, dAttn, nullptr, T, d, n_heads, head_dim);

        // Output proj + residual + FFN-norm (Kernel 4).
        launch_gemm<EPI_RESGAMMA>(
            dAttn, wo_l, dX, gf_l, nullptr, dH, dN2, T, d, d);
        k_row_invrms<<<(T + 255) / 256, 256>>>(dH, dR2, T, d, eps);

        // Gate/Up projection + SwiGLU (Kernel 6).
        launch_gemm<EPI_ROWSCALE>(
            dN2, wgu_l, nullptr, nullptr, dR2, nullptr, dDP, T, dff2, d);
        k_swiglu<<<grid2d(d_ff, T), blk>>>(dDP, dFF, T, d_ff);

        // Down proj + residual + next sublayer's norm (Kernel 4).
        const float* next_gamma =
            (l + 1 < n_layers) ? (dGA + (size_t)(l + 1) * d) : dGFinal;
        launch_gemm<EPI_RESGAMMA>(
            dFF, wd_l, dH, next_gamma, nullptr, dY, dOnorm, T, d, d_ff);
        k_row_invrms<<<(T + 255) / 256, 256>>>(dY, dR, T, d, eps);

        float* tmp = dX; dX = dY; dY = tmp;
    }

    // LM head: logits = (final-normed residual @ W_lm) ⊙ r  (Kernel 5).
    launch_gemm<EPI_ROWSCALE>(
        dOnorm, dLM, nullptr, nullptr, dR, nullptr, dLogits, T, vocab, d);

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

// Upload host weights into a Net's device weight buffers.
static void upload_weights(Net* n, const float* embed, const float* ga,
                           const float* wqkv, const float* wo, const float* gf,
                           const float* wgu, const float* wd, const float* gfin,
                           const float* lm) {
    int d = n->d, nl = n->nl, dff = n->dff, V = n->vocab;
    int d3 = 3 * d, dff2 = 2 * dff;
    auto cp = [](float* dst, const float* src, size_t n_el) {
        cudaMemcpy(dst, src, n_el * sizeof(float), cudaMemcpyHostToDevice);
    };
    cp(n->embed, embed, (size_t)V * d);
    cp(n->ga, ga, (size_t)nl * d);
    cp(n->wqkv, wqkv, (size_t)nl * d * d3);
    cp(n->wo, wo, (size_t)nl * d * d);
    cp(n->gf, gf, (size_t)nl * d);
    cp(n->wgu, wgu, (size_t)nl * d * dff2);
    cp(n->wd, wd, (size_t)nl * dff * d);
    cp(n->gfin, gfin, (size_t)d);
    cp(n->lm, lm, (size_t)d * V);
}

// One forward + backward; copies every gradient back to the host.
int coda_cuda_grads(
    int T, int d, int nl, int nh, int hd, int dff, int vocab, float eps,
    const float* embed, const float* ga, const float* wqkv, const float* wo,
    const float* gf, const float* wgu, const float* wd, const float* gfin,
    const float* lm, const float* cosT, const float* sinT,
    const int* tokens, const int* targets,
    float* g_embed, float* g_ga, float* g_wqkv, float* g_wo, float* g_gf,
    float* g_wgu, float* g_wd, float* g_gfin, float* g_lm, float* loss_out) {

    Net n;
    n.T = T; n.d = d; n.nl = nl; n.nh = nh; n.hd = hd; n.dff = dff;
    n.vocab = vocab; n.eps = eps;
    n.use_adam = 0;  // no optimizer state needed for a gradient query
    alloc_net(&n);
    upload_weights(&n, embed, ga, wqkv, wo, gf, wgu, wd, gfin, lm);
    cudaMemcpy(n.cosT, cosT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(n.sinT, sinT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(n.tokens, tokens, (size_t)T * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(n.targets, targets, (size_t)T * sizeof(int), cudaMemcpyHostToDevice);

    float loss = fwd_bwd(&n);
    int err = cuda_check("coda_cuda_grads");
    *loss_out = loss;

    int d3 = 3 * d, dff2 = 2 * dff;
    auto dn = [](float* dst, const float* src, size_t n_el) {
        cudaMemcpy(dst, src, n_el * sizeof(float), cudaMemcpyDeviceToHost);
    };
    dn(g_embed, n.g_embed, (size_t)vocab * d);
    dn(g_ga, n.g_ga, (size_t)nl * d);
    dn(g_wqkv, n.g_wqkv, (size_t)nl * d * d3);
    dn(g_wo, n.g_wo, (size_t)nl * d * d);
    dn(g_gf, n.g_gf, (size_t)nl * d);
    dn(g_wgu, n.g_wgu, (size_t)nl * d * dff2);
    dn(g_wd, n.g_wd, (size_t)nl * dff * d);
    dn(g_gfin, n.g_gfin, (size_t)d);
    dn(g_lm, n.g_lm, (size_t)d * vocab);
    free_net(&n);
    return err;
}

// Full device-resident training loop: weights and Adam state stay on the GPU
// for all `n_steps`; trained weights and the loss curve are returned.
int coda_cuda_train(
    int T, int d, int nl, int nh, int hd, int dff, int vocab, float eps,
    float* embed, float* ga, float* wqkv, float* wo, float* gf, float* wgu,
    float* wd, float* gfin, float* lm, const float* cosT, const float* sinT,
    const int* tokens, const int* targets, int n_steps, float lr,
    float* loss_curve) {

    Net n;
    n.T = T; n.d = d; n.nl = nl; n.nh = nh; n.hd = hd; n.dff = dff;
    n.vocab = vocab; n.eps = eps;
    n.use_adam = 1;
    alloc_net(&n);
    upload_weights(&n, embed, ga, wqkv, wo, gf, wgu, wd, gfin, lm);
    cudaMemcpy(n.cosT, cosT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(n.sinT, sinT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(n.tokens, tokens, (size_t)T * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(n.targets, targets, (size_t)T * sizeof(int), cudaMemcpyHostToDevice);

    int d3 = 3 * d, dff2 = 2 * dff;
    // Adam moments start at zero (cudaMalloc does not zero memory).
    struct WT { float *p, *g, *m, *v; size_t n; };
    WT wts[] = {
        {n.embed, n.g_embed, n.m_embed, n.v_embed, (size_t)vocab * d},
        {n.ga, n.g_ga, n.m_ga, n.v_ga, (size_t)nl * d},
        {n.wqkv, n.g_wqkv, n.m_wqkv, n.v_wqkv, (size_t)nl * d * d3},
        {n.wo, n.g_wo, n.m_wo, n.v_wo, (size_t)nl * d * d},
        {n.gf, n.g_gf, n.m_gf, n.v_gf, (size_t)nl * d},
        {n.wgu, n.g_wgu, n.m_wgu, n.v_wgu, (size_t)nl * d * dff2},
        {n.wd, n.g_wd, n.m_wd, n.v_wd, (size_t)nl * dff * d},
        {n.gfin, n.g_gfin, n.m_gfin, n.v_gfin, (size_t)d},
        {n.lm, n.g_lm, n.m_lm, n.v_lm, (size_t)d * vocab},
    };
    for (WT& w : wts) {
        cudaMemset(w.m, 0, w.n * sizeof(float));
        cudaMemset(w.v, 0, w.n * sizeof(float));
    }

    for (int step = 0; step < n_steps; ++step) {
        loss_curve[step] = fwd_bwd(&n);
        for (WT& w : wts) {
            int blocks = (int)((w.n + 255) / 256);
            k_adam<<<blocks, 256>>>(
                w.p, w.g, w.m, w.v, (long)w.n, lr, 0.9f, 0.999f, 1e-8f, step + 1);
        }
    }
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_train");

    auto dn = [](float* dst, const float* src, size_t n_el) {
        cudaMemcpy(dst, src, n_el * sizeof(float), cudaMemcpyDeviceToHost);
    };
    dn(embed, n.embed, (size_t)vocab * d);
    dn(ga, n.ga, (size_t)nl * d);
    dn(wqkv, n.wqkv, (size_t)nl * d * d3);
    dn(wo, n.wo, (size_t)nl * d * d);
    dn(gf, n.gf, (size_t)nl * d);
    dn(wgu, n.wgu, (size_t)nl * d * dff2);
    dn(wd, n.wd, (size_t)nl * dff * d);
    dn(gfin, n.gfin, (size_t)d);
    dn(lm, n.lm, (size_t)d * vocab);
    free_net(&n);
    return err;
}

// Train a model whose weights are generated and kept entirely on the GPU.
//
// For a multi-billion-parameter model the host can neither hold the weights
// nor afford Adam's two extra moment tensors. This entry point initializes the
// weights in place with an on-GPU hash RNG, never materializes them on the
// host, and optimizes with plain SGD. Only the per-step loss is returned.
int coda_cuda_train_random(
    int T, int d, int nl, int nh, int hd, int dff, int vocab, float eps,
    const float* cosT, const float* sinT, const int* tokens, const int* targets,
    int n_steps, float lr, unsigned int seed, float* loss_curve) {

    Net n;
    n.T = T; n.d = d; n.nl = nl; n.nh = nh; n.hd = hd; n.dff = dff;
    n.vocab = vocab; n.eps = eps;
    n.use_adam = 0;  // SGD: Adam moments would not fit a multi-billion-param model
    alloc_net(&n);

    int d3 = 3 * d, dff2 = 2 * dff;
    float si = 1.0f / sqrtf((float)d), sf = 1.0f / sqrtf((float)dff);
    auto init = [seed](float* w, size_t cnt, unsigned int salt, float sc) {
        int blocks = (int)((cnt + 255) / 256);
        k_init<<<blocks, 256>>>(w, (long)cnt, seed + salt, sc);
    };
    auto fill1 = [](float* w, size_t cnt) {
        int blocks = (int)((cnt + 255) / 256);
        k_fill<<<blocks, 256>>>(w, (long)cnt, 1.0f);
    };
    init(n.embed, (size_t)vocab * d, 1u, 0.08f);
    init(n.wqkv, (size_t)nl * d * d3, 2u, si);
    init(n.wo, (size_t)nl * d * d, 3u, si);
    init(n.wgu, (size_t)nl * d * dff2, 4u, si);
    init(n.wd, (size_t)nl * dff * d, 5u, sf);
    init(n.lm, (size_t)d * vocab, 6u, si);
    fill1(n.ga, (size_t)nl * d);
    fill1(n.gf, (size_t)nl * d);
    fill1(n.gfin, (size_t)d);

    cudaMemcpy(n.cosT, cosT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(n.sinT, sinT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(n.tokens, tokens, (size_t)T * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(n.targets, targets, (size_t)T * sizeof(int), cudaMemcpyHostToDevice);

    struct WT { float* p; float* g; size_t n; };
    WT wts[] = {
        {n.embed, n.g_embed, (size_t)vocab * d},
        {n.ga, n.g_ga, (size_t)nl * d},
        {n.wqkv, n.g_wqkv, (size_t)nl * d * d3},
        {n.wo, n.g_wo, (size_t)nl * d * d},
        {n.gf, n.g_gf, (size_t)nl * d},
        {n.wgu, n.g_wgu, (size_t)nl * d * dff2},
        {n.wd, n.g_wd, (size_t)nl * dff * d},
        {n.gfin, n.g_gfin, (size_t)d},
        {n.lm, n.g_lm, (size_t)d * vocab},
    };
    for (int step = 0; step < n_steps; ++step) {
        loss_curve[step] = fwd_bwd(&n);
        for (WT& w : wts) {
            int blocks = (int)((w.n + 255) / 256);
            k_sgd<<<blocks, 256>>>(w.p, w.g, (long)w.n, lr);
        }
    }
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_train_random");
    free_net(&n);
    return err;
}

}  // extern "C"
