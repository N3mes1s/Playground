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
#include <cuda_fp16.h>
#include <cublas_v2.h>
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
// fp16-weight GEMM and a fp32 -> fp16 conversion helper.
//
// Storing weights in half precision halves the bytes streamed over HBM per
// forward; the kernels below mirror their fp32 counterparts but read B as
// `__half*` and convert on the way into shared memory or registers. Compute
// stays fp32 (the fp16 -> fp32 conversion is a single hardware instruction
// per element). No tensor-core path here - the prefill GEMM is one-shot and
// the decode path uses the GEMV below; register-blocked is enough.
// ---------------------------------------------------------------------------

// Same staged-shared-memory GEMM as `k_gemm_epi`, but B is fp16 and is
// promoted to fp32 on staging into `Bs`.
template <int MODE>
__global__ void k_gemm_epi_h(const float* A, const __half* B, const float* C,
                             const float* gamma, const float* r,
                             float* D, float* O, int M, int N, int K) {
    __shared__ float As[BK * BM];
    __shared__ float Bs[BK * BN];

    int c_row = blockIdx.y;
    int c_col = blockIdx.x;
    int tid = threadIdx.x;
    int t_row = tid / (BN / TN);
    int t_col = tid % (BN / TN);

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
            Bs[k * BN + n] =
                (gk < K && gn < N) ? __half2float(B[gk * N + gn]) : 0.0f;
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

// fp16 tensor-core GEMM with cooperative A staging.
//
// All warps in a block share the same `tile_m` (the row strip of A), so A is
// staged into shared memory **once per block** rather than once per warp;
// each warp then loads its matrix_a fragment from that shared block. Matrix_b
// (fp16 weights) loads straight from global into the warp's fragment. The
// 16x16x16 fp16 fragments hit A100's fp16 tensor-core datapath (peak ~312
// TFLOPS), which is the lever that takes batched decode from compute-bound
// at ~10 TFLOPS back to bandwidth-bound.
//
// Block layout: TC_WARPS warps per block cover a 16 x (TC_WARPS * 16) output
// tile. Grid is `tile_m_count * ceil(tiles_n / TC_WARPS)`.
template <int MODE>
__global__ void k_gemm_tc_h(const float* A, const __half* B, const float* C,
                            const float* gamma, const float* r,
                            float* D, float* O, int M, int N, int K) {
#if __CUDA_ARCH__ >= 800
    using namespace nvcuda;
    int warp_idx = threadIdx.x / 32;
    int lane = threadIdx.x & 31;
    int tiles_n = N / 16;
    int n_groups = (tiles_n + TC_WARPS - 1) / TC_WARPS;
    int tile_m = blockIdx.x / n_groups;
    int n_group = blockIdx.x % n_groups;
    int tile_n = n_group * TC_WARPS + warp_idx;
    if (tile_m * 16 >= M) return;
    bool valid_n = (tile_n * 16 < N);

    // Shared memory: one 16x16 fp16 A buffer shared by all warps in the
    // block, plus a per-warp 16x16 fp32 epilogue tile.
    extern __shared__ char smem[];
    __half* sh_a = (__half*)smem;
    float* sh_tile_all =
        (float*)(smem + 256 * sizeof(__half));
    float* tile = sh_tile_all + warp_idx * 256;

    wmma::fragment<wmma::accumulator, 16, 16, 16, float> acc;
    wmma::fill_fragment(acc, 0.0f);

    int tid = threadIdx.x;  // 0 .. TC_WARPS*32 - 1
    for (int k0 = 0; k0 < K; k0 += 16) {
        // Cooperative A staging: 256 halves, 1 element per thread (block has
        // TC_WARPS * 32 = 256 threads when TC_WARPS = 8).
        if (tid < 256) {
            int row = tid / 16;
            int col = tid % 16;
            int gm = tile_m * 16 + row;
            int gk = k0 + col;
            float v = (gm < M && gk < K) ? A[gm * K + gk] : 0.0f;
            sh_a[tid] = __float2half(v);
        }
        __syncthreads();

        if (valid_n) {
            wmma::fragment<wmma::matrix_a, 16, 16, 16, __half, wmma::row_major> af;
            wmma::fragment<wmma::matrix_b, 16, 16, 16, __half, wmma::row_major> bf;
            wmma::load_matrix_sync(af, sh_a, 16);
            wmma::load_matrix_sync(bf, B + k0 * N + tile_n * 16, N);
            wmma::mma_sync(acc, af, bf, acc);
        }
        __syncthreads();
    }

    if (valid_n) {
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
    }
#endif
}

template <int MODE>
static void launch_gemm_h(const float* A, const __half* B, const float* C,
                          const float* gamma, const float* r, float* D, float* O,
                          int M, int N, int K) {
    // fp16 tensor cores when the shape aligns (decode batched GEMMs do).
    if (tensor_cores_available() && M % 16 == 0 && N % 16 == 0 && K % 16 == 0) {
        int tiles_n = N / 16;
        int n_groups = (tiles_n + TC_WARPS - 1) / TC_WARPS;
        int tile_m_count = (M + 15) / 16;
        int blocks = tile_m_count * n_groups;
        size_t shmem = 256 * sizeof(__half) +
                       (size_t)TC_WARPS * 256 * sizeof(float);
        k_gemm_tc_h<MODE><<<blocks, TC_WARPS * 32, shmem>>>(
            A, B, C, gamma, r, D, O, M, N, K);
    } else {
        dim3 grid((N + BN - 1) / BN, (M + BM - 1) / BM);
        k_gemm_epi_h<MODE><<<grid, GEMM_THREADS>>>(A, B, C, gamma, r, D, O, M, N, K);
    }
}

// Convert a flat fp32 buffer to fp16 in place-of-a-separate-buffer. Used once
// per generation to halve the resident weight footprint (and the per-token
// HBM traffic) before the fp32 source buffer is freed.
__global__ void k_f2h(const float* src, __half* dst, size_t n) {
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (; i < n; i += stride) dst[i] = __float2half(src[i]);
}

static void f2h(const float* src, __half* dst, size_t n) {
    int threads = 256;
    long long need = ((long long)n + threads - 1) / threads;
    int blocks = need > 65535 ? 65535 : (int)need;
    if (blocks < 1) blocks = 1;
    k_f2h<<<blocks, threads>>>(src, dst, n);
}

// ---------------------------------------------------------------------------
// cuBLAS-backed fp16 GEMM + tiny CODA epilogue kernels.
//
// My hand-rolled tensor-core GEMM runs at ~12 TFLOPS on A100 vs cuBLAS at
// ~150-200 TFLOPS. The CODA abstraction is the fused epilogue; the GEMM
// mainloop is interchangeable. For batched decode we hand the mainloop to
// cuBLAS (CUBLAS_COMPUTE_32F_FAST_16F, fp16 inputs + fp32 accumulator) and
// run the CODA epilogue as a separate tiny kernel right after - one extra
// kernel launch, but the GEMM itself runs at peak.
//
// Layout: my A and B are row-major. cuBLAS is column-major, so to compute
// C[M,N] = A[M,K] @ B[K,N] in row-major we ask cuBLAS to compute
// C^T (col-maj N x M) = B^T (col-maj N x K) @ A^T (col-maj K x M).
// ---------------------------------------------------------------------------

static const char* cublas_err_str(cublasStatus_t s) {
    switch (s) {
        case CUBLAS_STATUS_SUCCESS:           return "SUCCESS";
        case CUBLAS_STATUS_NOT_INITIALIZED:   return "NOT_INITIALIZED";
        case CUBLAS_STATUS_ALLOC_FAILED:      return "ALLOC_FAILED";
        case CUBLAS_STATUS_INVALID_VALUE:     return "INVALID_VALUE";
        case CUBLAS_STATUS_ARCH_MISMATCH:     return "ARCH_MISMATCH";
        case CUBLAS_STATUS_MAPPING_ERROR:     return "MAPPING_ERROR";
        case CUBLAS_STATUS_EXECUTION_FAILED:  return "EXECUTION_FAILED";
        case CUBLAS_STATUS_INTERNAL_ERROR:    return "INTERNAL_ERROR";
        case CUBLAS_STATUS_NOT_SUPPORTED:     return "NOT_SUPPORTED";
        default:                              return "?";
    }
}

// fp16 GEMM via cuBLAS. Converts A (fp32 activations) to fp16 in `dA_h_scratch`
// first; B is already fp16 weights. The result `C` is fp32. Computes
// `C[M,N] = A[M,K] @ B[K,N]` in row-major, no scaling or accumulation.
static int cublas_gemm_h(cublasHandle_t handle, const float* A_fp32,
                         const __half* B, float* C,
                         __half* dA_h_scratch, int M, int N, int K) {
    f2h(A_fp32, dA_h_scratch, (size_t)M * K);
    float alpha = 1.0f, beta = 0.0f;
    cublasStatus_t st = cublasGemmEx(
        handle, CUBLAS_OP_N, CUBLAS_OP_N,
        N, M, K,
        &alpha,
        B,            CUDA_R_16F, N,
        dA_h_scratch, CUDA_R_16F, K,
        &beta,
        C,            CUDA_R_32F, N,
        CUBLAS_COMPUTE_32F_FAST_16F,
        CUBLAS_GEMM_DEFAULT_TENSOR_OP);
    if (st != CUBLAS_STATUS_SUCCESS) {
        fprintf(stderr, "[coda-cuda] cublasGemmEx failed: %s\n",
                cublas_err_str(st));
        return 1;
    }
    return 0;
}

// CODA EPI_ROWSCALE epilogue: in-place `O[i,j] *= r[i]`. The cuBLAS GEMM has
// already written A @ B into O.
__global__ void k_epi_rowscale(const float* r, float* O, int M, int N) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y;
    if (i >= M || j >= N) return;
    O[(size_t)i * N + j] *= r[i];
}

// CODA EPI_RESGAMMA epilogue: `D[i,j] = A@B[i,j] + C[i,j]`, `O[i,j] = D[i,j] *
// gamma[j]`. cuBLAS has already written A @ B into D, so this kernel just
// adds the residual and applies the per-column gamma.
__global__ void k_epi_resgamma(const float* C, const float* gamma,
                               float* D, float* O, int M, int N) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y;
    if (i >= M || j >= N) return;
    size_t off = (size_t)i * N + j;
    float d = D[off] + C[off];
    D[off] = d;
    O[off] = d * gamma[j];
}

static void launch_epi_rowscale(const float* r, float* O, int M, int N) {
    dim3 grid((N + 255) / 256, M);
    k_epi_rowscale<<<grid, 256>>>(r, O, M, N);
}

static void launch_epi_resgamma(const float* C, const float* gamma,
                                float* D, float* O, int M, int N) {
    dim3 grid((N + 255) / 256, M);
    k_epi_resgamma<<<grid, 256>>>(C, gamma, D, O, M, N);
}

// ---------------------------------------------------------------------------
// Split-K GEMV: the M = 1 case of the fused-epilogue GEMM, for decode.
//
// A cached decode step processes one new token, so the projection "GEMMs" are
// matrix-vector products. A one-thread-per-column GEMV reads the weight matrix
// exactly once but launches only N/256 blocks - too few to fill the SMs or
// hide HBM latency, so it stalls at a fraction of peak bandwidth.
//
// This is a split-K GEMV instead. The contraction dimension is cut into
// `n_split` slices (chosen so the phase-1 grid is large enough to saturate the
// GPU); phase 1 runs one block per (column-tile, K-slice) and writes a partial
// sum, and phase 2 sums the `n_split` partials per column and applies the
// fused epilogue. The weight matrix is still streamed exactly once - the split
// only adds parallelism - and the epilogue matches `k_gemm_epi` row 0 (the
// input row A is [1, K], B is [K, N] row-major).
// ---------------------------------------------------------------------------
#define GEMV_BN 256        // output columns (threads) per block
#define GEMV_TARGET 512    // phase-1 block count to aim for
#define GEMV_MIN_CHUNK 64  // smallest worthwhile K-slice per block

// Phase 1: block (column-tile, K-slice) -> partial dot product. B is fp16
// (half the bytes per element off HBM, the same fp32 accumulator and partials).
__global__ void k_gemv_splitk_h(const float* A, const __half* B,
                                float* partials, int N, int K, int n_split) {
    int n = blockIdx.x * blockDim.x + threadIdx.x;  // output column
    int ks = blockIdx.y;                            // K-slice index
    if (n >= N) return;
    int chunk = (K + n_split - 1) / n_split;
    int k0 = ks * chunk;
    int k1 = min(k0 + chunk, K);
    float acc = 0.0f;
    for (int k = k0; k < k1; ++k)
        acc += A[k] * __half2float(B[(size_t)k * N + n]);
    partials[(size_t)ks * N + n] = acc;
}

// Phase 2: sum the per-column partials, then apply the fused epilogue.
template <int MODE>
__global__ void k_gemv_epilogue(const float* partials, const float* C,
                                const float* gamma, const float* r,
                                float* D, float* O, int N, int n_split) {
    int n = blockIdx.x * blockDim.x + threadIdx.x;
    if (n >= N) return;
    float acc = 0.0f;
    for (int s = 0; s < n_split; ++s) acc += partials[(size_t)s * N + n];
    if (MODE == EPI_PLAIN) {
        D[n] = acc;
    } else if (MODE == EPI_RESGAMMA) {
        float dv = acc + C[n];
        D[n] = dv;
        O[n] = dv * gamma[n];
    } else {  // EPI_ROWSCALE
        O[n] = acc * r[0];
    }
}

// Choose the K-split for an N-wide, K-deep GEMV: enough phase-1 blocks to fill
// the GPU, but each block's K-slice no smaller than GEMV_MIN_CHUNK.
static int gemv_split(int N, int K) {
    int col_blocks = (N + GEMV_BN - 1) / GEMV_BN;
    int n_split = GEMV_TARGET / (col_blocks > 0 ? col_blocks : 1);
    int max_split = (K + GEMV_MIN_CHUNK - 1) / GEMV_MIN_CHUNK;
    if (n_split > max_split) n_split = max_split;
    if (n_split < 1) n_split = 1;
    return n_split;
}

// Launch the fp16-weight split-K GEMV. `partials` is caller-owned scratch,
// sized for at least `gemv_split(N, K) * N` floats. Epilogue selection
// matches `launch_gemm`.
template <int MODE>
static void launch_gemv_h(const float* A, const __half* B, const float* C,
                          const float* gamma, const float* r, float* D, float* O,
                          int N, int K, float* partials) {
    int col_blocks = (N + GEMV_BN - 1) / GEMV_BN;
    int n_split = gemv_split(N, K);
    k_gemv_splitk_h<<<dim3(col_blocks, n_split), GEMV_BN>>>(
        A, B, partials, N, K, n_split);
    k_gemv_epilogue<MODE><<<col_blocks, GEMV_BN>>>(
        partials, C, gamma, r, D, O, N, n_split);
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

// Causal attention for a single decode step - one thread BLOCK per head.
//
// The KV cache holds the rotated keys (`Kc`) and values (`Vc`) for every
// position 0..p, so this kernel never recomputes them: the one new token's
// rotated query row attends against the `p + 1` cached entries. Mirrors
// `k_attention` but with a single query, the cache as the K/V source, and no
// softmax-matrix save (inference only). `Kc` / `Vc` are [Tmax, d] row-major.
__global__ void k_attention_decode(const float* q, const float* Kc,
                                   const float* Vc, float* O, int p, int d,
                                   int n_heads, int head_dim) {
    int h = blockIdx.x;            // one block per head
    int off = h * head_dim;
    int t = threadIdx.x;
    int L = p + 1;                 // cached keys/values, positions 0..p
    float scale = rsqrtf((float)head_dim);

    __shared__ float sc[ATTN_TMAX];
    __shared__ float red[ATTN_THREADS];

    for (int j = t; j < L; j += ATTN_THREADS) {
        float s = 0.0f;
        for (int e = 0; e < head_dim; ++e)
            s += q[off + e] * Kc[(size_t)j * d + off + e];
        sc[j] = s * scale;
    }
    __syncthreads();

    // Row max.
    float m = -1e30f;
    for (int j = t; j < L; j += ATTN_THREADS) m = fmaxf(m, sc[j]);
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
    for (int j = t; j < L; j += ATTN_THREADS) {
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

    for (int j = t; j < L; j += ATTN_THREADS) sc[j] /= se;
    __syncthreads();

    // Output: thread `e` reduces the weighted value column for this head.
    if (t < head_dim) {
        float acc = 0.0f;
        for (int j = 0; j < L; ++j) acc += sc[j] * Vc[(size_t)j * d + off + t];
        O[off + t] = acc;
    }
}

// Batched decode attention: one block per (head, batch). Each block reads the
// batch's query row + the batch's K/V cache slice. The cache layout is
// `[B, Tmax, d]` per layer so the b-th batch's cache rows are contiguous.
// `q` is `[B, d]`; `O` is `[B, d]`.
__global__ void k_attention_decode_b(const float* q, const float* Kc,
                                     const float* Vc, float* O,
                                     int p, int d, int n_heads, int head_dim,
                                     int Tmax) {
    int h = blockIdx.x;
    int b = blockIdx.y;
    int off = h * head_dim;
    int t = threadIdx.x;
    int L = p + 1;
    float scale = rsqrtf((float)head_dim);

    __shared__ float sc[ATTN_TMAX];
    __shared__ float red[ATTN_THREADS];

    const float* q_b = q + (size_t)b * d;
    const float* Kc_b = Kc + (size_t)b * Tmax * d;
    const float* Vc_b = Vc + (size_t)b * Tmax * d;
    float* O_b = O + (size_t)b * d;

    for (int j = t; j < L; j += ATTN_THREADS) {
        float s = 0.0f;
        for (int e = 0; e < head_dim; ++e)
            s += q_b[off + e] * Kc_b[(size_t)j * d + off + e];
        sc[j] = s * scale;
    }
    __syncthreads();

    float m = -1e30f;
    for (int j = t; j < L; j += ATTN_THREADS) m = fmaxf(m, sc[j]);
    red[t] = m;
    __syncthreads();
    for (int s = ATTN_THREADS / 2; s > 0; s >>= 1) {
        if (t < s) red[t] = fmaxf(red[t], red[t + s]);
        __syncthreads();
    }
    float mx = red[0];
    __syncthreads();

    float partial = 0.0f;
    for (int j = t; j < L; j += ATTN_THREADS) {
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

    for (int j = t; j < L; j += ATTN_THREADS) sc[j] /= se;
    __syncthreads();

    if (t < head_dim) {
        float acc = 0.0f;
        for (int j = 0; j < L; ++j) acc += sc[j] * Vc_b[(size_t)j * d + off + t];
        O_b[off + t] = acc;
    }
}

// Fused decode "post-QKV" kernel: take the QKV row, slice it into q/k/v, RoPE
// q and k at position p (the cos/sin pointers are caller-offset to that row),
// write the rotated q to `qrot`, and append the rotated k and the raw v to
// the per-layer KV cache at row p. Replaces 3 k_slice + 2 k_rope launches per
// layer in the decode hot loop (a ~5x cut in launches for that section). The
// rotation is the adjacent-pair convention CODA uses; matches `k_rope` on a
// single row.
__global__ void k_qkv_rope_cache(const float* qkv, const float* cosP,
                                 const float* sinP, float* qrot,
                                 float* kcache_row, float* vcache_row, int d) {
    int p = blockIdx.x * blockDim.x + threadIdx.x;  // adjacent-pair index
    int c0 = 2 * p, c1 = 2 * p + 1;
    if (c1 >= d) return;
    float q0 = qkv[c0],         q1 = qkv[c1];
    float k0 = qkv[d + c0],     k1 = qkv[d + c1];
    float v0 = qkv[2 * d + c0], v1 = qkv[2 * d + c1];
    float c = cosP[c0], s = sinP[c0];
    qrot[c0]       = q0 * c - q1 * s;
    qrot[c1]       = q0 * s + q1 * c;
    kcache_row[c0] = k0 * c - k1 * s;
    kcache_row[c1] = k0 * s + k1 * c;
    vcache_row[c0] = v0;
    vcache_row[c1] = v1;
}

// Batched version: QKV input is [B, 3d], q output is [B, d], cache is
// [B, Tmax, d] with the row at position `p` written for every batch entry.
// All entries are at the same step position `p` (we decode one new token
// across the whole batch in lockstep).
__global__ void k_qkv_rope_cache_b(const float* qkv, const float* cosP,
                                   const float* sinP, float* qrot,
                                   float* kcache, float* vcache,
                                   int d, int p, int Tmax) {
    int pp = blockIdx.x * blockDim.x + threadIdx.x;
    int b = blockIdx.y;
    int c0 = 2 * pp, c1 = 2 * pp + 1;
    if (c1 >= d) return;
    const float* qkv_b = qkv + (size_t)b * 3 * d;
    float* qrot_b = qrot + (size_t)b * d;
    float* kcache_row = kcache + (size_t)b * Tmax * d + (size_t)p * d;
    float* vcache_row = vcache + (size_t)b * Tmax * d + (size_t)p * d;
    float q0 = qkv_b[c0],         q1 = qkv_b[c1];
    float k0 = qkv_b[d + c0],     k1 = qkv_b[d + c1];
    float v0 = qkv_b[2 * d + c0], v1 = qkv_b[2 * d + c1];
    float c = cosP[c0], s = sinP[c0];
    qrot_b[c0]     = q0 * c - q1 * s;
    qrot_b[c1]     = q0 * s + q1 * c;
    kcache_row[c0] = k0 * c - k1 * s;
    kcache_row[c1] = k0 * s + k1 * c;
    vcache_row[c0] = v0;
    vcache_row[c1] = v1;
}

// Per-row argmax of `logits[B, vocab]` + scatter the resulting token back
// into the `[B, Tmax]` token buffer at position `p_plus_1`, AND write the
// step's batch of new ids to `out_step` for the host. One block per batch
// row; the host then needs only the tiny [B] cudaMemcpy, not the [B, vocab]
// logits transfer per step.
__global__ void k_argmax_scatter(const float* logits, int* tokens,
                                 int* out_step, int B, int N,
                                 int Tmax, int p_plus_1) {
    int b = blockIdx.x;
    int t = threadIdx.x;
    __shared__ float bestv[256];
    __shared__ int besti[256];
    bestv[t] = -1e30f;
    besti[t] = 0;
    const float* row = logits + (size_t)b * N;
    for (int j = t; j < N; j += blockDim.x) {
        float v = row[j];
        if (v > bestv[t]) { bestv[t] = v; besti[t] = j; }
    }
    __syncthreads();
    for (int s = blockDim.x / 2; s > 0; s >>= 1) {
        if (t < s && bestv[t + s] > bestv[t]) {
            bestv[t] = bestv[t + s];
            besti[t] = besti[t + s];
        }
        __syncthreads();
    }
    if (t == 0) {
        int best = besti[0];
        out_step[b] = best;
        tokens[(size_t)b * Tmax + p_plus_1] = best;
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

// Same gather with an fp16 embedding table (the table is promoted to fp32 on
// the load). Used by the generation path so the embedding can live in fp16.
__global__ void k_embed_gather_h(const __half* embed, const int* tokens,
                                 float* x0, int T, int d) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= T || j >= d) return;
    x0[i * d + j] = __half2float(embed[tokens[i] * d + j]);
}

// Batched single-position gather for decode: each batch element has its own
// `[Tmax]` slice of `tokens`, the one we want is at row `p`. Output is
// `[B, d]`. Replaces a per-row k_embed_gather_h launch.
__global__ void k_embed_gather_bdec(const __half* embed, const int* tokens,
                                    int p, int Tmax, float* x, int B, int d) {
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    int b = blockIdx.y;
    if (b >= B || j >= d) return;
    int tok = tokens[(size_t)b * Tmax + p];
    x[(size_t)b * d + j] = __half2float(embed[(size_t)tok * d + j]);
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

// ---------------------------------------------------------------------------
// Device-resident autoregressive generation with a KV cache.
//
// `coda_cuda_model_forward` re-uploads every weight on each call; for a
// multi-billion-parameter model that 27 GB transfer would dwarf the compute.
// This entry point uploads the whole weight set *once* and decodes with only
// one int (the new token) crossing the PCIe bus per step.
//
// Two phases:
//   * Prefill - one tiled forward over the whole prompt, which also fills the
//     per-layer KV cache (rotated keys + values) for positions 0..prompt_len-1.
//   * Decode  - each step processes exactly ONE new token: its projections are
//     matrix-vector products (`launch_gemv_h`), its key/value are appended to
//     the cache, and it attends against the cache instead of recomputing the
//     keys and values of every earlier position. A decode step is therefore
//     O(model) work, not O(model x sequence length) as a cache-free re-forward
//     would be - the difference between ~0.6 s/token and tens of ms/token.
//
// `cosT` / `sinT` are sized for `Tmax` positions; RoPE for the decode token at
// position `p` reads their row `p`. `out_ids` receives the `n_new` greedily
// decoded ids. Returns 0 on success, non-zero on a CUDA error.
// ---------------------------------------------------------------------------
int coda_cuda_generate(
    int Tmax, int d, int n_layers, int n_heads, int head_dim, int d_ff,
    int vocab, float eps,
    const float* embed, const float* gamma_attn, const float* wqkv,
    const float* wo, const float* gamma_ffn, const float* wgu,
    const float* wdown, const float* gamma_final, const float* lm_head,
    const float* cosT, const float* sinT,
    const int* prompt, int prompt_len, int n_new, int* out_ids) {

    int d3 = 3 * d;
    int dff2 = 2 * d_ff;

    // Weights: the big projection matrices are uploaded as fp32 and then
    // converted to fp16 device-side. The per-token decode then streams half
    // the bytes off HBM. The fp32 staging buffers are freed as soon as the
    // conversion is done; only the fp16 copies remain resident. Per-channel
    // gamma weights and the RoPE tables stay fp32 (small and read at every
    // layer, no benefit from going to fp16).
    size_t n_embed = (size_t)vocab * d;
    size_t n_wqkv = (size_t)n_layers * d * d3;
    size_t n_wo = (size_t)n_layers * d * d;
    size_t n_wgu = (size_t)n_layers * d * dff2;
    size_t n_wd = (size_t)n_layers * d_ff * d;
    size_t n_lm = (size_t)d * vocab;
    float* dEmbed_f = up(embed, n_embed);
    float* dWQKV_f = up(wqkv, n_wqkv);
    float* dWO_f = up(wo, n_wo);
    float* dWGU_f = up(wgu, n_wgu);
    float* dWD_f = up(wdown, n_wd);
    float* dLM_f = up(lm_head, n_lm);
    __half *dEmbed = nullptr, *dWQKV = nullptr, *dWO = nullptr;
    __half *dWGU = nullptr, *dWD = nullptr, *dLM = nullptr;
    cudaMalloc(&dEmbed, n_embed * sizeof(__half));
    cudaMalloc(&dWQKV, n_wqkv * sizeof(__half));
    cudaMalloc(&dWO, n_wo * sizeof(__half));
    cudaMalloc(&dWGU, n_wgu * sizeof(__half));
    cudaMalloc(&dWD, n_wd * sizeof(__half));
    cudaMalloc(&dLM, n_lm * sizeof(__half));
    f2h(dEmbed_f, dEmbed, n_embed);
    f2h(dWQKV_f, dWQKV, n_wqkv);
    f2h(dWO_f, dWO, n_wo);
    f2h(dWGU_f, dWGU, n_wgu);
    f2h(dWD_f, dWD, n_wd);
    f2h(dLM_f, dLM, n_lm);
    cudaDeviceSynchronize();
    cudaFree(dEmbed_f); cudaFree(dWQKV_f); cudaFree(dWO_f);
    cudaFree(dWGU_f); cudaFree(dWD_f); cudaFree(dLM_f);

    // Per-channel gamma weights and the RoPE tables stay fp32.
    float* dGA = up(gamma_attn, (size_t)n_layers * d);
    float* dGF = up(gamma_ffn, (size_t)n_layers * d);
    float* dGFinal = up(gamma_final, (size_t)d);
    float* dCos = up(cosT, (size_t)Tmax * d);
    float* dSin = up(sinT, (size_t)Tmax * d);

    // KV cache: rotated keys and values for every layer and position.
    float* dKcache = up(NULL, (size_t)n_layers * Tmax * d);
    float* dVcache = up(NULL, (size_t)n_layers * Tmax * d);

    // Token buffer: the prompt up front, generated ids appended in place.
    int* dTokens = nullptr;
    cudaMalloc(&dTokens, (size_t)Tmax * sizeof(int));
    cudaMemcpy(dTokens, prompt, (size_t)prompt_len * sizeof(int),
               cudaMemcpyHostToDevice);

    // Forward scratch, sized for the longest row count (the prompt prefill).
    float* dX = up(NULL, (size_t)Tmax * d);
    float* dY = up(NULL, (size_t)Tmax * d);
    float* dOnorm = up(NULL, (size_t)Tmax * d);
    float* dR = up(NULL, (size_t)Tmax);
    float* dR2 = up(NULL, (size_t)Tmax);
    float* dQKV = up(NULL, (size_t)Tmax * d3);
    float* dQ = up(NULL, (size_t)Tmax * d);
    float* dK = up(NULL, (size_t)Tmax * d);
    float* dQR = up(NULL, (size_t)Tmax * d);
    float* dAttn = up(NULL, (size_t)Tmax * d);
    float* dH = up(NULL, (size_t)Tmax * d);
    float* dN2 = up(NULL, (size_t)Tmax * d);
    float* dDP = up(NULL, (size_t)Tmax * dff2);
    float* dFF = up(NULL, (size_t)Tmax * d_ff);
    float* dLogits = up(NULL, (size_t)Tmax * vocab);

    // Split-K GEMV partial-sum scratch: sized for n_split * N of the widest
    // decode GEMV (the projections wqkv/wo/wgu/wd and the LM head).
    size_t part_max = (size_t)gemv_split(d3, d) * d3;
    size_t cand;
    cand = (size_t)gemv_split(d, d) * d;          if (cand > part_max) part_max = cand;
    cand = (size_t)gemv_split(dff2, d) * dff2;    if (cand > part_max) part_max = cand;
    cand = (size_t)gemv_split(d, d_ff) * d;       if (cand > part_max) part_max = cand;
    cand = (size_t)gemv_split(vocab, d) * vocab;  if (cand > part_max) part_max = cand;
    float* dPartials = up(NULL, part_max);

    dim3 blk(BLK, BLK);
    float* row = (float*)malloc((size_t)vocab * sizeof(float));
    int err = 0;

    // Per-section CUDA-event timers, accumulated across the decode loop.
    cudaEvent_t e_pre, e_emb, e_layers, e_lm;
    cudaEventCreate(&e_pre); cudaEventCreate(&e_emb);
    cudaEventCreate(&e_layers); cudaEventCreate(&e_lm);
    float t_emb = 0.0f, t_layers = 0.0f, t_lm = 0.0f;
    // One-layer fine breakdown captured on step 1, layer 0.
    cudaEvent_t f[6];
    for (int i = 0; i < 6; ++i) cudaEventCreate(&f[i]);
    float tf[5] = {0, 0, 0, 0, 0};
    bool fine_recorded = false;

    // ---- Prefill: one tiled forward over the whole prompt; fills the KV
    //      cache for positions 0 .. prompt_len-1. ----
    {
        int M = prompt_len;
        float* X = dX;
        float* Y = dY;
        k_embed_gather_h<<<grid2d(d, M), blk>>>(dEmbed, dTokens, X, M, d);
        k_row_invrms<<<(M + 255) / 256, 256>>>(X, dR, M, d, eps);
        k_col_scale<<<grid2d(d, M), blk>>>(X, dGA, dOnorm, M, d);

        for (int l = 0; l < n_layers; ++l) {
            const __half* wqkv_l = dWQKV + (size_t)l * d * d3;
            const __half* wo_l = dWO + (size_t)l * d * d;
            const float* gf_l = dGF + (size_t)l * d;
            const __half* wgu_l = dWGU + (size_t)l * d * dff2;
            const __half* wd_l = dWD + (size_t)l * d_ff * d;
            float* Kc = dKcache + (size_t)l * Tmax * d;
            float* Vc = dVcache + (size_t)l * Tmax * d;

            // QKV projection (Kernel 5); rotated K and V go straight to cache.
            launch_gemm_h<EPI_ROWSCALE>(
                dOnorm, wqkv_l, nullptr, nullptr, dR, nullptr, dQKV, M, d3, d);
            k_slice<<<grid2d(d, M), blk>>>(dQKV, dQ, M, d, d3, 0);
            k_slice<<<grid2d(d, M), blk>>>(dQKV, dK, M, d, d3, d);
            k_slice<<<grid2d(d, M), blk>>>(dQKV, Vc, M, d, d3, 2 * d);
            k_rope<<<grid2d(d / 2, M), blk>>>(dQ, dCos, dSin, dQR, M, d);
            k_rope<<<grid2d(d / 2, M), blk>>>(dK, dCos, dSin, Kc, M, d);
            k_attention<<<M * n_heads, ATTN_THREADS>>>(
                dQR, Kc, Vc, dAttn, nullptr, M, d, n_heads, head_dim);

            // Output proj + residual + FFN-norm (Kernel 4).
            launch_gemm_h<EPI_RESGAMMA>(
                dAttn, wo_l, X, gf_l, nullptr, dH, dN2, M, d, d);
            k_row_invrms<<<(M + 255) / 256, 256>>>(dH, dR2, M, d, eps);

            // Gate/Up projection + SwiGLU (Kernel 6).
            launch_gemm_h<EPI_ROWSCALE>(
                dN2, wgu_l, nullptr, nullptr, dR2, nullptr, dDP, M, dff2, d);
            k_swiglu<<<grid2d(d_ff, M), blk>>>(dDP, dFF, M, d_ff);

            // Down proj + residual + next sublayer's norm (Kernel 4).
            const float* next_gamma =
                (l + 1 < n_layers) ? (dGA + (size_t)(l + 1) * d) : dGFinal;
            launch_gemm_h<EPI_RESGAMMA>(
                dFF, wd_l, dH, next_gamma, nullptr, Y, dOnorm, M, d, d_ff);
            k_row_invrms<<<(M + 255) / 256, 256>>>(Y, dR, M, d, eps);

            float* tmp = X; X = Y; Y = tmp;
        }
        launch_gemm_h<EPI_ROWSCALE>(
            dOnorm, dLM, nullptr, nullptr, dR, nullptr, dLogits, M, vocab, d);
        cudaDeviceSynchronize();
        err = cuda_check("coda_cuda_generate (prefill)");

        if (!err) {
            // Logits of the last prompt row predict the first new token.
            cudaMemcpy(row, dLogits + (size_t)(M - 1) * vocab,
                       (size_t)vocab * sizeof(float), cudaMemcpyDeviceToHost);
            int best = 0;
            float bestv = row[0];
            for (int j = 1; j < vocab; ++j)
                if (row[j] > bestv) { bestv = row[j]; best = j; }
            out_ids[0] = best;
            cudaMemcpy(dTokens + M, &best, sizeof(int), cudaMemcpyHostToDevice);
            printf("    generated token 1/%d  (id %d)\n", n_new, best);
            fflush(stdout);
        }
    }

    // ---- Decode: one new token per step, attending against the KV cache. ----
    for (int step = 1; step < n_new && err == 0; ++step) {
        int p = prompt_len + step - 1;   // absolute position of the input token
        const float* cosP = dCos + (size_t)p * d;
        const float* sinP = dSin + (size_t)p * d;
        float* X = dX;
        float* Y = dY;

        cudaEventRecord(e_pre, 0);

        // Embed the one new token (dTokens[p]), then the embedding-side norm.
        k_embed_gather_h<<<grid2d(d, 1), blk>>>(dEmbed, dTokens + p, X, 1, d);
        k_row_invrms<<<1, 256>>>(X, dR, 1, d, eps);
        k_col_scale<<<grid2d(d, 1), blk>>>(X, dGA, dOnorm, 1, d);
        cudaEventRecord(e_emb, 0);

        for (int l = 0; l < n_layers; ++l) {
            const __half* wqkv_l = dWQKV + (size_t)l * d * d3;
            const __half* wo_l = dWO + (size_t)l * d * d;
            const float* gf_l = dGF + (size_t)l * d;
            const __half* wgu_l = dWGU + (size_t)l * d * dff2;
            const __half* wd_l = dWD + (size_t)l * d_ff * d;
            float* Kc = dKcache + (size_t)l * Tmax * d;
            float* Vc = dVcache + (size_t)l * Tmax * d;
            bool fine = (step == 1 && l == 0);

            // QKV as a matrix-vector product.
            if (fine) cudaEventRecord(f[0], 0);
            launch_gemv_h<EPI_ROWSCALE>(
                dOnorm, wqkv_l, nullptr, nullptr, dR, nullptr, dQKV, d3, d,
                dPartials);
            // Fused: split QKV into q/k/v, RoPE q and k, append k and v to cache.
            if (fine) cudaEventRecord(f[1], 0);
            k_qkv_rope_cache<<<(d / 2 + 255) / 256, 256>>>(
                dQKV, cosP, sinP, dQR,
                Kc + (size_t)p * d, Vc + (size_t)p * d, d);
            // Causal attention over the cache up to position p.
            if (fine) cudaEventRecord(f[2], 0);
            k_attention_decode<<<n_heads, ATTN_THREADS>>>(
                dQR, Kc, Vc, dAttn, p, d, n_heads, head_dim);

            // Output proj + residual + FFN-norm (Kernel 4).
            if (fine) cudaEventRecord(f[3], 0);
            launch_gemv_h<EPI_RESGAMMA>(
                dAttn, wo_l, X, gf_l, nullptr, dH, dN2, d, d, dPartials);
            k_row_invrms<<<1, 256>>>(dH, dR2, 1, d, eps);

            // Gate/Up projection + SwiGLU (Kernel 6) + down proj.
            if (fine) cudaEventRecord(f[4], 0);
            launch_gemv_h<EPI_ROWSCALE>(
                dN2, wgu_l, nullptr, nullptr, dR2, nullptr, dDP, dff2, d,
                dPartials);
            k_swiglu<<<grid2d(d_ff, 1), blk>>>(dDP, dFF, 1, d_ff);
            const float* next_gamma =
                (l + 1 < n_layers) ? (dGA + (size_t)(l + 1) * d) : dGFinal;
            launch_gemv_h<EPI_RESGAMMA>(
                dFF, wd_l, dH, next_gamma, nullptr, Y, dOnorm, d, d_ff,
                dPartials);
            k_row_invrms<<<1, 256>>>(Y, dR, 1, d, eps);
            if (fine) {
                cudaEventRecord(f[5], 0);
                fine_recorded = true;
            }

            float* tmp = X; X = Y; Y = tmp;
        }
        cudaEventRecord(e_layers, 0);

        // LM head: logits = (final-normed residual @ W_lm) * r  (Kernel 5).
        launch_gemv_h<EPI_ROWSCALE>(
            dOnorm, dLM, nullptr, nullptr, dR, nullptr, dLogits, vocab, d,
            dPartials);
        cudaEventRecord(e_lm, 0);
        cudaDeviceSynchronize();
        err = cuda_check("coda_cuda_generate (decode)");
        if (err) break;

        // Accumulate the per-section timings now that the events are done.
        float dt;
        cudaEventElapsedTime(&dt, e_pre, e_emb);     t_emb += dt;
        cudaEventElapsedTime(&dt, e_emb, e_layers);  t_layers += dt;
        cudaEventElapsedTime(&dt, e_layers, e_lm);   t_lm += dt;

        // Greedy: argmax of the single logits row is the next token.
        cudaMemcpy(row, dLogits, (size_t)vocab * sizeof(float),
                   cudaMemcpyDeviceToHost);
        int best = 0;
        float bestv = row[0];
        for (int j = 1; j < vocab; ++j)
            if (row[j] > bestv) { bestv = row[j]; best = j; }
        out_ids[step] = best;
        cudaMemcpy(dTokens + p + 1, &best, sizeof(int), cudaMemcpyHostToDevice);
        // Per-token printf+fflush against Modal's log-capture pipeline costs
        // ~150 ms/step (the GPU work itself is ~18 ms). Print periodically
        // instead so progress is still visible but the run isn't dominated
        // by stdout flushes.
        if ((step + 1) % 32 == 0 || step == n_new - 1) {
            printf("    generated %d/%d tokens\n", step + 1, n_new);
            fflush(stdout);
        }
    }

    // Decode timing breakdown (averaged over the steps that actually ran).
    int n_dec = (err == 0) ? (n_new - 1) : 0;
    if (n_dec > 0) {
        float total = t_emb + t_layers + t_lm;
        printf("\n    decode timing breakdown (mean over %d steps):\n", n_dec);
        printf("      embed prelude     %6.3f ms  (%.1f%%)\n",
               t_emb / n_dec, 100.0f * t_emb / total);
        printf("      %d layers (loop)   %6.3f ms  (%.1f%%)\n",
               n_layers, t_layers / n_dec, 100.0f * t_layers / total);
        printf("      LM head GEMV      %6.3f ms  (%.1f%%)\n",
               t_lm / n_dec, 100.0f * t_lm / total);
        printf("      GPU sum per step  %6.3f ms\n", total / n_dec);
    }
    if (fine_recorded) {
        float dt;
        cudaEventElapsedTime(&dt, f[0], f[1]); tf[0] = dt;  // qkv gemv
        cudaEventElapsedTime(&dt, f[1], f[2]); tf[1] = dt;  // fused qkv->rope/cache
        cudaEventElapsedTime(&dt, f[2], f[3]); tf[2] = dt;  // attention decode
        cudaEventElapsedTime(&dt, f[3], f[4]); tf[3] = dt;  // wo + invrms
        cudaEventElapsedTime(&dt, f[4], f[5]); tf[4] = dt;  // wgu + swiglu + wd + invrms
        printf("    one-layer sample (step 1, layer 0):\n");
        printf("      qkv GEMV          %6.3f ms\n", tf[0]);
        printf("      qkv->qkv+RoPE+$   %6.3f ms  (fused: slice/rope/cache)\n", tf[1]);
        printf("      attention decode  %6.3f ms\n", tf[2]);
        printf("      wo GEMV + invrms  %6.3f ms\n", tf[3]);
        printf("      wgu/swiglu/wd     %6.3f ms\n", tf[4]);
    }

    cudaEventDestroy(e_pre); cudaEventDestroy(e_emb);
    cudaEventDestroy(e_layers); cudaEventDestroy(e_lm);
    for (int i = 0; i < 6; ++i) cudaEventDestroy(f[i]);

    free(row);
    cudaFree(dEmbed); cudaFree(dGA); cudaFree(dWQKV); cudaFree(dWO);
    cudaFree(dGF); cudaFree(dWGU); cudaFree(dWD); cudaFree(dGFinal);
    cudaFree(dLM); cudaFree(dCos); cudaFree(dSin);
    cudaFree(dKcache); cudaFree(dVcache); cudaFree(dTokens);
    cudaFree(dX); cudaFree(dY); cudaFree(dOnorm); cudaFree(dR); cudaFree(dR2);
    cudaFree(dQKV); cudaFree(dQ); cudaFree(dK); cudaFree(dQR);
    cudaFree(dAttn); cudaFree(dH); cudaFree(dN2);
    cudaFree(dDP); cudaFree(dFF); cudaFree(dLogits); cudaFree(dPartials);
    return err;
}

// ---------------------------------------------------------------------------
// Batched device-resident generation.
//
// Same idea as `coda_cuda_generate` but `batch` prompts are processed in
// lockstep during decode. The decode step's projection "GEMMs" now have
// M = batch instead of M = 1, so the tiled GEMM (`launch_gemm_h`) does real
// work per step and the weight read is amortized across `batch` tokens.
// Aggregate throughput scales roughly linearly with batch up to the
// compute-bound shoulder.
//
// Memory layout:
//   * KV cache is `[n_layers, batch, Tmax, d]` so a single per-layer pointer
//     plus a batch offset locates each request's cached keys/values.
//   * Token buffer is `[batch, Tmax]`; prompts are uploaded in one block.
//
// Prefill is run sequentially per request (one-shot, small fraction of total
// time). Decode is fully batched. All prompts must have the same length; the
// caller pads if needed. `out_ids` is `[batch, n_new]` flat.
// ---------------------------------------------------------------------------
int coda_cuda_generate_batch(
    int Tmax, int d, int n_layers, int n_heads, int head_dim, int d_ff,
    int vocab, float eps, int batch,
    const float* embed, const float* gamma_attn, const float* wqkv,
    const float* wo, const float* gamma_ffn, const float* wgu,
    const float* wdown, const float* gamma_final, const float* lm_head,
    const float* cosT, const float* sinT,
    const int* prompts, int prompt_len, int n_new, int* out_ids) {

    int B = batch;
    int d3 = 3 * d;
    int dff2 = 2 * d_ff;

    // ---- Weights: same fp32 -> fp16 device-side conversion as the
    //      single-prompt path. ----
    size_t n_embed = (size_t)vocab * d;
    size_t n_wqkv = (size_t)n_layers * d * d3;
    size_t n_wo = (size_t)n_layers * d * d;
    size_t n_wgu = (size_t)n_layers * d * dff2;
    size_t n_wd = (size_t)n_layers * d_ff * d;
    size_t n_lm = (size_t)d * vocab;
    float* dEmbed_f = up(embed, n_embed);
    float* dWQKV_f = up(wqkv, n_wqkv);
    float* dWO_f = up(wo, n_wo);
    float* dWGU_f = up(wgu, n_wgu);
    float* dWD_f = up(wdown, n_wd);
    float* dLM_f = up(lm_head, n_lm);
    __half *dEmbed = nullptr, *dWQKV = nullptr, *dWO = nullptr;
    __half *dWGU = nullptr, *dWD = nullptr, *dLM = nullptr;
    cudaMalloc(&dEmbed, n_embed * sizeof(__half));
    cudaMalloc(&dWQKV, n_wqkv * sizeof(__half));
    cudaMalloc(&dWO, n_wo * sizeof(__half));
    cudaMalloc(&dWGU, n_wgu * sizeof(__half));
    cudaMalloc(&dWD, n_wd * sizeof(__half));
    cudaMalloc(&dLM, n_lm * sizeof(__half));
    f2h(dEmbed_f, dEmbed, n_embed);
    f2h(dWQKV_f, dWQKV, n_wqkv);
    f2h(dWO_f, dWO, n_wo);
    f2h(dWGU_f, dWGU, n_wgu);
    f2h(dWD_f, dWD, n_wd);
    f2h(dLM_f, dLM, n_lm);
    cudaDeviceSynchronize();
    cudaFree(dEmbed_f); cudaFree(dWQKV_f); cudaFree(dWO_f);
    cudaFree(dWGU_f); cudaFree(dWD_f); cudaFree(dLM_f);

    float* dGA = up(gamma_attn, (size_t)n_layers * d);
    float* dGF = up(gamma_ffn, (size_t)n_layers * d);
    float* dGFinal = up(gamma_final, (size_t)d);
    float* dCos = up(cosT, (size_t)Tmax * d);
    float* dSin = up(sinT, (size_t)Tmax * d);

    // KV cache: [n_layers, B, Tmax, d].
    float* dKcache = up(NULL, (size_t)n_layers * B * Tmax * d);
    float* dVcache = up(NULL, (size_t)n_layers * B * Tmax * d);

    // Token buffer: [B, Tmax]. Prompts uploaded in one batched block; each
    // request's slice is row b.
    int* dTokens = nullptr;
    cudaMalloc(&dTokens, (size_t)B * Tmax * sizeof(int));
    for (int b = 0; b < B; ++b) {
        cudaMemcpy(dTokens + (size_t)b * Tmax,
                   prompts + (size_t)b * prompt_len,
                   (size_t)prompt_len * sizeof(int),
                   cudaMemcpyHostToDevice);
    }
    // Per-step next-token staging (B ids) and host-side copy buffer.
    int* dNextToks = nullptr;
    cudaMalloc(&dNextToks, (size_t)B * sizeof(int));

    // Scratch: sized for max(B, prompt_len) on the row dimension so both
    // serial prefill and batched decode share the buffers.
    int Mmax = B > prompt_len ? B : prompt_len;
    float* dX = up(NULL, (size_t)Mmax * d);
    float* dY = up(NULL, (size_t)Mmax * d);
    float* dOnorm = up(NULL, (size_t)Mmax * d);
    float* dR = up(NULL, (size_t)Mmax);
    float* dR2 = up(NULL, (size_t)Mmax);
    float* dQKV = up(NULL, (size_t)Mmax * d3);
    float* dQ = up(NULL, (size_t)Mmax * d);
    float* dK = up(NULL, (size_t)Mmax * d);
    float* dQR = up(NULL, (size_t)Mmax * d);
    float* dAttn = up(NULL, (size_t)Mmax * d);
    float* dH = up(NULL, (size_t)Mmax * d);
    float* dN2 = up(NULL, (size_t)Mmax * d);
    float* dDP = up(NULL, (size_t)Mmax * dff2);
    float* dFF = up(NULL, (size_t)Mmax * d_ff);
    float* dLogits = up(NULL, (size_t)Mmax * vocab);

    dim3 blk(BLK, BLK);
    float* row = (float*)malloc((size_t)vocab * sizeof(float));
    int* host_next = (int*)malloc((size_t)B * sizeof(int));
    int err = 0;

    // cuBLAS handle for the decode-loop GEMMs; the hand-rolled k_gemm_tc_h is
    // 3-5% of peak on these shapes, cuBLAS hits ~150-200 TFLOPS. The CODA
    // epilogue still runs as a separate kernel right after.
    cublasHandle_t cublas = nullptr;
    cublasCreate(&cublas);
    cublasSetMathMode(cublas, CUBLAS_TF32_TENSOR_OP_MATH);
    // Scratch fp16 activation buffer for the cuBLAS path; sized for the
    // widest decode GEMM's M*K.
    size_t a_h_max = (size_t)B * d;
    if ((size_t)B * d_ff > a_h_max) a_h_max = (size_t)B * d_ff;
    __half* dA_h = nullptr;
    cudaMalloc(&dA_h, a_h_max * sizeof(__half));

    // Per-section CUDA-event timers across the batched decode loop.
    cudaEvent_t e_pre, e_emb, e_layers, e_lm, e_done;
    cudaEventCreate(&e_pre); cudaEventCreate(&e_emb);
    cudaEventCreate(&e_layers); cudaEventCreate(&e_lm);
    cudaEventCreate(&e_done);
    float t_emb = 0.0f, t_layers = 0.0f, t_lm = 0.0f, t_argmax = 0.0f;
    cudaEvent_t f[6];
    for (int i = 0; i < 6; ++i) cudaEventCreate(&f[i]);
    float tf[5] = {0, 0, 0, 0, 0};
    bool fine_recorded = false;

    // ---- Prefill: serially process each prompt; fills its KV-cache slice
    //      and produces its first generated token. ----
    for (int b = 0; b < B && err == 0; ++b) {
        int M = prompt_len;
        const int* tokens_b = dTokens + (size_t)b * Tmax;
        float* X = dX;
        float* Y = dY;
        k_embed_gather_h<<<grid2d(d, M), blk>>>(dEmbed, tokens_b, X, M, d);
        k_row_invrms<<<(M + 255) / 256, 256>>>(X, dR, M, d, eps);
        k_col_scale<<<grid2d(d, M), blk>>>(X, dGA, dOnorm, M, d);

        for (int l = 0; l < n_layers; ++l) {
            const __half* wqkv_l = dWQKV + (size_t)l * d * d3;
            const __half* wo_l = dWO + (size_t)l * d * d;
            const float* gf_l = dGF + (size_t)l * d;
            const __half* wgu_l = dWGU + (size_t)l * d * dff2;
            const __half* wd_l = dWD + (size_t)l * d_ff * d;
            // Cache slice for this layer and this batch row.
            float* Kc_b = dKcache + ((size_t)l * B + b) * Tmax * d;
            float* Vc_b = dVcache + ((size_t)l * B + b) * Tmax * d;

            launch_gemm_h<EPI_ROWSCALE>(
                dOnorm, wqkv_l, nullptr, nullptr, dR, nullptr, dQKV, M, d3, d);
            k_slice<<<grid2d(d, M), blk>>>(dQKV, dQ, M, d, d3, 0);
            k_slice<<<grid2d(d, M), blk>>>(dQKV, dK, M, d, d3, d);
            k_slice<<<grid2d(d, M), blk>>>(dQKV, Vc_b, M, d, d3, 2 * d);
            k_rope<<<grid2d(d / 2, M), blk>>>(dQ, dCos, dSin, dQR, M, d);
            k_rope<<<grid2d(d / 2, M), blk>>>(dK, dCos, dSin, Kc_b, M, d);
            k_attention<<<M * n_heads, ATTN_THREADS>>>(
                dQR, Kc_b, Vc_b, dAttn, nullptr, M, d, n_heads, head_dim);

            launch_gemm_h<EPI_RESGAMMA>(
                dAttn, wo_l, X, gf_l, nullptr, dH, dN2, M, d, d);
            k_row_invrms<<<(M + 255) / 256, 256>>>(dH, dR2, M, d, eps);
            launch_gemm_h<EPI_ROWSCALE>(
                dN2, wgu_l, nullptr, nullptr, dR2, nullptr, dDP, M, dff2, d);
            k_swiglu<<<grid2d(d_ff, M), blk>>>(dDP, dFF, M, d_ff);
            const float* next_gamma =
                (l + 1 < n_layers) ? (dGA + (size_t)(l + 1) * d) : dGFinal;
            launch_gemm_h<EPI_RESGAMMA>(
                dFF, wd_l, dH, next_gamma, nullptr, Y, dOnorm, M, d, d_ff);
            k_row_invrms<<<(M + 255) / 256, 256>>>(Y, dR, M, d, eps);

            float* tmp = X; X = Y; Y = tmp;
        }
        launch_gemm_h<EPI_ROWSCALE>(
            dOnorm, dLM, nullptr, nullptr, dR, nullptr, dLogits, M, vocab, d);
        cudaDeviceSynchronize();
        err = cuda_check("coda_cuda_generate_batch (prefill)");
        if (err) break;

        cudaMemcpy(row, dLogits + (size_t)(M - 1) * vocab,
                   (size_t)vocab * sizeof(float), cudaMemcpyDeviceToHost);
        int best = 0;
        float bestv = row[0];
        for (int j = 1; j < vocab; ++j)
            if (row[j] > bestv) { bestv = row[j]; best = j; }
        out_ids[(size_t)b * n_new] = best;
        cudaMemcpy(dTokens + (size_t)b * Tmax + prompt_len, &best,
                   sizeof(int), cudaMemcpyHostToDevice);
    }
    printf("    prefilled %d prompts\n", B);
    fflush(stdout);

    // ---- Batched decode: one new token per request per step. ----
    for (int step = 1; step < n_new && err == 0; ++step) {
        int p = prompt_len + step - 1;
        const float* cosP = dCos + (size_t)p * d;
        const float* sinP = dSin + (size_t)p * d;
        float* X = dX;
        float* Y = dY;
        cudaEventRecord(e_pre, 0);

        // Gather the one new token per request from row `p` of each batch slice.
        k_embed_gather_bdec<<<dim3((d + 255) / 256, B), 256>>>(
            dEmbed, dTokens, p, Tmax, X, B, d);
        k_row_invrms<<<(B + 255) / 256, 256>>>(X, dR, B, d, eps);
        k_col_scale<<<grid2d(d, B), blk>>>(X, dGA, dOnorm, B, d);
        cudaEventRecord(e_emb, 0);

        for (int l = 0; l < n_layers; ++l) {
            const __half* wqkv_l = dWQKV + (size_t)l * d * d3;
            const __half* wo_l = dWO + (size_t)l * d * d;
            const float* gf_l = dGF + (size_t)l * d;
            const __half* wgu_l = dWGU + (size_t)l * d * dff2;
            const __half* wd_l = dWD + (size_t)l * d_ff * d;
            float* Kc = dKcache + (size_t)l * B * Tmax * d;
            float* Vc = dVcache + (size_t)l * B * Tmax * d;
            bool fine = (step == 1 && l == 0);

            // QKV: cuBLAS GEMM + CODA EPI_ROWSCALE epilogue.
            if (fine) cudaEventRecord(f[0], 0);
            err |= cublas_gemm_h(cublas, dOnorm, wqkv_l, dQKV, dA_h, B, d3, d);
            launch_epi_rowscale(dR, dQKV, B, d3);
            if (fine) cudaEventRecord(f[1], 0);
            k_qkv_rope_cache_b<<<dim3((d / 2 + 255) / 256, B), 256>>>(
                dQKV, cosP, sinP, dQR, Kc, Vc, d, p, Tmax);
            if (fine) cudaEventRecord(f[2], 0);
            k_attention_decode_b<<<dim3(n_heads, B), ATTN_THREADS>>>(
                dQR, Kc, Vc, dAttn, p, d, n_heads, head_dim, Tmax);

            // Output proj: cuBLAS GEMM + EPI_RESGAMMA (residual + gamma).
            if (fine) cudaEventRecord(f[3], 0);
            err |= cublas_gemm_h(cublas, dAttn, wo_l, dH, dA_h, B, d, d);
            launch_epi_resgamma(X, gf_l, dH, dN2, B, d);
            k_row_invrms<<<(B + 255) / 256, 256>>>(dH, dR2, B, d, eps);

            // FFN: wgu (ROWSCALE) -> SwiGLU -> wd (RESGAMMA into next residual).
            if (fine) cudaEventRecord(f[4], 0);
            err |= cublas_gemm_h(cublas, dN2, wgu_l, dDP, dA_h, B, dff2, d);
            launch_epi_rowscale(dR2, dDP, B, dff2);
            k_swiglu<<<grid2d(d_ff, B), blk>>>(dDP, dFF, B, d_ff);
            const float* next_gamma =
                (l + 1 < n_layers) ? (dGA + (size_t)(l + 1) * d) : dGFinal;
            err |= cublas_gemm_h(cublas, dFF, wd_l, Y, dA_h, B, d, d_ff);
            launch_epi_resgamma(dH, next_gamma, Y, dOnorm, B, d);
            k_row_invrms<<<(B + 255) / 256, 256>>>(Y, dR, B, d, eps);
            if (fine) {
                cudaEventRecord(f[5], 0);
                fine_recorded = true;
            }

            float* tmp = X; X = Y; Y = tmp;
        }
        cudaEventRecord(e_layers, 0);

        // LM head: cuBLAS GEMM + EPI_ROWSCALE.
        err |= cublas_gemm_h(cublas, dOnorm, dLM, dLogits, dA_h, B, vocab, d);
        launch_epi_rowscale(dR, dLogits, B, vocab);
        // Device-side argmax over each row + scatter into the token buffer.
        // Host only needs the B new ids (256 bytes for B = 64).
        k_argmax_scatter<<<B, 256>>>(
            dLogits, dTokens, dNextToks, B, vocab, Tmax, p + 1);
        cudaEventRecord(e_lm, 0);
        cudaMemcpy(host_next, dNextToks, (size_t)B * sizeof(int),
                   cudaMemcpyDeviceToHost);
        cudaEventRecord(e_done, 0);
        err = cuda_check("coda_cuda_generate_batch (decode)");
        if (err) break;
        for (int b = 0; b < B; ++b) out_ids[(size_t)b * n_new + step] = host_next[b];

        // Accumulate per-section timings (the cudaMemcpy above synchronizes).
        float dt;
        cudaEventElapsedTime(&dt, e_pre, e_emb);     t_emb += dt;
        cudaEventElapsedTime(&dt, e_emb, e_layers);  t_layers += dt;
        cudaEventElapsedTime(&dt, e_layers, e_lm);   t_lm += dt;
        cudaEventElapsedTime(&dt, e_lm, e_done);     t_argmax += dt;

        if ((step + 1) % 32 == 0 || step == n_new - 1) {
            printf("    generated %d/%d tokens across %d prompts\n",
                   step + 1, n_new, B);
            fflush(stdout);
        }
    }

    // Decode timing breakdown.
    int n_dec = (err == 0) ? (n_new - 1) : 0;
    if (n_dec > 0) {
        float total = t_emb + t_layers + t_lm + t_argmax;
        printf("\n    batched decode timing (mean over %d steps, B = %d):\n",
               n_dec, B);
        printf("      embed prelude      %7.3f ms  (%.1f%%)\n",
               t_emb / n_dec, 100.0f * t_emb / total);
        printf("      %d layers (loop)    %7.3f ms  (%.1f%%)\n",
               n_layers, t_layers / n_dec, 100.0f * t_layers / total);
        printf("      LM head + argmax   %7.3f ms  (%.1f%%)\n",
               t_lm / n_dec, 100.0f * t_lm / total);
        printf("      next-token sync    %7.3f ms  (%.1f%%)\n",
               t_argmax / n_dec, 100.0f * t_argmax / total);
        printf("      GPU sum per step   %7.3f ms\n", total / n_dec);
    }
    if (fine_recorded) {
        float dt;
        cudaEventElapsedTime(&dt, f[0], f[1]); tf[0] = dt;
        cudaEventElapsedTime(&dt, f[1], f[2]); tf[1] = dt;
        cudaEventElapsedTime(&dt, f[2], f[3]); tf[2] = dt;
        cudaEventElapsedTime(&dt, f[3], f[4]); tf[3] = dt;
        cudaEventElapsedTime(&dt, f[4], f[5]); tf[4] = dt;
        printf("    one-layer sample (step 1, layer 0):\n");
        printf("      qkv GEMM           %7.3f ms\n", tf[0]);
        printf("      qkv->Q/K/V+RoPE+$  %7.3f ms\n", tf[1]);
        printf("      attention decode   %7.3f ms\n", tf[2]);
        printf("      wo GEMM + invrms   %7.3f ms\n", tf[3]);
        printf("      wgu/swiglu/wd      %7.3f ms\n", tf[4]);
    }

    cudaEventDestroy(e_pre); cudaEventDestroy(e_emb);
    cudaEventDestroy(e_layers); cudaEventDestroy(e_lm);
    cudaEventDestroy(e_done);
    for (int i = 0; i < 6; ++i) cudaEventDestroy(f[i]);

    cublasDestroy(cublas);
    cudaFree(dA_h);
    free(row);
    free(host_next);
    cudaFree(dEmbed); cudaFree(dGA); cudaFree(dWQKV); cudaFree(dWO);
    cudaFree(dGF); cudaFree(dWGU); cudaFree(dWD); cudaFree(dGFinal);
    cudaFree(dLM); cudaFree(dCos); cudaFree(dSin);
    cudaFree(dKcache); cudaFree(dVcache); cudaFree(dTokens); cudaFree(dNextToks);
    cudaFree(dX); cudaFree(dY); cudaFree(dOnorm); cudaFree(dR); cudaFree(dR2);
    cudaFree(dQKV); cudaFree(dQ); cudaFree(dK); cudaFree(dQR);
    cudaFree(dAttn); cudaFree(dH); cudaFree(dN2);
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

// Train a model on a real corpus by stochastic windowed training.
//
// The whole token corpus is uploaded once and stays on the GPU; each step
// copies a different (host-chosen) length-T window into the input/target
// buffers and runs one fwd_bwd + Adam step. Because every step sees a fresh
// window of real text, the model learns the corpus distribution rather than
// memorizing a single sequence. Weights are trained in place.
int coda_cuda_train_corpus(
    int T, int d, int nl, int nh, int hd, int dff, int vocab, float eps,
    float* embed, float* ga, float* wqkv, float* wo, float* gf, float* wgu,
    float* wd, float* gfin, float* lm, const float* cosT, const float* sinT,
    const int* corpus, int corpus_len, const int* window_starts,
    int n_steps, int batch, float lr, float* loss_curve) {

    Net n;
    n.T = T; n.d = d; n.nl = nl; n.nh = nh; n.hd = hd; n.dff = dff;
    n.vocab = vocab; n.eps = eps;
    n.use_adam = 1;
    alloc_net(&n);
    upload_weights(&n, embed, ga, wqkv, wo, gf, wgu, wd, gfin, lm);
    cudaMemcpy(n.cosT, cosT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(n.sinT, sinT, (size_t)T * d * sizeof(float), cudaMemcpyHostToDevice);

    int* dCorpus = nullptr;
    cudaMalloc(&dCorpus, (size_t)corpus_len * sizeof(int));
    cudaMemcpy(dCorpus, corpus, (size_t)corpus_len * sizeof(int),
               cudaMemcpyHostToDevice);

    int d3 = 3 * d, dff2 = 2 * dff;
    struct WT { float* p; float* g; float* m; float* v; size_t n; };
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
    // Per-tensor gradient accumulators: one Adam step uses the gradient summed
    // over `batch` windows, which cuts the batch-1 gradient noise that would
    // otherwise stall convergence on a real (non-memorized) corpus.
    float* acc[9];
    for (int i = 0; i < 9; ++i) acc[i] = up(0, wts[i].n);
    for (WT& w : wts) {
        cudaMemset(w.m, 0, w.n * sizeof(float));
        cudaMemset(w.v, 0, w.n * sizeof(float));
    }

    for (int step = 0; step < n_steps; ++step) {
        for (int i = 0; i < 9; ++i)
            cudaMemsetAsync(acc[i], 0, wts[i].n * sizeof(float), 0);
        float lsum = 0.0f;
        for (int b = 0; b < batch; ++b) {
            int s = window_starts[step * batch + b];
            cudaMemcpyAsync(n.tokens, dCorpus + s, (size_t)T * sizeof(int),
                            cudaMemcpyDeviceToDevice, 0);
            cudaMemcpyAsync(n.targets, dCorpus + s + 1, (size_t)T * sizeof(int),
                            cudaMemcpyDeviceToDevice, 0);
            lsum += fwd_bwd(&n);
            for (int i = 0; i < 9; ++i) {
                int blk = (int)((wts[i].n + 255) / 256);
                k_add<<<blk, 256>>>(acc[i], wts[i].g, (int)wts[i].n);
            }
        }
        loss_curve[step] = lsum / (float)batch;
        // Adam is ~invariant to gradient scale (m / sqrt(v)), so the summed
        // accumulator works directly as the mini-batch gradient.
        for (int i = 0; i < 9; ++i) {
            int blk = (int)((wts[i].n + 255) / 256);
            k_adam<<<blk, 256>>>(wts[i].p, acc[i], wts[i].m, wts[i].v,
                                 (long)wts[i].n, lr, 0.9f, 0.999f, 1e-8f, step + 1);
        }
    }
    for (int i = 0; i < 9; ++i) cudaFree(acc[i]);
    cudaDeviceSynchronize();
    int err = cuda_check("coda_cuda_train_corpus");

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
    cudaFree(dCorpus);
    free_net(&n);
    return err;
}

}  // extern "C"
