//! Minimal, dependency-free linear-algebra primitives used by the repository
//! encoder and the Code2LoRA hypernetwork. Everything is `f32`, row-major.
//!
//! This is deliberately small: the hypernetwork forward pass is just a handful
//! of dense matmuls plus elementwise nonlinearities, so we avoid pulling in a
//! heavyweight tensor framework and keep the build fast and reproducible.

/// Deterministic PRNG (splitmix64 seed -> xoshiro256**-style stream).
/// Reproducible weight init is important: the same seed must always produce the
/// same hypernetwork, so that "same repo -> same adapter" holds bit-for-bit.
pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        // splitmix64 to expand the seed into the 256-bit state.
        let mut z = seed.wrapping_add(0x9E3779B97F4A7C15);
        let mut next = || {
            z = z.wrapping_add(0x9E3779B97F4A7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
            x ^ (x >> 31)
        };
        Rng {
            s: [next(), next(), next(), next()],
        }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform f32 in [0, 1).
    #[inline]
    pub fn uniform(&mut self) -> f32 {
        // 24 random bits -> [0,1)
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }

    /// Standard normal via Box-Muller.
    #[inline]
    pub fn normal(&mut self) -> f32 {
        let u1 = (self.uniform()).max(1e-9);
        let u2 = self.uniform();
        (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos()
    }
}

/// Row-major dense matrix of f32.
#[derive(Clone)]
pub struct Mat {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<f32>,
}

impl Mat {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Mat {
            rows,
            cols,
            data: vec![0.0; rows * cols],
        }
    }

    /// Kaiming/LeCun-ish normal init scaled by `1/sqrt(fan_in)`.
    pub fn randn(rows: usize, cols: usize, rng: &mut Rng) -> Self {
        let scale = 1.0 / (cols as f32).sqrt();
        let mut data = vec![0.0f32; rows * cols];
        for v in data.iter_mut() {
            *v = rng.normal() * scale;
        }
        Mat { rows, cols, data }
    }

    #[inline]
    pub fn row(&self, r: usize) -> &[f32] {
        &self.data[r * self.cols..(r + 1) * self.cols]
    }

    /// y = self @ x, where x has length == self.cols, returns length == self.rows.
    pub fn matvec(&self, x: &[f32]) -> Vec<f32> {
        assert_eq!(x.len(), self.cols, "matvec dim mismatch");
        let mut y = vec![0.0f32; self.rows];
        for r in 0..self.rows {
            let row = self.row(r);
            let mut acc = 0.0f32;
            for c in 0..self.cols {
                acc += row[c] * x[c];
            }
            y[r] = acc;
        }
        y
    }
}

/// Exact GELU (tanh-free erf approximation good enough for a forward pass).
#[inline]
pub fn gelu(x: f32) -> f32 {
    0.5 * x * (1.0 + (0.7978845608028654 * (x + 0.044715 * x * x * x)).tanh())
}

/// Logistic sigmoid.
#[inline]
pub fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Parameter-free LayerNorm over a vector (zero-mean, unit-variance).
pub fn layernorm(v: &mut [f32], eps: f32) {
    let n = v.len() as f32;
    if n == 0.0 {
        return;
    }
    let mean = v.iter().sum::<f32>() / n;
    let var = v.iter().map(|x| (x - mean) * (x - mean)).sum::<f32>() / n;
    let inv = 1.0 / (var + eps).sqrt();
    for x in v.iter_mut() {
        *x = (*x - mean) * inv;
    }
}

/// L2-normalize a vector in place; returns the original norm.
pub fn l2_normalize(v: &mut [f32]) -> f32 {
    let norm = (v.iter().map(|x| x * x).sum::<f32>()).sqrt();
    if norm > 1e-12 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
    norm
}

/// Frobenius norm of a flat slice.
pub fn frob(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}
