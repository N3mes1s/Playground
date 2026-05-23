//! The `Mat` type and DRAM-traffic instrumentation.
//!
//! CODA's claim is about *data movement*. To make that claim measurable on a
//! CPU, every operator that streams an activation-sized tensor through "global
//! memory" calls [`account_read`] / [`account_write`]. Fused CODA kernels keep
//! intermediates in the on-chip accumulator and therefore never account them;
//! the naive unfused [`crate::reference`] path materializes every intermediate
//! and accounts each one. Comparing the two counters quantifies the win.

use std::cell::Cell;

// The counters are thread-local: each unit of work (the demo, or one test
// thread) measures its own traffic independently, with no cross-talk.
thread_local! {
    static DRAM_BYTES: Cell<u64> = const { Cell::new(0) };
    static DRAM_TENSORS: Cell<u64> = const { Cell::new(0) };
}

/// Reset the DRAM-traffic counters to zero.
pub fn reset_traffic() {
    DRAM_BYTES.with(|c| c.set(0));
    DRAM_TENSORS.with(|c| c.set(0));
}

/// Total bytes streamed through "global memory" since the last reset.
pub fn traffic_bytes() -> u64 {
    DRAM_BYTES.with(|c| c.get())
}

/// Number of distinct tensor read/write events since the last reset.
pub fn traffic_tensors() -> u64 {
    DRAM_TENSORS.with(|c| c.get())
}

/// Record a global-memory traffic event of `elems` f32 values.
pub fn account_elems(elems: usize) {
    DRAM_BYTES.with(|c| c.set(c.get() + elems as u64 * 4));
    DRAM_TENSORS.with(|c| c.set(c.get() + 1));
}

/// Account a full read of `m` from global memory.
pub fn account_read(m: &Mat) {
    account_elems(m.data.len());
}

/// Account a full write of `m` to global memory.
pub fn account_write(m: &Mat) {
    account_elems(m.data.len());
}

/// A dense, row-major `rows x cols` matrix of `f32`.
#[derive(Clone, Debug, PartialEq)]
pub struct Mat {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<f32>,
}

impl Mat {
    /// All-zero matrix.
    pub fn zeros(rows: usize, cols: usize) -> Mat {
        Mat { rows, cols, data: vec![0.0; rows * cols] }
    }

    /// Build from an existing row-major buffer.
    pub fn from_vec(rows: usize, cols: usize, data: Vec<f32>) -> Mat {
        assert_eq!(rows * cols, data.len(), "Mat::from_vec shape mismatch");
        Mat { rows, cols, data }
    }

    /// Number of elements.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the matrix is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Element at `(i, j)`.
    #[inline]
    pub fn get(&self, i: usize, j: usize) -> f32 {
        self.data[i * self.cols + j]
    }

    /// Set element at `(i, j)`.
    #[inline]
    pub fn set(&mut self, i: usize, j: usize, v: f32) {
        self.data[i * self.cols + j] = v;
    }

    /// Add `v` to element `(i, j)`.
    #[inline]
    pub fn add(&mut self, i: usize, j: usize, v: f32) {
        self.data[i * self.cols + j] += v;
    }

    /// Immutable view of row `i`.
    #[inline]
    pub fn row(&self, i: usize) -> &[f32] {
        &self.data[i * self.cols..(i + 1) * self.cols]
    }

    /// Mutable view of row `i`.
    #[inline]
    pub fn row_mut(&mut self, i: usize) -> &mut [f32] {
        &mut self.data[i * self.cols..(i + 1) * self.cols]
    }

    /// Transpose into a fresh matrix (used by reference / weight-gradient code).
    pub fn transpose(&self) -> Mat {
        let mut out = Mat::zeros(self.cols, self.rows);
        for i in 0..self.rows {
            for j in 0..self.cols {
                out.set(j, i, self.get(i, j));
            }
        }
        out
    }

    /// Max absolute element-wise difference against `other` (same shape).
    pub fn max_abs_diff(&self, other: &Mat) -> f32 {
        assert_eq!((self.rows, self.cols), (other.rows, other.cols));
        self.data
            .iter()
            .zip(&other.data)
            .map(|(a, b)| (a - b).abs())
            .fold(0.0, f32::max)
    }
}
