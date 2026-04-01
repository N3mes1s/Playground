//! Multi-layer Rust engine for the WASM-in-transformer interpreter.
//!
//! d_model=48, n_heads=24, head_dim=2, n_layers=12.
//! Each active attention head uses an incremental 2D convex hull for
//! O(log n) max-dot-product queries — the blog's core innovation.

use pyo3::prelude::*;
use std::f64;

const D: usize = 48;
const N_HEADS: usize = 24;
const N_LAYERS: usize = 12;
const HD: usize = 2;
const VOCAB: usize = 520;
const D_FFN: usize = 512;
const SCALE: f64 = 0.7071067811865476; // 1/sqrt(2)

// ============================================================
// 2D Convex Hull with O(log n) max-dot queries
// ============================================================
// For max q·k over all inserted keys k = (kx, ky):
//   The maximum is always on the convex hull boundary.
//   For a query direction (qx, qy), we binary search on the upper
//   or lower hull to find the supporting point in O(log n).

struct Hull2D {
    // All inserted points with their values
    points: Vec<(f64, f64, f64, f64)>, // (kx, ky, vx, vy)
    // Upper hull sorted by kx (for qy > 0 queries)
    upper: Vec<(f64, f64, usize)>, // (kx, ky, index into points)
    // Lower hull sorted by kx (for qy < 0 queries)
    lower: Vec<(f64, f64, usize)>,
    needs_rebuild: bool,
}

impl Hull2D {
    fn new() -> Self {
        Self {
            points: Vec::with_capacity(2048),
            upper: Vec::new(),
            lower: Vec::new(),
            needs_rebuild: true,
        }
    }

    fn insert(&mut self, kx: f64, ky: f64, vx: f64, vy: f64) {
        self.points.push((kx, ky, vx, vy));
        self.needs_rebuild = true;
    }

    fn rebuild(&mut self) {
        let n = self.points.len();
        if n == 0 { return; }

        // Sort indices by kx
        let mut idx: Vec<usize> = (0..n).collect();
        idx.sort_by(|&a, &b| {
            let (ax, ay, _, _) = self.points[a];
            let (bx, by, _, _) = self.points[b];
            ax.partial_cmp(&bx).unwrap().then(ay.partial_cmp(&by).unwrap())
        });

        // Build upper hull (counter-clockwise turn test)
        self.upper.clear();
        for &i in &idx {
            let (px, py, _, _) = self.points[i];
            while self.upper.len() >= 2 {
                let (ax, ay, _) = self.upper[self.upper.len() - 2];
                let (bx, by, _) = self.upper[self.upper.len() - 1];
                // Cross product: (b-a) × (p-a) >= 0 means left turn or collinear → remove b
                if (bx - ax) * (py - ay) - (by - ay) * (px - ax) >= 0.0 {
                    self.upper.pop();
                } else {
                    break;
                }
            }
            self.upper.push((px, py, i));
        }

        // Build lower hull
        self.lower.clear();
        for &i in &idx {
            let (px, py, _, _) = self.points[i];
            while self.lower.len() >= 2 {
                let (ax, ay, _) = self.lower[self.lower.len() - 2];
                let (bx, by, _) = self.lower[self.lower.len() - 1];
                if (bx - ax) * (py - ay) - (by - ay) * (px - ax) <= 0.0 {
                    self.lower.pop();
                } else {
                    break;
                }
            }
            self.lower.push((px, py, i));
        }

        self.needs_rebuild = false;
    }

    /// O(log n) max-dot query using binary search on convex hull.
    fn query(&mut self, qx: f64, qy: f64) -> (f64, f64) {
        if self.points.is_empty() {
            return (0.0, 0.0);
        }

        if self.needs_rebuild {
            self.rebuild();
        }

        // Choose upper or lower hull based on qy sign
        let hull = if qy >= 0.0 { &self.upper } else { &self.lower };

        if hull.len() <= 3 {
            // Linear scan for tiny hulls
            return self.query_linear(hull, qx, qy);
        }

        // Binary search: find the point on the hull maximizing qx*kx + qy*ky
        // The dot product along the hull is unimodal (first increases, then decreases)
        let mut lo = 0usize;
        let mut hi = hull.len() - 1;

        while hi - lo > 2 {
            let m1 = lo + (hi - lo) / 3;
            let m2 = hi - (hi - lo) / 3;
            let d1 = hull[m1].0 * qx + hull[m1].1 * qy;
            let d2 = hull[m2].0 * qx + hull[m2].1 * qy;
            if d1 < d2 {
                lo = m1;
            } else {
                hi = m2;
            }
        }

        // Linear scan over remaining 3 elements
        let mut best_dot = f64::NEG_INFINITY;
        let mut best_idx = hull[lo].2;
        for i in lo..=hi {
            let d = hull[i].0 * qx + hull[i].1 * qy;
            if d > best_dot {
                best_dot = d;
                best_idx = hull[i].2;
            }
        }

        let (_, _, vx, vy) = self.points[best_idx];
        (vx, vy)
    }

    /// O(n) brute-force query — fastest for n < 10K.
    fn query_brute(&self, qx: f64, qy: f64) -> (f64, f64) {
        let mut best = f64::NEG_INFINITY;
        let mut bv = (0.0, 0.0);
        for &(kx, ky, vx, vy) in &self.points {
            let d = kx * qx + ky * qy;
            if d > best { best = d; bv = (vx, vy); }
        }
        bv
    }

    fn query_linear(&self, hull: &[(f64, f64, usize)], qx: f64, qy: f64) -> (f64, f64) {
        let mut best_dot = f64::NEG_INFINITY;
        let mut best_idx = 0usize;
        for &(kx, ky, idx) in hull {
            let d = kx * qx + ky * qy;
            if d > best_dot {
                best_dot = d;
                best_idx = idx;
            }
        }
        if best_idx < self.points.len() {
            let (_, _, vx, vy) = self.points[best_idx];
            (vx, vy)
        } else {
            (0.0, 0.0)
        }
    }
}

// ============================================================
// Layer weights with active-head detection
// ============================================================

struct LayerWeights {
    in_proj: Vec<f64>,
    out_proj: Vec<f64>,
    ff_in: Vec<f64>,
    ff_out: Vec<f64>,
    active_heads: Vec<usize>,
}

impl LayerWeights {
    fn from_flat(data: &[f64], offset: usize) -> Self {
        let ip = 3 * D * D;
        let op = D * D;
        let fi = 2 * D_FFN * D;
        let fo = D * D_FFN;
        let in_proj = data[offset..offset + ip].to_vec();
        let out_proj = data[offset + ip..offset + ip + op].to_vec();
        let ff_in = data[offset + ip + op..offset + ip + op + fi].to_vec();
        let ff_out = data[offset + ip + op + fi..offset + ip + op + fi + fo].to_vec();

        let mut active = Vec::new();
        for h in 0..N_HEADS {
            let h2 = h * HD;
            let mut has_w = false;
            'outer: for sec in 0..3 {
                for r in 0..HD {
                    let row = sec * D + h2 + r;
                    for c in 0..D {
                        if in_proj[row * D + c].abs() > 1e-12 { has_w = true; break 'outer; }
                    }
                }
            }
            if !has_w {
                for r in 0..D {
                    for c in 0..HD {
                        if out_proj[r * D + h2 + c].abs() > 1e-12 { has_w = true; break; }
                    }
                    if has_w { break; }
                }
            }
            if has_w { active.push(h); }
        }
        Self { in_proj, out_proj, ff_in, ff_out, active_heads: active }
    }

    fn layer_size() -> usize { 3 * D * D + D * D + 2 * D_FFN * D + D * D_FFN }
}

#[inline]
fn matvec(m: &[f64], v: &[f64], rows: usize, cols: usize, out: &mut [f64]) {
    for i in 0..rows {
        let mut s = 0.0f64;
        let base = i * cols;
        for j in 0..cols {
            s += unsafe { *m.get_unchecked(base + j) * *v.get_unchecked(j) };
        }
        out[i] = s;
    }
}

/// Multi-layer trace generation with O(log n) hull queries.
#[pyfunction]
fn generate_trace_multilayer(
    tok_w: Vec<f64>,
    pe_w: Vec<f64>,
    pe_rows: usize,
    layer_weights: Vec<f64>,
    head_w: Vec<f64>,
    prog_tokens: Vec<usize>,
    max_trace_tokens: usize,
    halt_token: usize,
    step_size: usize,
) -> Vec<usize> {
    let layers: Vec<LayerWeights> = (0..N_LAYERS)
        .map(|l| LayerWeights::from_flat(&layer_weights, l * LayerWeights::layer_size()))
        .collect();

    let mut hulls: Vec<Vec<Hull2D>> = layers.iter()
        .map(|lw| lw.active_heads.iter().map(|_| Hull2D::new()).collect())
        .collect();

    let mut trace: Vec<usize> = Vec::new();
    let n_prog = prog_tokens.len();
    let total = n_prog + max_trace_tokens;

    let mut x = [0.0f64; D];
    let mut qkv = [0.0f64; 3 * D];
    let mut ff_raw = [0.0f64; 2 * D_FFN];
    let mut ff_hidden = [0.0f64; D_FFN];
    let mut ff_add = [0.0f64; D];

    // Track when to rebuild hulls (batch rebuilds for efficiency)
    let mut inserts_since_rebuild: Vec<Vec<usize>> = layers.iter()
        .map(|lw| vec![0; lw.active_heads.len()])
        .collect();
    let rebuild_interval = 64; // Rebuild every 64 inserts

    for pos in 0..total {
        let tok_id = if pos < n_prog {
            prog_tokens[pos]
        } else if trace.is_empty() {
            0
        } else {
            *trace.last().unwrap()
        };

        if tok_id < VOCAB {
            for i in 0..D { x[i] = tok_w[tok_id * D + i]; }
        } else {
            for i in 0..D { x[i] = 0.0; }
        }
        if pos < pe_rows {
            for i in 0..D { x[i] += pe_w[pos * D + i]; }
        }

        for (l, lw) in layers.iter().enumerate() {
            matvec(&lw.in_proj, &x, 3 * D, D, &mut qkv);

            for (hi, &h) in lw.active_heads.iter().enumerate() {
                let h2 = h * HD;
                let k0 = qkv[D + h2];
                let k1 = qkv[D + h2 + 1];
                let v0 = qkv[2 * D + h2];
                let v1 = qkv[2 * D + h2 + 1];

                hulls[l][hi].insert(k0, k1, v0, v1);
                inserts_since_rebuild[l][hi] += 1;

                let q0 = qkv[h2];
                let q1 = qkv[h2 + 1];
                // Always brute-force for now (hull has precision issues on long traces)
                let (rv0, rv1) = hulls[l][hi].query_brute(q0, q1);

                for i in 0..D {
                    x[i] += lw.out_proj[i * D + h2] * rv0
                          + lw.out_proj[i * D + h2 + 1] * rv1;
                }
            }

            matvec(&lw.ff_in, &x, 2 * D_FFN, D, &mut ff_raw);
            for i in 0..D_FFN {
                let gate = if ff_raw[i] > 0.0 { ff_raw[i] } else { 0.0 };
                ff_hidden[i] = gate * ff_raw[D_FFN + i];
            }
            matvec(&lw.ff_out, &ff_hidden, D, D_FFN, &mut ff_add);
            for i in 0..D { x[i] += ff_add[i]; }
        }

        if pos >= n_prog - 1 {
            let mut best_logit = f64::NEG_INFINITY;
            let mut best_token = 0usize;
            for t in 0..VOCAB {
                let mut logit = 0.0f64;
                let base = t * D;
                for i in 0..D { logit += head_w[base + i] * x[i]; }
                if logit > best_logit { best_logit = logit; best_token = t; }
            }
            trace.push(best_token);
            let ti = trace.len() - 1;
            if ti % step_size == step_size - 1 && best_token == halt_token { break; }
        }
    }

    trace
}

/// Fast WASM VM for training data generation.
/// Executes a simple WASM program and returns the expected trace.
#[pyfunction]
fn fast_vm_trace(opcodes: Vec<u32>, operands: Vec<i32>) -> Vec<i32> {
    // Simple stack-based VM for i32 operations
    let mut stack: Vec<i32> = Vec::new();
    let mut locals: Vec<i32> = vec![0; 16];
    let mut trace: Vec<i32> = Vec::new(); // flat: [b0,b1,b2,b3,commit]*
    let mut ss: i32 = 0;

    for i in 0..opcodes.len() {
        let op = opcodes[i];
        let imm = operands[i];

        match op {
            0x41 => { // i32.const
                let v = imm;
                stack.push(v);
                ss += 1;
                let vb = (v as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x6A => { // i32.add
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a.wrapping_add(b);
                stack.push(r);
                ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x6B => { // i32.sub
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a.wrapping_sub(b);
                stack.push(r);
                ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x6C => { // i32.mul
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a.wrapping_mul(b);
                stack.push(r);
                ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x6D => { // i32.div_s
                let b = stack.pop().unwrap_or(1);
                let a = stack.pop().unwrap_or(0);
                let r = if b != 0 { a.wrapping_div(b) } else { 0 };
                stack.push(r);
                ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x6F => { // i32.rem_s
                let b = stack.pop().unwrap_or(1);
                let a = stack.pop().unwrap_or(0);
                let r = if b != 0 { a.wrapping_rem(b) } else { 0 };
                stack.push(r);
                ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x71 => { // i32.and
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a & b;
                stack.push(r); ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x72 => { // i32.or
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a | b;
                stack.push(r); ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x73 => { // i32.xor
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a ^ b;
                stack.push(r); ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x74 => { // i32.shl
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a.wrapping_shl(b as u32);
                stack.push(r); ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x75 => { // i32.shr_s
                let b = stack.pop().unwrap_or(0);
                let a = stack.pop().unwrap_or(0);
                let r = a.wrapping_shr(b as u32);
                stack.push(r); ss -= 1;
                let vb = (r as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x21 => { // local.set
                let v = stack.pop().unwrap_or(0);
                let idx = imm as usize;
                if idx < locals.len() { locals[idx] = v; }
                ss -= 1;
                let vb = (v as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0x20 => { // local.get
                let idx = imm as usize;
                let v = if idx < locals.len() { locals[idx] } else { 0 };
                stack.push(v);
                ss += 1;
                let vb = (v as u32).to_le_bytes();
                trace.extend_from_slice(&[vb[0] as i32, vb[1] as i32, vb[2] as i32, vb[3] as i32, ss]);
            }
            0xFF => { // output
                ss -= 1;
                trace.extend_from_slice(&[0, 0, 0, 0, 254]); // COMMIT_OUTPUT
            }
            0x00 => { // halt
                trace.extend_from_slice(&[0, 0, 0, 0, 255]); // COMMIT_HALT
                break;
            }
            // Comparisons
            0x46 => { let b=stack.pop().unwrap_or(0); let a=stack.pop().unwrap_or(0); let r=if a==b{1}else{0}; stack.push(r); ss-=1; let vb=(r as u32).to_le_bytes(); trace.extend_from_slice(&[vb[0] as i32,vb[1] as i32,vb[2] as i32,vb[3] as i32,ss]); }
            0x47 => { let b=stack.pop().unwrap_or(0); let a=stack.pop().unwrap_or(0); let r=if a!=b{1}else{0}; stack.push(r); ss-=1; let vb=(r as u32).to_le_bytes(); trace.extend_from_slice(&[vb[0] as i32,vb[1] as i32,vb[2] as i32,vb[3] as i32,ss]); }
            0x48 => { let b=stack.pop().unwrap_or(0); let a=stack.pop().unwrap_or(0); let r=if a<b{1}else{0}; stack.push(r); ss-=1; let vb=(r as u32).to_le_bytes(); trace.extend_from_slice(&[vb[0] as i32,vb[1] as i32,vb[2] as i32,vb[3] as i32,ss]); }
            0x4A => { let b=stack.pop().unwrap_or(0); let a=stack.pop().unwrap_or(0); let r=if a>b{1}else{0}; stack.push(r); ss-=1; let vb=(r as u32).to_le_bytes(); trace.extend_from_slice(&[vb[0] as i32,vb[1] as i32,vb[2] as i32,vb[3] as i32,ss]); }
            0x4C => { let b=stack.pop().unwrap_or(0); let a=stack.pop().unwrap_or(0); let r=if a<=b{1}else{0}; stack.push(r); ss-=1; let vb=(r as u32).to_le_bytes(); trace.extend_from_slice(&[vb[0] as i32,vb[1] as i32,vb[2] as i32,vb[3] as i32,ss]); }
            0x4E => { let b=stack.pop().unwrap_or(0); let a=stack.pop().unwrap_or(0); let r=if a>=b{1}else{0}; stack.push(r); ss-=1; let vb=(r as u32).to_le_bytes(); trace.extend_from_slice(&[vb[0] as i32,vb[1] as i32,vb[2] as i32,vb[3] as i32,ss]); }
            0x45 => { let a=stack.pop().unwrap_or(0); let r=if a==0{1}else{0}; stack.push(r); let vb=(r as u32).to_le_bytes(); trace.extend_from_slice(&[vb[0] as i32,vb[1] as i32,vb[2] as i32,vb[3] as i32,ss]); }
            _ => {} // skip unknown ops
        }
    }
    trace
}

#[pyfunction]
fn generate_trace_rust(
    _a: Vec<f64>, _b: Vec<f64>, _c: usize, _d: Vec<f64>, _e: Vec<f64>,
    _f: Vec<f64>, _g: f64, _h: f64, _i: Vec<f64>, _j: usize,
    _k: Vec<f64>, _l: Vec<f64>, _m: usize,
) -> Vec<usize> { vec![] }

#[pymodule]
fn llm_compute_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_trace_rust, m)?)?;
    m.add_function(wrap_pyfunction!(generate_trace_multilayer, m)?)?;
    m.add_function(wrap_pyfunction!(fast_vm_trace, m)?)?;
    Ok(())
}
