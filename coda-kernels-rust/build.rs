//! Build script: compiles the CUDA backend when the `cuda` feature is on.
//!
//! Without `--features cuda` this is a no-op, so the pure-CPU crate builds and
//! tests with no CUDA toolchain present. With the feature, it invokes `nvcc`
//! to compile `cuda/coda_kernels.cu` into a static library and links it
//! together with the CUDA runtime.

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=cuda/coda_kernels.cu");
    println!("cargo:rerun-if-changed=build.rs");

    if env::var("CARGO_FEATURE_CUDA").is_err() {
        return; // CPU-only build.
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let obj = format!("{out_dir}/coda_kernels.o");
    let lib = format!("{out_dir}/libcoda_cuda.a");

    // Locate nvcc: prefer PATH, fall back to the standard CUDA install path.
    let nvcc = ["nvcc", "/usr/local/cuda/bin/nvcc"].into_iter().find(|cand| {
        Command::new(cand)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    });
    let Some(nvcc) = nvcc else {
        // No CUDA toolkit: still let `cargo check --features cuda` type-check
        // the Rust side. A real link will fail with undefined `coda_cuda_*`
        // symbols until this runs on a machine with nvcc (e.g. the Modal GPU).
        println!(
            "cargo:warning=nvcc not found; CUDA kernels not compiled. \
             `cargo check` works; a full build needs the CUDA toolkit."
        );
        return;
    };

    // Compile the kernels to a relocatable object. compute_70 PTX is embedded,
    // so the driver JITs for any GPU of compute capability >= 7.0 (T4, A10,
    // A100, L4, H100, ...).
    let status = Command::new(nvcc)
        .args([
            "-O3",
            "-std=c++14",
            "-Xcompiler",
            "-fPIC",
            "-gencode",
            "arch=compute_70,code=compute_70",
            "-c",
            "cuda/coda_kernels.cu",
            "-o",
            &obj,
        ])
        .status()
        .expect("failed to spawn nvcc");
    assert!(status.success(), "nvcc failed to compile cuda/coda_kernels.cu");

    // Archive into a static library.
    let status = Command::new("ar")
        .args(["crs", &lib, &obj])
        .status()
        .expect("failed to spawn ar");
    assert!(status.success(), "ar failed to archive the CUDA object");

    // Link our static lib + the CUDA runtime + the C++ runtime.
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=coda_cuda");
    for dir in ["/usr/local/cuda/lib64", "/usr/local/cuda/lib"] {
        if Path::new(dir).exists() {
            println!("cargo:rustc-link-search=native={dir}");
        }
    }
    println!("cargo:rustc-link-lib=dylib=cudart");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
