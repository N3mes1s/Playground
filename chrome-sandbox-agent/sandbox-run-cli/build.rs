use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let extracted = PathBuf::from(&manifest_dir).join("../extracted");
    let build_dir = extracted.join("build");

    // Step 1: Ensure cmake has built the static libraries
    if !build_dir.join("libsandbox_bpf_dsl.a").exists() {
        eprintln!("=== Building Chrome sandbox C++ libraries via cmake ===");
        let _ = std::fs::create_dir_all(&build_dir);
        let status = Command::new("cmake")
            .current_dir(&build_dir)
            .arg("..")
            .status()
            .expect("cmake not found - install cmake");
        assert!(status.success(), "cmake failed");

        let status = Command::new("make")
            .current_dir(&build_dir)
            .arg("-j")
            .arg(num_cpus())
            .status()
            .expect("make not found");
        assert!(status.success(), "make failed");
    }

    // Step 2: Compile sandbox_harness.cc into a static archive using cc crate
    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .file(extracted.join("harness/sandbox_harness.cc"))
        .include(&extracted)
        .include(extracted.join("base_shims"))
        .include(extracted.join("build_config"))
        .flag("-include")
        .flag(
            extracted
                .join("base_shims/standalone_compat.h")
                .to_str()
                .unwrap(),
        )
        .define("COMPONENT_BUILD", "0")
        .define("OS_LINUX", "1")
        .define("OS_POSIX", "1")
        .warnings(false)
        .compile("sandbox_harness");

    // Step 3: Link the cmake-built static archives
    // Order: dependents before dependencies
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=sandbox_syscall_broker");
    println!("cargo:rustc-link-lib=static=sandbox_services");
    println!("cargo:rustc-link-lib=static=sandbox_seccomp_helpers");
    println!("cargo:rustc-link-lib=static=sandbox_seccomp_bpf");
    println!("cargo:rustc-link-lib=static=sandbox_bpf_dsl");

    // Step 4: System libraries
    println!("cargo:rustc-link-lib=cap");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=pthread");

    // Rebuild triggers
    println!("cargo:rerun-if-changed=../extracted/harness/sandbox_harness.cc");
    println!("cargo:rerun-if-changed=../extracted/harness/sandbox_harness.h");
}

fn num_cpus() -> String {
    std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|_| "2".to_string())
}
