//! Hello-world parity tests across all (os, arch) combos we care about.
//!
//! These exist to sniff out loader / ISA / OS-surface gaps. Each test loads a
//! tiny C `printf("hello world")` binary built by `examples/hello-world/Makefile`,
//! takes a bounded number of steps, and asserts the loader picked the right
//! arch. Tests for combos the emulator does not yet support are `#[ignore]`d
//! with a comment pointing at the gap so future work can flip them on.
//!
//! Source: examples/hello-world/main.c
//! Build:  make -C examples/hello-world all  (then move into tests/fixtures/)

use crate::tests::helpers;
use crate::*;

const HELLO_LINUX_X86: &[u8] = include_bytes!("../fixtures/hello_linux_x86");
const HELLO_LINUX_X64: &[u8] = include_bytes!("../fixtures/hello_linux_x64");
const HELLO_LINUX_ARM64: &[u8] = include_bytes!("../fixtures/hello_linux_arm64");
const HELLO_MAC_ARM64: &[u8] = include_bytes!("../fixtures/hello_mac_arm64");
const HELLO_MAC_X64: &[u8] = include_bytes!("../fixtures/hello_mac_x64");
const HELLO_WIN_X86: &[u8] = include_bytes!("../fixtures/hello_win_x86.exe");
const HELLO_WIN_X64: &[u8] = include_bytes!("../fixtures/hello_win_x64.exe");
const HELLO_WIN_ARM64: &[u8] = include_bytes!("../fixtures/hello_win_arm64.exe");

const MAX_STEPS: usize = 64;

fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// PARITY GAP: panics in crates/libmwemu/src/maps/mem64.rs:576 with
/// `FAILED to write without permission: addr: 0x0` early in dynamic
/// ELF32 startup. Un-ignore once ELF32 hello-world steps without
/// dereferencing a null pointer.
#[test]
#[ignore = "parity gap: mem64.rs:576 null write on dynamic ELF32 startup"]
fn hello_linux_x86() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_linux_x86", HELLO_LINUX_X86);

    let mut emu = emu32();
    emu.load_code(path.to_str().unwrap());

    assert!(
        matches!(emu.cfg.arch, crate::arch::Arch::X86),
        "expected ELF32 x86 dispatch, got {:?}",
        emu.cfg.arch
    );
    let entry = emu.regs().rip;
    assert!(entry != 0, "entry point should be set");

    for _ in 0..MAX_STEPS {
        if !emu.step() {
            break;
        }
    }
}

/// PARITY GAP: panics in
/// crates/libmwemu/src/engine/instructions/call.rs:41 with
/// `attempt to subtract with overflow` while stepping a glibc-dynamic
/// `printf("hello world")`. Also logs `elf64.strtab overlappss` from
/// the loader. Un-ignore once dynamic ELF64 x86_64 startup runs cleanly.
#[test]
#[ignore = "parity gap: call.rs:41 sub overflow on dynamic ELF64 x86_64"]
fn hello_linux_x64() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_linux_x64", HELLO_LINUX_X64);

    let mut emu = emu64();
    emu.load_code(path.to_str().unwrap());

    assert!(emu.cfg.arch.is_x64(), "expected ELF64 x86_64 dispatch");
    let entry = emu.regs().rip;
    assert!(entry != 0, "entry point should be set");

    for _ in 0..MAX_STEPS {
        if !emu.step() {
            break;
        }
    }
}

/// PARITY GAP: panics in crates/libmwemu/src/maps/mem64.rs:357 with
/// `FAILED to read without permission: addr: 0x555555554700` early in
/// dynamic ELF64 aarch64 startup. Loader also logs `elf64.strtab overlappss`.
/// Un-ignore once aarch64 dynamic-linker startup maps the right ranges.
#[test]
#[ignore = "parity gap: mem64.rs:357 perm denied on dynamic ELF64 aarch64"]
fn hello_linux_arm64() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_linux_arm64", HELLO_LINUX_ARM64);

    let mut emu = emu_aarch64();
    emu.load_code(path.to_str().unwrap());

    assert!(emu.cfg.arch.is_aarch64(), "expected ELF64 aarch64 dispatch");
    let pc = emu.regs_aarch64().pc;
    assert!(pc != 0, "pc should be set by loader");

    for _ in 0..MAX_STEPS {
        if !emu.step() {
            break;
        }
    }
}

#[test]
fn hello_mac_arm64() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_mac_arm64", HELLO_MAC_ARM64);

    let mut emu = emu_aarch64();
    emu.load_code(path.to_str().unwrap());

    assert!(emu.cfg.arch.is_aarch64(), "expected Mach-O aarch64 dispatch");
    let pc = emu.regs_aarch64().pc;
    assert!(pc >= 0x100000000, "entry 0x{:x} should be in __TEXT", pc);

    for _ in 0..MAX_STEPS {
        if !emu.step() {
            break;
        }
    }
}

/// PARITY GAP: there is no `Macho64::is_macho64_x64` branch in
/// crates/libmwemu/src/emu/loaders.rs — only the aarch64 path exists. A
/// Mach-O x86_64 binary currently falls through to the shellcode default and
/// gets garbage-decoded. Un-ignore once an x86_64 Mach-O loader path lands.
#[test]
#[ignore = "loader gap: no Mach-O x86_64 dispatch in load_code"]
fn hello_mac_x64() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_mac_x64", HELLO_MAC_X64);

    let mut emu = emu64();
    emu.load_code(path.to_str().unwrap());

    assert!(
        emu.cfg.arch.is_x64(),
        "expected Mach-O x86_64 dispatch, got {:?}",
        emu.cfg.arch
    );
}

/// PARITY GAP: panics in crates/libmwemu/src/maps/mod.rs:327
/// `incorrect memory map name` while loading a mingw-clang built PE32.
/// Un-ignore once PE32 hello-world loads without tripping the maps name check.
#[test]
#[ignore = "parity gap: maps/mod.rs:327 incorrect memory map name on PE32 mingw"]
fn hello_win_x86() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_win_x86.exe", HELLO_WIN_X86);

    let mut emu = emu32();
    emu.load_code(path.to_str().unwrap());

    assert!(
        matches!(emu.cfg.arch, crate::arch::Arch::X86),
        "expected PE32 x86 dispatch, got {:?}",
        emu.cfg.arch
    );
    let entry = emu.regs().rip;
    assert!(entry != 0, "entry point should be set");

    for _ in 0..MAX_STEPS {
        if !emu.step() {
            break;
        }
    }
}

/// PARITY GAP: panics in
/// crates/libmwemu/src/loaders/pe/pe64/parser.rs:127 with
/// `pe64 binary not found`. The PE64 loader re-opens the file by name
/// (`File::open(filename)`) inside `PE64::load`, which fails for the
/// temp-file path used by this test even though the path was just written.
/// Un-ignore once the loader works from already-read bytes or resolves paths
/// robustly.
#[test]
#[ignore = "parity gap: pe64 parser.rs:127 re-opens file by name and fails"]
fn hello_win_x64() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_win_x64.exe", HELLO_WIN_X64);

    let mut emu = emu64();
    emu.load_code(path.to_str().unwrap());

    assert!(emu.cfg.arch.is_x64(), "expected PE64 x86_64 dispatch");
    let entry = emu.regs().rip;
    assert!(entry != 0, "entry point should be set");

    for _ in 0..MAX_STEPS {
        if !emu.step() {
            break;
        }
    }
}

/// PARITY GAP: `PE64::is_pe64` does not differentiate by machine type, so an
/// ARM64 PE is currently mis-routed into the x86_64 PE loader and decoded as
/// x86_64. There is no aarch64 PE dispatch path in load_code. Un-ignore once
/// the loader recognizes IMAGE_FILE_MACHINE_ARM64 and routes to an aarch64
/// PE loader.
#[test]
#[ignore = "loader gap: no PE aarch64 dispatch in load_code"]
fn hello_win_arm64() {
    helpers::setup();
    let path = write_tmp("mwemu_hello_win_arm64.exe", HELLO_WIN_ARM64);

    let mut emu = emu_aarch64();
    emu.load_code(path.to_str().unwrap());

    assert!(
        emu.cfg.arch.is_aarch64(),
        "expected PE aarch64 dispatch, got {:?}",
        emu.cfg.arch
    );
}
