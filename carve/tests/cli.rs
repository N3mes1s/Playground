//! End-to-end CLI tests: run the actual built `carve` binary and check behavior.
//! Uses CARGO_BIN_EXE_carve, the path Cargo provides to the compiled binary.

use std::process::Command;

fn carve() -> Command {
    Command::new(env!("CARGO_BIN_EXE_carve"))
}

#[test]
fn help_lists_the_core_subcommands() {
    let out = carve().arg("--help").output().expect("run carve --help");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for cmd in ["analyze", "vendor", "slice", "harden", "verify", "restore"] {
        assert!(text.contains(cmd), "--help missing `{cmd}`:\n{text}");
    }
}

#[test]
fn version_prints() {
    let out = carve()
        .arg("--version")
        .output()
        .expect("run carve --version");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("carve"));
}

#[test]
fn tools_lists_the_agent_surface() {
    let out = carve().arg("tools").output().expect("run carve tools");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for tool in ["cargo_check", "read_file", "parse_items"] {
        assert!(text.contains(tool), "tools missing `{tool}`:\n{text}");
    }
}

#[test]
fn unknown_subcommand_fails_cleanly() {
    let out = carve()
        .arg("definitely-not-a-command")
        .output()
        .expect("run carve");
    assert!(!out.status.success());
}
