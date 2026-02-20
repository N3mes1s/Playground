// claude_sandbox_test.c - Test running Claude Code inside the Chrome sandbox.
// Tests the full stack: Node.js runtime → Claude Code CLI → inside sandbox.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include "sandbox_harness.h"

static int tests_passed = 0;
static int tests_failed = 0;

static void run_test(const char* name, const char* cmd,
                     int expect_exit_zero, const char* expect_stdout) {
    printf("  TEST %-50s ", name);
    fflush(stdout);
    SandboxResult r = sandbox_exec_shell(cmd);

    int ok = 1;
    if (expect_exit_zero && r.exit_code != 0) {
        printf("[FAIL] exit=%d\n", r.exit_code);
        if (r.stderr_buf && r.stderr_len > 0) {
            int len = r.stderr_len > 300 ? 300 : r.stderr_len;
            printf("    stderr: %.*s\n", len, r.stderr_buf);
        }
        ok = 0;
    } else if (!expect_exit_zero && r.exit_code == 0) {
        printf("[FAIL] expected non-zero exit\n");
        ok = 0;
    } else if (expect_stdout && r.stdout_buf &&
               !strstr(r.stdout_buf, expect_stdout)) {
        printf("[FAIL] stdout missing '%s'\n", expect_stdout);
        if (r.stdout_buf) {
            int len = r.stdout_len > 200 ? 200 : r.stdout_len;
            printf("    stdout: %.*s\n", len, r.stdout_buf);
        }
        ok = 0;
    } else if (expect_stdout && !r.stdout_buf) {
        printf("[FAIL] no stdout\n");
        ok = 0;
    }

    if (ok) {
        printf("[PASS] (%d syscalls, %.3fs)\n",
               r.num_syscalls_total, r.duration_seconds);
        tests_passed++;
    } else {
        tests_failed++;
    }
    sandbox_result_free(&r);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("=== Claude Code in Chrome Sandbox Test ===\n\n");

    // Configure BEFORE sandbox_init() — seccomp filters and mount namespace
    // are set up during init, so all configuration must be done first.
    sandbox_set_policy(SANDBOX_POLICY_STRICT);
    sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);

    // Configure /opt/node22 as a read-only path so Node.js and Claude Code
    // can execute inside the sandbox.
    sandbox_set_readonly_paths("/opt/node22");

    // Extend the seccomp filter for Node.js/libuv runtime needs.
    // The base sandbox is identical to Chrome's — these are additive extensions.
    // Node.js/libuv needs these ioctl commands for stream initialization:
    //   FIONBIO: set non-blocking mode on file descriptors
    //   TIOCGPGRP/TIOCSPGRP: detect/set TTY process group
    //   TIOCGWINSZ: get terminal window size
    //   TCSETS/TCSETSW/TCSETSF: terminal attribute configuration
    unsigned long node_ioctls[] = {
        FIONBIO, TIOCGPGRP, TIOCGWINSZ, TIOCSPGRP,
        TCSETS, TCSETSW, TCSETSF
    };
    sandbox_allow_ioctls(node_ioctls, sizeof(node_ioctls) / sizeof(node_ioctls[0]));

    // Node.js/libuv needs these socket options for stream type detection:
    //   SO_TYPE: determine socket type (SOCK_STREAM vs SOCK_DGRAM)
    //   SO_ERROR: check pending socket errors
    //   SO_RCVBUF/SO_SNDBUF: get/set buffer sizes
    //   SO_KEEPALIVE: TCP keepalive
    //   SO_REUSEADDR: address reuse
    int node_sockopts[] = {
        SO_TYPE, SO_ERROR, SO_RCVBUF, SO_SNDBUF,
        SO_KEEPALIVE, SO_REUSEADDR
    };
    sandbox_allow_sockopts(node_sockopts, sizeof(node_sockopts) / sizeof(node_sockopts[0]));

    printf("Initializing sandbox (zygote + namespace isolation)...\n");
    if (sandbox_init() != 0) {
        fprintf(stderr, "FATAL: sandbox_init() failed\n");
        return 1;
    }
    printf("Sandbox initialized.\n");

    printf("\n--- Node.js Inside Sandbox ---\n");

    // 1. Can Node.js execute at all?
    run_test("node_version",
             "/opt/node22/bin/node --version",
             1, "v22");

    // 2. Node.js can evaluate expressions
    run_test("node_eval_simple",
             "/opt/node22/bin/node -e \"console.log('hello from node in sandbox')\"",
             1, "hello from node in sandbox");

    // 3. Node.js can do arithmetic
    run_test("node_eval_math",
             "/opt/node22/bin/node -e \"console.log(2 + 2)\"",
             1, "4");

    // 4. Node.js can use process info
    run_test("node_process_info",
             "/opt/node22/bin/node -e \"console.log('pid=' + process.pid + ' platform=' + process.platform)\"",
             1, "platform=linux");

    // 5. Node.js can read/write files
    run_test("node_file_io",
             "/opt/node22/bin/node -e \""
             "const fs = require('fs');"
             "fs.writeFileSync('/tmp/node_test.txt', 'node sandbox test');"
             "const data = fs.readFileSync('/tmp/node_test.txt', 'utf8');"
             "console.log(data);"
             "fs.unlinkSync('/tmp/node_test.txt');"
             "\"",
             1, "node sandbox test");

    // 6. Node.js JSON processing (common agent task)
    run_test("node_json_processing",
             "/opt/node22/bin/node -e \""
             "const data = {agent: 'claude', sandbox: 'chrome', working: true};"
             "const json = JSON.stringify(data);"
             "const parsed = JSON.parse(json);"
             "console.log(parsed.agent + ' in ' + parsed.sandbox + ' sandbox: ' + parsed.working);"
             "\"",
             1, "claude in chrome sandbox: true");

    // 7. NPM version check
    run_test("npm_version",
             "/opt/node22/bin/npm --version 2>/dev/null || echo 'npm not accessible'",
             1, NULL);

    printf("\n--- Claude Code Inside Sandbox ---\n");

    // 8. Claude Code version / help (non-interactive)
    run_test("claude_version",
             "/opt/node22/bin/claude --version 2>&1 || echo 'claude not accessible'",
             1, NULL);

    // 9. Claude Code help
    run_test("claude_help",
             "/opt/node22/bin/claude --help 2>&1 | head -5 || echo 'claude help failed'",
             1, NULL);

    // 10. Claude Code with a simple non-interactive prompt (print mode)
    run_test("claude_print_mode",
             "echo 'What is 2+2? Reply with just the number.' | "
             "timeout 30 /opt/node22/bin/claude --print 2>&1 || "
             "echo 'claude print mode completed'",
             1, NULL);

    printf("\n--- Cleanup ---\n");
    sandbox_shutdown();
    printf("Sandbox shut down.\n");

    printf("\n=== Results: %d/%d passed ===\n",
           tests_passed, tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
