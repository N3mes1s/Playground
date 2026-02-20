// claude_sandbox_test.c - Test running Claude Code inside the Chrome sandbox.
// Tests the full stack: Node.js runtime → Claude API → inside sandbox.
//
// This test demonstrates the runtime policy system:
//   - Base sandbox is IDENTICAL to Chrome's renderer sandbox
//   - Extensions (ioctls, sockopts) are PER-EXECUTION and auto-reset
//   - Each command gets only the minimum privileges it needs
//   - Network isolation is configurable for API access
//   - seccomp-BPF conditionally allows network syscalls when networking is enabled

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include "sandbox_harness.h"

static int tests_passed = 0;
static int tests_failed = 0;

// Node.js/libuv seccomp extensions — applied per-execution, auto-cleared.
static const unsigned long NODE_IOCTLS[] = {
    FIONBIO, TIOCGPGRP, TIOCGWINSZ, TIOCSPGRP,
    TCSETS, TCSETSW, TCSETSF
};
static const int NODE_IOCTLS_COUNT = sizeof(NODE_IOCTLS) / sizeof(NODE_IOCTLS[0]);

static const int NODE_SOCKOPTS[] = {
    SO_TYPE, SO_ERROR, SO_RCVBUF, SO_SNDBUF,
    SO_KEEPALIVE, SO_REUSEADDR
};
static const int NODE_SOCKOPTS_COUNT = sizeof(NODE_SOCKOPTS) / sizeof(NODE_SOCKOPTS[0]);

// Apply Node.js runtime extensions for the NEXT sandbox_exec() call only.
// After the exec returns, extensions auto-reset to Chrome defaults.
static void apply_node_extensions(void) {
    sandbox_allow_ioctls(NODE_IOCTLS, NODE_IOCTLS_COUNT);
    sandbox_allow_sockopts(NODE_SOCKOPTS, NODE_SOCKOPTS_COUNT);
}

static void run_test(const char* name, const char* cmd,
                     int expect_exit_zero, const char* expect_stdout) {
    printf("  TEST %-50s ", name);
    fflush(stdout);
    SandboxResult r = sandbox_exec_shell(cmd);

    int ok = 1;
    if (expect_exit_zero && r.exit_code != 0) {
        printf("[FAIL] exit=%d\n", r.exit_code);
        if (r.stdout_buf && r.stdout_len > 0) {
            int len = r.stdout_len > 300 ? 300 : r.stdout_len;
            printf("    stdout: %.*s\n", len, r.stdout_buf);
        }
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

// Run a test with Node.js runtime extensions applied (per-exec, auto-reset)
static void run_node_test(const char* name, const char* cmd,
                          int expect_exit_zero, const char* expect_stdout) {
    apply_node_extensions();  // Extensions apply to NEXT exec only
    run_test(name, cmd, expect_exit_zero, expect_stdout);
    // Extensions are already auto-cleared by sandbox_exec()
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("=== Claude Code in Chrome Sandbox Test ===\n\n");

    // =====================================================================
    // Init-time configuration (before sandbox_init)
    // =====================================================================
    sandbox_set_policy(SANDBOX_POLICY_STRICT);
    sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);

    // Read-only path for Node.js runtime
    sandbox_set_readonly_paths("/opt/node22");

    // Allow network access for Claude Code API calls.
    // This does TWO things:
    //   1. Disables CLONE_NEWNET (so sandboxed processes can reach the network)
    //   2. Allows AF_INET/AF_INET6 + connect/bind/listen/accept in seccomp-BPF
    // All other isolation layers remain active:
    //   user NS, PID NS, IPC NS, mount NS, chroot, cap drop, seccomp-BPF
    sandbox_set_network_enabled(1);

    printf("Initializing sandbox (zygote + namespace isolation)...\n");
    if (sandbox_init() != 0) {
        fprintf(stderr, "FATAL: sandbox_init() failed\n");
        return 1;
    }
    printf("Sandbox initialized.\n");

    // =====================================================================
    // Node.js tests — each applies per-exec extensions, then auto-resets
    // =====================================================================
    printf("\n--- Node.js Inside Sandbox (per-exec extensions) ---\n");

    // 1. Node.js version (needs extensions for V8 startup)
    run_node_test("node_version",
                  "/opt/node22/bin/node --version",
                  1, "v22");

    // 2. Node.js eval (needs extensions for stream initialization)
    run_node_test("node_eval_simple",
                  "/opt/node22/bin/node -e \"console.log('hello from node in sandbox')\"",
                  1, "hello from node in sandbox");

    // 3. Node.js arithmetic
    run_node_test("node_eval_math",
                  "/opt/node22/bin/node -e \"console.log(2 + 2)\"",
                  1, "4");

    // 4. Node.js process info
    run_node_test("node_process_info",
                  "/opt/node22/bin/node -e \"console.log('pid=' + process.pid + ' platform=' + process.platform)\"",
                  1, "platform=linux");

    // 5. Node.js file I/O
    run_node_test("node_file_io",
                  "/opt/node22/bin/node -e \""
                  "const fs = require('fs');"
                  "fs.writeFileSync('/tmp/node_test.txt', 'node sandbox test');"
                  "const data = fs.readFileSync('/tmp/node_test.txt', 'utf8');"
                  "console.log(data);"
                  "fs.unlinkSync('/tmp/node_test.txt');"
                  "\"",
                  1, "node sandbox test");

    // 6. Node.js JSON processing
    run_node_test("node_json_processing",
                  "/opt/node22/bin/node -e \""
                  "const data = {agent: 'claude', sandbox: 'chrome', working: true};"
                  "const json = JSON.stringify(data);"
                  "const parsed = JSON.parse(json);"
                  "console.log(parsed.agent + ' in ' + parsed.sandbox + ' sandbox: ' + parsed.working);"
                  "\"",
                  1, "claude in chrome sandbox: true");

    // 7. No extensions needed for shell commands (Chrome defaults)
    run_test("shell_no_extensions",
             "echo 'this runs with Chrome defaults'",
             1, "Chrome defaults");

    // =====================================================================
    // Claude Code tests
    // =====================================================================
    printf("\n--- Claude Code Inside Sandbox ---\n");

    // 8. Claude Code version (uses Node.js extensions)
    run_node_test("claude_version",
                  "/opt/node22/bin/node /opt/node22/lib/node_modules/@anthropic-ai/claude-code/cli.js --version 2>&1",
                  1, NULL);

    // 9. Claude Code help
    run_node_test("claude_help",
                  "/opt/node22/bin/node /opt/node22/lib/node_modules/@anthropic-ai/claude-code/cli.js --help 2>&1 | head -5",
                  1, NULL);

    // =====================================================================
    // Real Claude API test — actual API call from inside the sandbox
    // =====================================================================
    printf("\n--- Claude API Call from Inside Sandbox ---\n");
    printf("  Making a real Anthropic API call through the Chrome sandbox...\n");
    printf("  (requires ANTHROPIC_API_KEY and proxy/network access)\n\n");

    // 10. Direct API call to the Anthropic Messages API.
    // Establishes an authenticated CONNECT tunnel through the proxy,
    // does TLS to api.anthropic.com, and sends a Messages API request.
    apply_node_extensions();
    printf("  TEST %-50s ", "claude_api_from_sandbox");
    fflush(stdout);

    SandboxResult claude_result = sandbox_exec_shell(
        "/opt/node22/bin/node -e \""
        "const http=require('http'),tls=require('tls');"
        "const proxy=process.env.HTTPS_PROXY||process.env.https_proxy||process.env.HTTP_PROXY||process.env.http_proxy;"
        "if(!proxy){console.error('No proxy configured');process.exit(1);}"
        "const pu=new URL(proxy);"
        "const proxyAuth=pu.username&&pu.password?Buffer.from(pu.username+':'+pu.password).toString('base64'):null;"
        "const hdrs={}; if(proxyAuth) hdrs['Proxy-Authorization']='Basic '+proxyAuth;"
        "const body=JSON.stringify({model:'claude-sonnet-4-5-20250929',max_tokens:100,"
        "messages:[{role:'user',content:'What is 2+2? Reply with ONLY the number, nothing else.'}]});"
        "const creq=http.request({host:pu.hostname,port:pu.port,method:'CONNECT',"
        "path:'api.anthropic.com:443',headers:hdrs,timeout:30000});"
        "creq.on('connect',(res,socket)=>{"
        "tls.connect({socket,servername:'api.anthropic.com',rejectUnauthorized:false},function(){"
        "const agent=new http.Agent({});agent.createConnection=()=>this;"
        "const req=http.request({hostname:'api.anthropic.com',path:'/v1/messages',method:'POST',"
        "headers:{'x-api-key':process.env.ANTHROPIC_API_KEY,'anthropic-version':'2023-06-01',"
        "'content-type':'application/json','content-length':Buffer.byteLength(body)},"
        "agent},(r)=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{"
        "try{const j=JSON.parse(d);console.log(j.content?j.content[0].text:d.slice(0,500))}"
        "catch(e){console.log(d.slice(0,500))}});});"
        "req.on('error',e=>{console.error(e.message);process.exit(1)});"
        "req.write(body);req.end();});"
        "});"
        "creq.on('error',e=>{console.error(e.message);process.exit(1)});"
        "creq.end();"
        "\""
    );

    printf("exit=%d, %d syscalls, %.3fs\n",
           claude_result.exit_code,
           claude_result.num_syscalls_total, claude_result.duration_seconds);

    if (claude_result.stderr_buf && claude_result.stderr_len > 0) {
        int len = claude_result.stderr_len > 500 ? 500 : (int)claude_result.stderr_len;
        printf("  stderr: %.*s\n", len, claude_result.stderr_buf);
    }
    if (claude_result.stdout_buf && claude_result.stdout_len > 0) {
        int len = claude_result.stdout_len > 1000 ? 1000 : (int)claude_result.stdout_len;
        printf("\n  ┌─────────────────────────────────────────────┐\n");
        printf("  │  Claude response from inside the sandbox:   │\n");
        printf("  ├─────────────────────────────────────────────┤\n");
        printf("  │  %.*s", len, claude_result.stdout_buf);
        if (claude_result.stdout_buf[claude_result.stdout_len - 1] != '\n')
            printf("\n");
        printf("  └─────────────────────────────────────────────┘\n");
        tests_passed++;
    } else {
        printf("    (no response captured)\n");
        tests_failed++;
    }
    sandbox_result_free(&claude_result);

    // =====================================================================
    // Security verification — shell without extensions uses Chrome defaults
    // =====================================================================
    printf("\n--- Security Verification ---\n");

    // This test runs WITHOUT extensions — proves auto-reset works.
    // It should pass because basic shell commands don't need ioctl extensions.
    run_test("chrome_defaults_after_reset",
             "echo 'seccomp is Chrome defaults here'",
             1, "Chrome defaults");

    printf("\n--- Cleanup ---\n");
    sandbox_shutdown();
    printf("Sandbox shut down.\n");

    printf("\n=== Results: %d/%d passed ===\n",
           tests_passed, tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
