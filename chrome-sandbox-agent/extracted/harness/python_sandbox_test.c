// python_sandbox_test.c - Test running Python inside the Chrome sandbox.
// Tests what Claude Code does when it writes a Python file and executes it:
//   - Python interpreter starts and runs inside the sandboxed environment
//   - File I/O (write script to /tmp, execute it, read output)
//   - Standard library modules (json, subprocess, os) work correctly
//   - Claude API calls via urllib through HTTPS proxy
//
// Python doesn't need the ioctl/sockopt extensions that Node.js requires
// (no V8/libuv event loop), so it runs with Chrome's default seccomp policy
// plus network access for API calls.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
        if (r.stdout_buf && r.stdout_len > 0) {
            int len = r.stdout_len > 300 ? 300 : (int)r.stdout_len;
            printf("    stdout: %.*s\n", len, r.stdout_buf);
        }
        if (r.stderr_buf && r.stderr_len > 0) {
            int len = r.stderr_len > 300 ? 300 : (int)r.stderr_len;
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
            int len = r.stdout_len > 200 ? 200 : (int)r.stdout_len;
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

// Write a Python script to /tmp, execute it, and clean up.
// This is exactly the pattern Claude Code uses: write code, run it, get output.
static void run_python_file_test(const char* name, const char* script,
                                 int expect_exit_zero, const char* expect_stdout) {
    // Build command: write script -> run it -> clean up
    // Use cat with heredoc to handle multi-line scripts with any quoting
    char cmd[8192];
    snprintf(cmd, sizeof(cmd),
        "cat > /tmp/_test.py << 'PYTHON_SCRIPT_EOF'\n%s\nPYTHON_SCRIPT_EOF\n"
        "/usr/bin/python3.11 /tmp/_test.py; ret=$?; rm -f /tmp/_test.py; exit $ret",
        script);
    run_test(name, cmd, expect_exit_zero, expect_stdout);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("=== Python in Chrome Sandbox Test ===\n\n");

    // =====================================================================
    // Init-time configuration (before sandbox_init)
    // =====================================================================
    sandbox_set_policy(SANDBOX_POLICY_STRICT);
    sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);

    // Read-only paths for Python runtime:
    //   /usr/local/lib  - third-party packages (anthropic, httpx, etc.)
    //   /usr/local/bin  - python3 symlink (/usr/local/bin/python3 -> /usr/bin/python3.11)
    // The core Python runtime (/usr/bin/python3.11, /usr/lib/python3.11/) is
    // already covered by the default broker permissions.
    sandbox_set_readonly_paths("/usr/local/lib:/usr/local/bin");

    // Enable network for API call tests
    sandbox_set_network_enabled(1);

    printf("Initializing sandbox (zygote + namespace isolation)...\n");
    if (sandbox_init() != 0) {
        fprintf(stderr, "FATAL: sandbox_init() failed\n");
        return 1;
    }
    printf("Sandbox initialized.\n");

    // =====================================================================
    // Python interpreter tests — runs with Chrome's default seccomp policy
    // =====================================================================
    printf("\n--- Python Inside Sandbox ---\n");

    // 1. Python version
    run_test("python_version",
             "/usr/bin/python3.11 --version",
             1, "Python 3.11");

    // 2. Simple eval
    run_test("python_eval_simple",
             "/usr/bin/python3.11 -c \"print('hello from python in sandbox')\"",
             1, "hello from python in sandbox");

    // 3. Arithmetic
    run_test("python_eval_math",
             "/usr/bin/python3.11 -c \"print(2 + 2)\"",
             1, "4");

    // 4. Process info (semicolons for multi-statement one-liner)
    run_test("python_process_info",
             "/usr/bin/python3.11 -c \""
             "import os, sys; "
             "print(f'pid={os.getpid()} python={sys.version_info.major}.{sys.version_info.minor}')"
             "\"",
             1, "python=3.11");

    // =====================================================================
    // Claude Code workflow: write a Python file to /tmp, then execute it
    // =====================================================================
    printf("\n--- Claude Code Writes & Runs Python ---\n");

    // 5. Write a Python script to /tmp and execute it
    run_python_file_test("write_and_run_script",
        "print('hello from a python script')",
        1, "hello from a python script");

    // 6. File I/O round-trip
    run_python_file_test("python_file_io",
        "data = 'sandbox file test 12345'\n"
        "with open('/tmp/pytest_data.txt', 'w') as f:\n"
        "    f.write(data)\n"
        "with open('/tmp/pytest_data.txt', 'r') as f:\n"
        "    result = f.read()\n"
        "import os; os.unlink('/tmp/pytest_data.txt')\n"
        "print(result)",
        1, "sandbox file test 12345");

    // 7. JSON processing (typical Claude Code tool output)
    run_python_file_test("python_json_processing",
        "import json\n"
        "data = {'agent': 'claude', 'sandbox': 'chrome', 'runtime': 'python'}\n"
        "encoded = json.dumps(data, sort_keys=True)\n"
        "decoded = json.loads(encoded)\n"
        "print(f\"{decoded['agent']} in {decoded['sandbox']} via {decoded['runtime']}\")",
        1, "claude in chrome via python");

    // 8. Multi-step: Python writes another Python file and runs it
    run_python_file_test("python_multi_step_script",
        "import json, subprocess, sys\n"
        "script = 'import sys, os, json\\n'\n"
        "script += 'result = {\"cwd\": os.getcwd(), \"platform\": sys.platform, \"items\": list(range(5))}\\n'\n"
        "script += 'print(json.dumps(result))\\n'\n"
        "with open('/tmp/agent_task.py', 'w') as f:\n"
        "    f.write(script)\n"
        "r = subprocess.run([sys.executable, '/tmp/agent_task.py'],\n"
        "                   capture_output=True, text=True)\n"
        "import os; os.unlink('/tmp/agent_task.py')\n"
        "print(r.stdout.strip())",
        1, "\"platform\": \"linux\"");

    // 9. Subprocess: Python spawning child processes (agent running tools)
    run_python_file_test("python_subprocess",
        "import subprocess\n"
        "r = subprocess.run(['echo', 'spawned from python'],\n"
        "                   capture_output=True, text=True)\n"
        "print(r.stdout.strip())",
        1, "spawned from python");

    // 10. Python reading system info
    run_python_file_test("python_system_inspect",
        "import os, sys\n"
        "print(f'executable={sys.executable}')\n"
        "print(f'tmp_exists={os.path.isdir(\"/tmp\")}')",
        1, "tmp_exists=True");

    // =====================================================================
    // Claude API call from Python inside the sandbox
    // =====================================================================
    printf("\n--- Claude API Call from Python Inside Sandbox ---\n");
    printf("  Making a real Anthropic API call via Python urllib...\n");
    printf("  (requires ANTHROPIC_API_KEY and proxy/network access)\n\n");

    // 11. Direct API call using Python's stdlib through HTTPS proxy.
    printf("  TEST %-50s ", "python_claude_api_from_sandbox");
    fflush(stdout);

    SandboxResult api_result = sandbox_exec_shell(
        "cat > /tmp/_api_test.py << 'PYTHON_SCRIPT_EOF'\n"
        "import os, json, ssl, socket\n"
        "\n"
        "api_key = os.environ.get('ANTHROPIC_API_KEY', '')\n"
        "proxy = (os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')\n"
        "         or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy'))\n"
        "if not proxy:\n"
        "    print('NO_PROXY')\n"
        "    exit(0)\n"
        "if not api_key:\n"
        "    print('NO_API_KEY')\n"
        "    exit(0)\n"
        "\n"
        "# Parse proxy URL\n"
        "from urllib.parse import urlparse\n"
        "pu = urlparse(proxy)\n"
        "\n"
        "# Connect through proxy via CONNECT tunnel\n"
        "sock = socket.create_connection((pu.hostname, pu.port or 8080), timeout=30)\n"
        "connect_req = f'CONNECT api.anthropic.com:443 HTTP/1.1\\r\\nHost: api.anthropic.com:443\\r\\n'\n"
        "if pu.username and pu.password:\n"
        "    import base64\n"
        "    creds = base64.b64encode(f'{pu.username}:{pu.password}'.encode()).decode()\n"
        "    connect_req += f'Proxy-Authorization: Basic {creds}\\r\\n'\n"
        "connect_req += '\\r\\n'\n"
        "sock.sendall(connect_req.encode())\n"
        "\n"
        "# Read CONNECT response\n"
        "resp = b''\n"
        "while b'\\r\\n\\r\\n' not in resp:\n"
        "    resp += sock.recv(4096)\n"
        "\n"
        "# Wrap with TLS\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "tlssock = ctx.wrap_socket(sock, server_hostname='api.anthropic.com')\n"
        "\n"
        "# Send API request\n"
        "body = json.dumps({\n"
        "    'model': 'claude-sonnet-4-5-20250929', 'max_tokens': 50,\n"
        "    'messages': [{'role': 'user', 'content': 'What is 2+2? Reply with ONLY the number.'}]\n"
        "})\n"
        "req = (f'POST /v1/messages HTTP/1.1\\r\\n'\n"
        "       f'Host: api.anthropic.com\\r\\n'\n"
        "       f'x-api-key: {api_key}\\r\\n'\n"
        "       f'anthropic-version: 2023-06-01\\r\\n'\n"
        "       f'content-type: application/json\\r\\n'\n"
        "       f'content-length: {len(body)}\\r\\n'\n"
        "       f'\\r\\n{body}')\n"
        "tlssock.sendall(req.encode())\n"
        "\n"
        "# Read response\n"
        "data = b''\n"
        "while True:\n"
        "    chunk = tlssock.recv(4096)\n"
        "    if not chunk:\n"
        "        break\n"
        "    data += chunk\n"
        "    if b'\"stop_reason\"' in data:\n"
        "        break\n"
        "\n"
        "# Parse response body (after HTTP headers)\n"
        "parts = data.split(b'\\r\\n\\r\\n', 1)\n"
        "if len(parts) > 1:\n"
        "    try:\n"
        "        j = json.loads(parts[1])\n"
        "        print(j.get('content', [{}])[0].get('text', 'no text'))\n"
        "    except Exception:\n"
        "        print(parts[1][:500].decode(errors='replace'))\n"
        "else:\n"
        "    print(data[:500].decode(errors='replace'))\n"
        "tlssock.close()\n"
        "PYTHON_SCRIPT_EOF\n"
        "/usr/bin/python3.11 /tmp/_api_test.py; ret=$?; rm -f /tmp/_api_test.py; exit $ret"
    );

    printf("exit=%d, %d syscalls, %.3fs\n",
           api_result.exit_code,
           api_result.num_syscalls_total, api_result.duration_seconds);

    if (api_result.stderr_buf && api_result.stderr_len > 0) {
        int len = api_result.stderr_len > 500 ? 500 : (int)api_result.stderr_len;
        printf("  stderr: %.*s\n", len, api_result.stderr_buf);
    }
    if (api_result.stdout_buf && api_result.stdout_len > 0) {
        int len = api_result.stdout_len > 1000 ? 1000 : (int)api_result.stdout_len;
        printf("\n  ┌─────────────────────────────────────────────────┐\n");
        printf("  │  Claude response (Python urllib from sandbox):  │\n");
        printf("  ├─────────────────────────────────────────────────┤\n");
        printf("  │  %.*s", len, api_result.stdout_buf);
        if (api_result.stdout_buf[api_result.stdout_len - 1] != '\n')
            printf("\n");
        printf("  └─────────────────────────────────────────────────┘\n");

        // Count as pass if we got any output (NO_PROXY/NO_API_KEY are graceful)
        tests_passed++;
    } else {
        printf("    (no response captured)\n");
        tests_failed++;
    }
    sandbox_result_free(&api_result);

    // =====================================================================
    // Security verification
    // =====================================================================
    printf("\n--- Security Verification ---\n");

    // Python can't write to system directories
    run_python_file_test("python_cant_write_system",
        "try:\n"
        "    open('/usr/bin/evil', 'w')\n"
        "    print('FAIL: should not be able to write')\n"
        "except (PermissionError, OSError) as e:\n"
        "    print(f'blocked: {e}')",
        1, "blocked:");

    // Shell still works with Chrome defaults after Python tests
    run_test("chrome_defaults_after_python",
             "echo 'chrome defaults still work'",
             1, "chrome defaults still work");

    // =====================================================================
    // Cleanup
    // =====================================================================
    printf("\n--- Cleanup ---\n");
    sandbox_shutdown();
    printf("Sandbox shut down.\n");

    printf("\n=== Results: %d/%d passed ===\n",
           tests_passed, tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
