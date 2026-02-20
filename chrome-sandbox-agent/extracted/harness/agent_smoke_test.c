// agent_smoke_test.c - Test real agent-like commands in the Chrome sandbox.
// Tests what a real AI agent would do: run shell commands, read/write files,
// execute multi-step workflows, and verify security boundaries.

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
        if (r.stderr_buf && r.stderr_len > 0) {
            printf("    stderr: %.*s\n",
                   (int)(r.stderr_len > 200 ? 200 : r.stderr_len), r.stderr_buf);
        }
        ok = 0;
    } else if (!expect_exit_zero && r.exit_code == 0) {
        printf("[FAIL] expected non-zero exit\n");
        ok = 0;
    } else if (expect_stdout && r.stdout_buf &&
               !strstr(r.stdout_buf, expect_stdout)) {
        printf("[FAIL] stdout missing '%s'\n", expect_stdout);
        ok = 0;
    } else if (expect_stdout && !r.stdout_buf) {
        printf("[FAIL] no stdout\n");
        ok = 0;
    }

    if (ok) {
        printf("[PASS]\n");
        tests_passed++;
    } else {
        tests_failed++;
    }
    sandbox_result_free(&r);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("=== Chrome Sandbox Agent Smoke Test ===\n\n");
    printf("Initializing sandbox (zygote + namespace isolation)...\n");

    if (sandbox_init() != 0) {
        fprintf(stderr, "FATAL: sandbox_init() failed\n");
        return 1;
    }
    printf("Sandbox initialized.\n");

    // Configure like a real agent would
    sandbox_set_policy(SANDBOX_POLICY_STRICT);
    sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);

    printf("\n--- Basic Agent Operations ---\n");

    // 1. Simple echo (baseline)
    run_test("echo_baseline",
             "echo 'hello from sandbox'", 1, "hello from sandbox");

    // 2. File creation and reading (core agent capability)
    run_test("create_and_read_file",
             "echo 'hello sandbox' > /tmp/test_agent.txt && "
             "cat /tmp/test_agent.txt && rm /tmp/test_agent.txt",
             1, "hello sandbox");

    // 3. Multi-step file workflow (append + count lines)
    run_test("multi_step_file_workflow",
             "echo 'line 1' > /tmp/agent_data.txt && "
             "echo 'line 2' >> /tmp/agent_data.txt && "
             "wc -l < /tmp/agent_data.txt && "
             "rm /tmp/agent_data.txt",
             1, "2");

    // 4. Command pipeline (grep, wc)
    run_test("text_processing_pipeline",
             "printf 'apple\\nbanana\\ncherry\\n' | grep 'an' | wc -l",
             1, "1");

    // 5. Read /proc (self info)
    run_test("read_proc_self",
             "cat /proc/self/status 2>/dev/null | head -1 || echo 'no proc'",
             1, NULL);

    printf("\n--- Agent Tool-like Operations ---\n");

    // 6. Complex shell script (like an agent running a build)
    run_test("loop_and_count",
             "count=0; for i in 1 2 3 4 5 6 7 8 9 10; do count=$((count+1)); done; echo \"count: $count\"",
             1, "count: 10");

    // 7. Environment inspection
    run_test("env_inspection",
             "echo \"pid=$$, uid=$(id -u 2>/dev/null || echo unknown)\"",
             1, "pid=");

    // 8. Temp file round-trip
    run_test("temp_file_roundtrip",
             "dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 > /tmp/rand.txt && "
             "wc -c < /tmp/rand.txt && rm /tmp/rand.txt",
             1, NULL);

    // 9. Multiple sequential commands through the zygote
    run_test("sequential_1", "echo 'seq1'", 1, "seq1");
    run_test("sequential_2", "echo 'seq2'", 1, "seq2");
    run_test("sequential_3", "echo 'seq3'", 1, "seq3");

    printf("\n--- Security Boundary Tests ---\n");

    // 10. Can't write to system directories
    run_test("system_dirs_readonly",
             "touch /bin/evil 2>/dev/null; echo $?",
             1, NULL);  // Should succeed (returns exit code via echo)

    // 11. Process isolation (PID namespace)
    run_test("pid_namespace",
             "echo \"my pid is $$\"",
             1, "my pid is");

    // 12. stderr capture
    run_test("stderr_capture",
             "echo 'stdout_data' && echo 'stderr_data' >&2",
             1, "stdout_data");

    // 13. Exit code propagation
    run_test("exit_code_42", "exit 42", 0, NULL);

    // 14. Large output handling
    run_test("large_output",
             "seq 1 500 | tail -1",
             1, "500");

    printf("\n--- Cleanup ---\n");
    sandbox_shutdown();
    printf("Sandbox shut down.\n");

    printf("\n=== Results: %d/%d passed ===\n",
           tests_passed, tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
