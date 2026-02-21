// Minimal test: run a single command inside the Chrome sandbox
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sandbox_harness.h"

int main() {
    setbuf(stdout, NULL);  // Unbuffered output
    setbuf(stderr, NULL);

    printf("Step 1: Initializing sandbox...\n");
    int rc = sandbox_init();
    if (rc != 0) {
        fprintf(stderr, "FATAL: sandbox_init() failed\n");
        return 1;
    }
    printf("Step 2: Sandbox initialized OK\n");

    printf("Step 3: Running 'echo hello world' inside sandbox...\n");
    SandboxResult result = sandbox_exec_shell("echo hello world");
    printf("Step 4: Command finished, exit_code=%d\n", result.exit_code);

    if (result.stdout_buf) {
        printf("  stdout: %.*s", (int)result.stdout_len, result.stdout_buf);
    }
    if (result.stderr_buf && result.stderr_len > 0) {
        printf("  stderr: %.*s", (int)result.stderr_len, result.stderr_buf);
    }
    printf("  syscalls: total=%d blocked=%d\n",
           result.num_syscalls_total, result.num_syscalls_blocked);
    printf("  duration: %.3fs\n", result.duration_seconds);
    sandbox_result_free(&result);

    printf("Step 5: Running 'ls /tmp' inside sandbox...\n");
    result = sandbox_exec_shell("ls /tmp 2>&1 | head -5");
    printf("Step 6: ls finished, exit_code=%d\n", result.exit_code);
    if (result.stdout_buf) {
        printf("  stdout: %.*s", (int)result.stdout_len, result.stdout_buf);
    }
    sandbox_result_free(&result);

    printf("Step 7: Running file creation workflow...\n");
    result = sandbox_exec_shell(
        "echo 'test data 12345' > /tmp/sandbox_test.txt && "
        "cat /tmp/sandbox_test.txt && "
        "rm /tmp/sandbox_test.txt && "
        "echo 'cleanup done'"
    );
    printf("Step 8: File workflow finished, exit_code=%d\n", result.exit_code);
    if (result.stdout_buf) {
        printf("  stdout: %.*s", (int)result.stdout_len, result.stdout_buf);
    }
    sandbox_result_free(&result);

    printf("Step 9: Shutting down sandbox...\n");
    sandbox_shutdown();
    printf("Step 10: Done! Sandbox works correctly.\n");

    return 0;
}
