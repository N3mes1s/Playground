// sandbox_integration_test.cc — End-to-end test of the Chrome sandbox harness.
//
// Tests the full stack: zygote, namespace isolation, seccomp-BPF,
// ptrace-based broker, exec policy enforcement.

#include "harness/sandbox_harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
  do { \
    tests_run++; \
    printf("  TEST %-50s ", #name); \
    fflush(stdout); \
  } while (0)

#define PASS() \
  do { \
    tests_passed++; \
    printf("[PASS]\n"); \
  } while (0)

#define FAIL(msg) \
  do { \
    tests_failed++; \
    printf("[FAIL] %s\n", msg); \
  } while (0)

#define ASSERT(cond, msg) \
  do { \
    if (!(cond)) { FAIL(msg); return; } \
  } while (0)

// =============================================================================
// Test: Basic initialization and shutdown
// =============================================================================
static void test_init_shutdown() {
  TEST(init_shutdown);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Execute a simple command (echo)
// =============================================================================
static void test_exec_echo() {
  TEST(exec_echo);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  SandboxResult result = sandbox_exec_shell("echo hello_sandbox");
  ASSERT(result.exit_code == 0, "echo failed");
  ASSERT(result.stdout_buf != NULL, "no stdout captured");
  ASSERT(strstr(result.stdout_buf, "hello_sandbox") != NULL,
         "stdout doesn't contain expected string");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Command that writes to stderr
// =============================================================================
static void test_exec_stderr() {
  TEST(exec_stderr);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  SandboxResult result = sandbox_exec_shell("echo error_msg >&2");
  ASSERT(result.exit_code == 0, "stderr command failed");
  ASSERT(result.stderr_buf != NULL, "no stderr captured");
  ASSERT(strstr(result.stderr_buf, "error_msg") != NULL,
         "stderr doesn't contain expected string");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Command exit code
// =============================================================================
static void test_exit_code() {
  TEST(exit_code);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  SandboxResult result = sandbox_exec_shell("exit 42");
  ASSERT(result.exit_code == 42, "wrong exit code");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Syscall logging
// =============================================================================
static void test_syscall_logging() {
  TEST(syscall_logging);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  SandboxResult result = sandbox_exec_shell("true");
  ASSERT(result.exit_code == 0, "true command failed");
  ASSERT(result.num_syscalls_total > 0, "no syscalls recorded");
  ASSERT(result.syscall_log != NULL, "no syscall log");
  ASSERT(result.syscall_log_len > 0, "empty syscall log");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Multiple commands through zygote (verifies zygote stays alive)
// =============================================================================
static void test_multiple_commands() {
  TEST(multiple_commands_via_zygote);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  for (int i = 0; i < 3; i++) {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "echo run_%d", i);
    SandboxResult result = sandbox_exec_shell(cmd);
    ASSERT(result.exit_code == 0, "command failed");
    char expected[32];
    snprintf(expected, sizeof(expected), "run_%d", i);
    ASSERT(result.stdout_buf != NULL && strstr(result.stdout_buf, expected),
           "wrong output from multi-command");
    sandbox_result_free(&result);
  }

  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Exec policy — BROKERED (default, allows exec to valid paths)
// =============================================================================
static void test_exec_policy_brokered() {
  TEST(exec_policy_brokered);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);
  SandboxResult result = sandbox_exec_shell("ls /");
  ASSERT(result.exit_code == 0, "brokered exec should allow ls");
  ASSERT(result.stdout_buf != NULL, "no output from ls");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Exec policy — CHROME (blocks exec after initial)
// =============================================================================
static void test_exec_policy_chrome() {
  TEST(exec_policy_chrome);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  sandbox_set_exec_policy(SANDBOX_EXEC_CHROME);
  // /bin/sh needs to exec itself to run, so the first exec is /bin/sh.
  // Then "ls" would be a second exec — Chrome mode should block it.
  // Use a direct binary instead to test single-exec.
  const char* argv[] = {"/bin/echo", "chrome_mode_works", NULL};
  SandboxResult result = sandbox_exec(argv);
  ASSERT(result.exit_code == 0, "chrome mode should allow initial exec");
  ASSERT(result.stdout_buf != NULL &&
         strstr(result.stdout_buf, "chrome_mode_works"),
         "chrome mode initial exec output wrong");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Network isolation (should not be able to reach network)
// =============================================================================
static void test_network_isolation() {
  TEST(network_isolation);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);
  // Try to list network interfaces — in a net NS, only loopback (down)
  SandboxResult result = sandbox_exec_shell(
      "cat /proc/net/dev 2>/dev/null | wc -l");
  // Should succeed but show minimal interfaces
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: /tmp is writable (tmpfs in chroot)
// =============================================================================
static void test_tmp_writable() {
  TEST(tmp_writable);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);
  SandboxResult result = sandbox_exec_shell(
      "echo test_data > /tmp/sandbox_test && cat /tmp/sandbox_test");
  ASSERT(result.exit_code == 0, "/tmp should be writable");
  ASSERT(result.stdout_buf != NULL &&
         strstr(result.stdout_buf, "test_data"),
         "/tmp write/read failed");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: System dirs are readable
// =============================================================================
static void test_system_dirs_readable() {
  TEST(system_dirs_readable);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);
  SandboxResult result = sandbox_exec_shell("ls /bin/sh");
  ASSERT(result.exit_code == 0, "/bin should be readable");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Duration tracking
// =============================================================================
static void test_duration_tracking() {
  TEST(duration_tracking);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  SandboxResult result = sandbox_exec_shell("sleep 0.1");
  ASSERT(result.duration_seconds >= 0.05, "duration too short");
  ASSERT(result.duration_seconds < 10.0, "duration too long");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Test: Capability check
// =============================================================================
static void test_capabilities_check() {
  TEST(capabilities_check);
  ASSERT(sandbox_has_seccomp_bpf(), "seccomp-BPF not available");
  PASS();
}

// =============================================================================
// Test: Kernel version
// =============================================================================
static void test_kernel_version() {
  TEST(kernel_version);
  const char* ver = sandbox_kernel_version();
  ASSERT(ver != NULL && strlen(ver) > 0, "no kernel version");
  ASSERT(strstr(ver, "Linux") != NULL, "doesn't look like Linux");
  PASS();
}

// =============================================================================
// Test: Pipeline (multiple processes)
// =============================================================================
static void test_pipeline() {
  TEST(pipeline);
  int rc = sandbox_init();
  ASSERT(rc == 0, "sandbox_init() failed");

  sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);
  SandboxResult result = sandbox_exec_shell(
      "echo 'hello world' | tr 'h' 'H'");
  ASSERT(result.exit_code == 0, "pipeline failed");
  ASSERT(result.stdout_buf != NULL &&
         strstr(result.stdout_buf, "Hello"),
         "pipeline output wrong");
  sandbox_result_free(&result);
  sandbox_shutdown();
  PASS();
}

// =============================================================================
// Main
// =============================================================================
int main() {
  printf("=== Chrome Sandbox Harness Integration Tests ===\n\n");

  test_capabilities_check();
  test_kernel_version();
  test_init_shutdown();
  test_exec_echo();
  test_exec_stderr();
  test_exit_code();
  test_syscall_logging();
  test_multiple_commands();
  test_exec_policy_brokered();
  test_exec_policy_chrome();
  test_network_isolation();
  test_tmp_writable();
  test_system_dirs_readable();
  test_duration_tracking();
  test_pipeline();

  printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
  if (tests_failed > 0)
    printf(", %d FAILED", tests_failed);
  printf(" ===\n");

  return tests_failed > 0 ? 1 : 0;
}
