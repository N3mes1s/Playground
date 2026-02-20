#include "harness/sandbox_harness.h"
#include <stdio.h>
#include <string.h>

int main() {
  sandbox_init();
  sandbox_set_policy(SANDBOX_POLICY_STRICT);
  sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);
  SandboxResult r = sandbox_exec_shell("ls -la /bin/sh 2>&1; echo RC=$?");
  // Write full syscall log to file
  if (r.syscall_log) {
    FILE* f = fopen("/tmp/syscall_log.json", "w");
    if (f) { fwrite(r.syscall_log, 1, r.syscall_log_len, f); fclose(f); }
  }
  printf("exit_code=%d total=%d blocked=%d\n",
         r.exit_code, r.num_syscalls_total, r.num_syscalls_blocked);
  printf("stdout='%s'\n", r.stdout_buf ? r.stdout_buf : "(null)");
  sandbox_result_free(&r);
  sandbox_shutdown();
  return 0;
}
