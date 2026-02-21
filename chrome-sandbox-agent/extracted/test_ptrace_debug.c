#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <linux/capability.h>

static void drop_all_caps() {
  struct __user_cap_header_struct hdr = {};
  hdr.version = _LINUX_CAPABILITY_VERSION_3;
  struct __user_cap_data_struct data[2] = {};
  syscall(SYS_capset, &hdr, data);
}

static void test_ptrace(const char* label) {
  int pipefd[2];
  pipe(pipefd);

  pid_t child = fork();
  if (child == 0) {
    close(pipefd[0]);
    errno = 0;
    long ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
    int err = errno;
    char msg[256];
    int len = snprintf(msg, sizeof(msg),
        "  %-40s ret=%ld errno=%d(%s)\n",
        label, ret, err, strerror(err));
    write(pipefd[1], msg, len);
    close(pipefd[1]);
    _exit(0);
  }
  close(pipefd[1]);
  // Read result from child
  char buf[256];
  ssize_t n = read(pipefd[0], buf, sizeof(buf)-1);
  close(pipefd[0]);
  if (n > 0) { buf[n] = 0; printf("%s", buf); }

  // Reap child - handle ptrace stops
  int status;
  for (;;) {
    pid_t w = waitpid(child, &status, __WALL);
    if (w < 0) break;
    if (WIFEXITED(status) || WIFSIGNALED(status)) break;
    // Resume any ptrace-stopped child
    ptrace(PTRACE_CONT, child, 0, 0);
  }
}

int main() {
  printf("=== PTRACE_TRACEME capability tests ===\n\n");

  test_ptrace("1. plain");

  if (unshare(CLONE_NEWUSER) != 0) {
    printf("unshare(CLONE_NEWUSER) failed: %s\n", strerror(errno));
    return 1;
  }

  // Write uid/gid maps
  {
    FILE* f = fopen("/proc/self/setgroups", "w");
    if (f) { fprintf(f, "deny"); fclose(f); }
    uid_t uid = getuid();
    gid_t gid = getgid();
    char buf[64];
    f = fopen("/proc/self/uid_map", "w");
    if (f) { snprintf(buf, sizeof(buf), "%d %d 1", uid, uid); fprintf(f, "%s", buf); fclose(f); }
    f = fopen("/proc/self/gid_map", "w");
    if (f) { snprintf(buf, sizeof(buf), "%d %d 1", gid, gid); fprintf(f, "%s", buf); fclose(f); }
  }

  test_ptrace("2. user NS");

  unshare(CLONE_NEWIPC);
  test_ptrace("3. + IPC NS");

  unshare(CLONE_NEWNET);
  test_ptrace("4. + net NS");

  unshare(CLONE_NEWNS);
  mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
  test_ptrace("5. + mount NS");

  prctl(PR_SET_DUMPABLE, 0);
  test_ptrace("6. + dumpable=0");

  prctl(PR_SET_DUMPABLE, 1);
  test_ptrace("7. + dumpable=1 (restored)");

  drop_all_caps();
  test_ptrace("8. + caps dropped");

  prctl(PR_SET_DUMPABLE, 0);
  test_ptrace("9. + caps dropped + dumpable=0");

  printf("\nDone.\n");
  return 0;
}
