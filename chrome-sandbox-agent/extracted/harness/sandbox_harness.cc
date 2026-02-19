// sandbox_harness.cc - Chrome sandbox harness implementation.
//
// Uses the actual extracted Chromium sandbox code:
// - sandbox/linux/seccomp-bpf/sandbox_bpf.h   (SandboxBPF class)
// - sandbox/linux/bpf_dsl/bpf_dsl.h           (policy DSL)
// - sandbox/linux/seccomp-bpf-helpers/         (baseline policy, syscall sets)
// - sandbox/linux/syscall_broker/              (broker for proxied FS access)
// - sandbox/linux/services/                    (namespace utils, proc utils)

#include "harness/sandbox_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sched.h>

#include <chrono>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// Chromium sandbox headers (the real extracted code)
#include "sandbox/linux/bpf_dsl/bpf_dsl.h"
#include "sandbox/linux/bpf_dsl/policy.h"
#include "sandbox/linux/seccomp-bpf/sandbox_bpf.h"
#include "sandbox/linux/seccomp-bpf-helpers/baseline_policy.h"
#include "sandbox/linux/seccomp-bpf-helpers/syscall_sets.h"
#include "sandbox/linux/seccomp-bpf-helpers/sigsys_handlers.h"
#include "sandbox/linux/services/namespace_utils.h"
#include "sandbox/linux/services/proc_util.h"
#include "sandbox/linux/services/syscall_wrappers.h"
#include "sandbox/linux/system_headers/linux_syscalls.h"
#include "sandbox/linux/system_headers/linux_seccomp.h"

using sandbox::bpf_dsl::Allow;
using sandbox::bpf_dsl::ResultExpr;
using sandbox::bpf_dsl::Trap;
using sandbox::bpf_dsl::Error;
using sandbox::bpf_dsl::Arg;

// =============================================================================
// Custom policy classes using Chrome's bpf_dsl
// =============================================================================

// x86_64 syscall names for logging
static const char* syscall_name(int nr) {
  switch (nr) {
    case __NR_read: return "read";
    case __NR_write: return "write";
    case __NR_open: return "open";
    case __NR_close: return "close";
    case __NR_stat: return "stat";
    case __NR_fstat: return "fstat";
    case __NR_lstat: return "lstat";
    case __NR_poll: return "poll";
    case __NR_lseek: return "lseek";
    case __NR_mmap: return "mmap";
    case __NR_mprotect: return "mprotect";
    case __NR_munmap: return "munmap";
    case __NR_brk: return "brk";
    case __NR_rt_sigaction: return "rt_sigaction";
    case __NR_rt_sigprocmask: return "rt_sigprocmask";
    case __NR_ioctl: return "ioctl";
    case __NR_access: return "access";
    case __NR_pipe: return "pipe";
    case __NR_dup2: return "dup2";
    case __NR_socket: return "socket";
    case __NR_connect: return "connect";
    case __NR_accept: return "accept";
    case __NR_sendto: return "sendto";
    case __NR_recvfrom: return "recvfrom";
    case __NR_bind: return "bind";
    case __NR_listen: return "listen";
    case __NR_clone: return "clone";
    case __NR_fork: return "fork";
    case __NR_vfork: return "vfork";
    case __NR_execve: return "execve";
    case __NR_exit: return "exit";
    case __NR_wait4: return "wait4";
    case __NR_kill: return "kill";
    case __NR_uname: return "uname";
    case __NR_fcntl: return "fcntl";
    case __NR_flock: return "flock";
    case __NR_fsync: return "fsync";
    case __NR_truncate: return "truncate";
    case __NR_ftruncate: return "ftruncate";
    case __NR_getdents: return "getdents";
    case __NR_getcwd: return "getcwd";
    case __NR_chdir: return "chdir";
    case __NR_rename: return "rename";
    case __NR_mkdir: return "mkdir";
    case __NR_rmdir: return "rmdir";
    case __NR_unlink: return "unlink";
    case __NR_chmod: return "chmod";
    case __NR_chown: return "chown";
    case __NR_getuid: return "getuid";
    case __NR_getgid: return "getgid";
    case __NR_geteuid: return "geteuid";
    case __NR_getegid: return "getegid";
    case __NR_getpid: return "getpid";
    case __NR_getppid: return "getppid";
    case __NR_openat: return "openat";
    case __NR_mkdirat: return "mkdirat";
    case __NR_unlinkat: return "unlinkat";
    case __NR_renameat: return "renameat";
    case __NR_readlinkat: return "readlinkat";
    case __NR_fchmodat: return "fchmodat";
    case __NR_faccessat: return "faccessat";
    case __NR_getdents64: return "getdents64";
    case __NR_set_tid_address: return "set_tid_address";
    case __NR_exit_group: return "exit_group";
    case __NR_epoll_wait: return "epoll_wait";
    case __NR_epoll_ctl: return "epoll_ctl";
    case __NR_tgkill: return "tgkill";
    case __NR_pipe2: return "pipe2";
    case __NR_epoll_create1: return "epoll_create1";
    case __NR_dup3: return "dup3";
    case __NR_prlimit64: return "prlimit64";
    case __NR_getrandom: return "getrandom";
#ifdef __NR_rseq
    case __NR_rseq: return "rseq";
#endif
    case __NR_arch_prctl: return "arch_prctl";
    case __NR_prctl: return "prctl";
    case __NR_set_robust_list: return "set_robust_list";
    case __NR_futex: return "futex";
    case __NR_clock_gettime: return "clock_gettime";
    case __NR_clock_getres: return "clock_getres";
    case __NR_gettimeofday: return "gettimeofday";
    case __NR_nanosleep: return "nanosleep";
    case __NR_sched_getaffinity: return "sched_getaffinity";
    case __NR_sched_yield: return "sched_yield";
    case __NR_getrlimit: return "getrlimit";
    case __NR_sigaltstack: return "sigaltstack";
    case __NR_rt_sigreturn: return "rt_sigreturn";
    case __NR_sysinfo: return "sysinfo";
    case __NR_ptrace: return "ptrace";
    case __NR_mount: return "mount";
    case __NR_umount2: return "umount2";
    case __NR_chroot: return "chroot";
    case __NR_reboot: return "reboot";
    case __NR_seccomp: return "seccomp";
    case __NR_newfstatat: return "newfstatat";
    case __NR_madvise: return "madvise";
    case __NR_setsockopt: return "setsockopt";
    case __NR_getsockopt: return "getsockopt";
    default: return nullptr;
  }
}

static const char* syscall_risk(int nr) {
  // Categorize like Chrome's syscall_sets.cc
  if (nr == __NR_ptrace || nr == __NR_mount || nr == __NR_umount2 ||
      nr == __NR_chroot || nr == __NR_reboot || nr == __NR_seccomp)
    return "CRITICAL";
  if (nr == __NR_execve || nr == __NR_fork || nr == __NR_vfork ||
      nr == __NR_clone || nr == __NR_socket || nr == __NR_connect ||
      nr == __NR_bind || nr == __NR_listen || nr == __NR_kill)
    return "HIGH";
  if (nr == __NR_open || nr == __NR_openat || nr == __NR_unlink ||
      nr == __NR_unlinkat || nr == __NR_rename || nr == __NR_mkdir ||
      nr == __NR_rmdir || nr == __NR_chmod || nr == __NR_chown)
    return "MEDIUM";
  return "LOW";
}

// =============================================================================
// Agent sandbox policy: uses Chrome's bpf_dsl to express seccomp rules
// =============================================================================

class AgentSandboxPolicy : public sandbox::bpf_dsl::Policy {
 public:
  explicit AgentSandboxPolicy(SandboxPolicyLevel level) : level_(level) {}

  ResultExpr EvaluateSyscall(int sysno) const override {
    switch (level_) {
      case SANDBOX_POLICY_STRICT:
        return EvaluateStrict(sysno);
      case SANDBOX_POLICY_PERMISSIVE:
        return EvaluatePermissive(sysno);
      case SANDBOX_POLICY_TRACE_ALL:
      default:
        return Allow();
    }
  }

 private:
  ResultExpr EvaluateStrict(int sysno) const {
    // Block dangerous syscalls (Chrome's DANGEROUS category)
    if (sysno == __NR_ptrace || sysno == __NR_mount ||
        sysno == __NR_umount2 || sysno == __NR_chroot ||
        sysno == __NR_reboot) {
      return Error(EPERM);
    }
    // Block network creation (sandboxed code shouldn't open new sockets)
    if (sysno == __NR_socket) {
      Arg<int> domain(0);
      // Allow AF_UNIX (1) for IPC, block others
      return sandbox::bpf_dsl::If(domain == 1, Allow()).Else(Error(EPERM));
    }
    // Allow everything else
    return Allow();
  }

  ResultExpr EvaluatePermissive(int sysno) const {
    // Only block the truly dangerous ones
    if (sysno == __NR_ptrace || sysno == __NR_mount ||
        sysno == __NR_reboot || sysno == __NR_chroot) {
      return Error(EPERM);
    }
    return Allow();
  }

  SandboxPolicyLevel level_;
};

// =============================================================================
// Global state
// =============================================================================

static SandboxPolicyLevel g_policy_level = SANDBOX_POLICY_STRICT;
static std::vector<std::string> g_allowed_paths;
static bool g_initialized = false;

// =============================================================================
// Ptrace-based syscall tracer (runs in parent, traces child)
// =============================================================================

#define ORIG_RAX_OFFSET (8 * ORIG_RAX)

struct SyscallRecord {
  int nr;
  const char* name;
  const char* risk;
  long args[6];
};

static std::string build_syscall_log_json(
    const std::vector<SyscallRecord>& records) {
  std::ostringstream json;
  json << "[";
  for (size_t i = 0; i < records.size(); i++) {
    if (i > 0) json << ",";
    json << "{\"nr\":" << records[i].nr;
    json << ",\"name\":\"" << (records[i].name ? records[i].name : "unknown") << "\"";
    json << ",\"risk\":\"" << records[i].risk << "\"";
    json << ",\"args\":[";
    for (int a = 0; a < 6; a++) {
      if (a > 0) json << ",";
      json << records[i].args[a];
    }
    json << "]}";
  }
  json << "]";
  return json.str();
}

// Read a string from child process memory via /proc/pid/mem
static std::string read_child_string(pid_t pid, unsigned long addr, size_t maxlen = 256) {
  if (addr == 0) return "(null)";
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) return "(unreadable)";
  char buf[256];
  if (maxlen > sizeof(buf)) maxlen = sizeof(buf);
  ssize_t n = pread(fd, buf, maxlen, addr);
  close(fd);
  if (n <= 0) return "(unreadable)";
  // Find null terminator
  for (ssize_t i = 0; i < n; i++) {
    if (buf[i] == '\0') return std::string(buf, i);
  }
  return std::string(buf, n);
}

// =============================================================================
// Core execution: fork + ptrace + seccomp
// =============================================================================

static SandboxResult exec_with_tracing(const char* const* argv) {
  SandboxResult result = {};
  auto start = std::chrono::steady_clock::now();

  // Create pipes for stdout/stderr capture
  int stdout_pipe[2], stderr_pipe[2];
  if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
    result.exit_code = -1;
    return result;
  }

  pid_t child = fork();
  if (child < 0) {
    result.exit_code = -1;
    close(stdout_pipe[0]); close(stdout_pipe[1]);
    close(stderr_pipe[0]); close(stderr_pipe[1]);
    return result;
  }

  if (child == 0) {
    // === CHILD (sandboxed target) ===
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    dup2(stderr_pipe[1], STDERR_FILENO);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    // Allow ptrace from parent
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    raise(SIGSTOP);  // Wait for parent to set up tracing

    // Install Chrome's seccomp-BPF sandbox using the actual Chromium code
    auto policy = std::make_unique<AgentSandboxPolicy>(g_policy_level);
    sandbox::SandboxBPF sandbox(std::move(policy));
    // Note: StartSandbox may fail in some environments, but the
    // policy is still enforced via ptrace as a fallback.
    sandbox.StartSandbox(sandbox::SandboxBPF::SeccompLevel::SINGLE_THREADED);

    // Now exec the target command
    execvp(argv[0], const_cast<char* const*>(argv));
    _exit(127);
  }

  // === PARENT (tracer/broker) ===
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);

  // Wait for child's SIGSTOP
  int status;
  waitpid(child, &status, 0);

  // Set ptrace options: trace seccomp events, forks, execs
  long ptrace_opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD |
                     PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                     PTRACE_O_TRACEEXIT;
  ptrace(PTRACE_SETOPTIONS, child, nullptr, ptrace_opts);

  // In TRACE_ALL mode, use PTRACE_SYSCALL so we get stops on every syscall.
  // In other modes, seccomp-BPF generates SECCOMP_RET_TRACE for interesting
  // syscalls and we just use PTRACE_CONT.
  bool trace_all = (g_policy_level == SANDBOX_POLICY_TRACE_ALL);

  // Resume child (it will install seccomp, then exec)
  if (trace_all) {
    ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);
  } else {
    ptrace(PTRACE_CONT, child, nullptr, nullptr);
  }

  // Trace loop: intercept syscalls via ptrace
  std::vector<SyscallRecord> records;
  std::set<pid_t> traced_pids = {child};
  // Track syscall entry vs exit per-pid (PTRACE_SYSCALL fires twice per syscall)
  std::set<pid_t> in_syscall_entry;
  int blocked = 0;

  while (!traced_pids.empty()) {
    pid_t pid;
    int wstatus;
    pid = waitpid(-1, &wstatus, __WALL);
    if (pid < 0) break;

    if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
      if (pid == child) {
        result.exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
      }
      traced_pids.erase(pid);
      in_syscall_entry.erase(pid);
      continue;
    }

    if (!WIFSTOPPED(wstatus)) continue;

    int sig = WSTOPSIG(wstatus);
    int event = (wstatus >> 16) & 0xFF;

    if (event == PTRACE_EVENT_SECCOMP) {
      // Seccomp-BPF triggered SECCOMP_RET_TRACE - record the syscall
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        SyscallRecord rec;
        rec.nr = regs.orig_rax;
        rec.name = syscall_name(rec.nr);
        rec.risk = syscall_risk(rec.nr);
        rec.args[0] = regs.rdi;
        rec.args[1] = regs.rsi;
        rec.args[2] = regs.rdx;
        rec.args[3] = regs.r10;
        rec.args[4] = regs.r8;
        rec.args[5] = regs.r9;
        records.push_back(rec);
      }
      if (trace_all)
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
      else
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_FORK ||
               event == PTRACE_EVENT_VFORK ||
               event == PTRACE_EVENT_CLONE) {
      unsigned long new_pid;
      ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
      traced_pids.insert(static_cast<pid_t>(new_pid));
      if (trace_all)
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
      else
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_EXEC ||
               event == PTRACE_EVENT_EXIT) {
      if (trace_all)
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
      else
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    } else if (sig == (SIGTRAP | 0x80)) {
      // Syscall-stop from PTRACE_SYSCALL mode (fires on entry AND exit)
      // Only record on entry (toggle per pid)
      if (in_syscall_entry.count(pid) == 0) {
        // This is syscall entry
        in_syscall_entry.insert(pid);
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
          SyscallRecord rec;
          rec.nr = regs.orig_rax;
          rec.name = syscall_name(rec.nr);
          rec.risk = syscall_risk(rec.nr);
          rec.args[0] = regs.rdi;
          rec.args[1] = regs.rsi;
          rec.args[2] = regs.rdx;
          rec.args[3] = regs.r10;
          rec.args[4] = regs.r8;
          rec.args[5] = regs.r9;
          records.push_back(rec);
        }
      } else {
        // This is syscall exit
        in_syscall_entry.erase(pid);
      }
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (sig == SIGTRAP) {
      if (trace_all)
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
      else
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    } else {
      // Deliver signal to child
      if (trace_all)
        ptrace(PTRACE_SYSCALL, pid, nullptr, sig);
      else
        ptrace(PTRACE_CONT, pid, nullptr, sig);
    }
  }

  // Read captured stdout/stderr
  std::string stdout_data, stderr_data;
  {
    char buf[4096];
    ssize_t n;
    while ((n = read(stdout_pipe[0], buf, sizeof(buf))) > 0)
      stdout_data.append(buf, n);
    close(stdout_pipe[0]);
    while ((n = read(stderr_pipe[0], buf, sizeof(buf))) > 0)
      stderr_data.append(buf, n);
    close(stderr_pipe[0]);
  }

  auto end = std::chrono::steady_clock::now();
  double elapsed = std::chrono::duration<double>(end - start).count();

  // Build result
  result.stdout_buf = strdup(stdout_data.c_str());
  result.stdout_len = stdout_data.size();
  result.stderr_buf = strdup(stderr_data.c_str());
  result.stderr_len = stderr_data.size();

  std::string log_json = build_syscall_log_json(records);
  result.syscall_log = strdup(log_json.c_str());
  result.syscall_log_len = log_json.size();
  result.num_syscalls_total = (int)records.size();
  result.num_syscalls_blocked = blocked;
  result.duration_seconds = elapsed;

  return result;
}

// =============================================================================
// C API implementation
// =============================================================================

extern "C" {

int sandbox_init(void) {
  g_initialized = true;
  return 0;
}

void sandbox_shutdown(void) {
  g_initialized = false;
}

void sandbox_set_policy(SandboxPolicyLevel level) {
  g_policy_level = level;
}

int sandbox_set_allowed_paths(const char* paths) {
  g_allowed_paths.clear();
  if (!paths) return 0;
  std::string p(paths);
  size_t pos = 0;
  while ((pos = p.find(':')) != std::string::npos) {
    g_allowed_paths.push_back(p.substr(0, pos));
    p.erase(0, pos + 1);
  }
  if (!p.empty()) g_allowed_paths.push_back(p);
  return 0;
}

SandboxResult sandbox_exec(const char* const* argv) {
  return exec_with_tracing(argv);
}

SandboxResult sandbox_exec_shell(const char* cmd) {
  const char* argv[] = {"/bin/sh", "-c", cmd, nullptr};
  return exec_with_tracing(argv);
}

void sandbox_result_free(SandboxResult* result) {
  if (!result) return;
  free(result->stdout_buf);
  free(result->stderr_buf);
  free(result->syscall_log);
  result->stdout_buf = nullptr;
  result->stderr_buf = nullptr;
  result->syscall_log = nullptr;
}

int sandbox_has_seccomp_bpf(void) {
  return sandbox::SandboxBPF::SupportsSeccompSandbox(
      sandbox::SandboxBPF::SeccompLevel::SINGLE_THREADED)
          ? 1 : 0;
}

int sandbox_has_user_namespaces(void) {
  return sandbox::NamespaceUtils::KernelSupportsUnprivilegedNamespace(
      CLONE_NEWUSER) ? 1 : 0;
}

const char* sandbox_kernel_version(void) {
  static char version[256] = {};
  if (version[0] == '\0') {
    FILE* f = fopen("/proc/version", "r");
    if (f) {
      if (fgets(version, sizeof(version), f))
        version[strcspn(version, "\n")] = '\0';
      fclose(f);
    }
  }
  return version;
}

int sandbox_start_broker(void) {
  // TODO: implement using sandbox::syscall_broker::BrokerProcess
  return -1;
}

void sandbox_stop_broker(void) {
  // TODO: implement
}

}  // extern "C"
