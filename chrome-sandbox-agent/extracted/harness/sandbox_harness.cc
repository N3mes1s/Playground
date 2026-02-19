// sandbox_harness.cc - Chrome sandbox harness implementation.
//
// Uses the actual extracted Chromium sandbox code:
// - sandbox/linux/seccomp-bpf/sandbox_bpf.h   (SandboxBPF class)
// - sandbox/linux/bpf_dsl/bpf_dsl.h           (policy DSL)
// - sandbox/linux/seccomp-bpf-helpers/         (baseline policy, syscall sets)
// - sandbox/linux/syscall_broker/              (broker for proxied FS access)
// - sandbox/linux/services/                    (namespace utils, proc utils)
//
// Sandbox layers (matching Chrome's defense-in-depth):
// Layer 1: Namespace isolation (user, PID, network) via unshare(2)
// Layer 2: Filesystem isolation via chroot(2) to empty dir
// Layer 3: Capability dropping via capset(2)
// Layer 4: seccomp-BPF syscall filtering via Chrome's SandboxBPF

#include "harness/sandbox_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
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
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// Chromium sandbox headers (the real extracted code)
#include "sandbox/linux/bpf_dsl/bpf_dsl.h"
#include "sandbox/linux/bpf_dsl/policy.h"
#include "sandbox/linux/seccomp-bpf/sandbox_bpf.h"
#include "sandbox/linux/seccomp-bpf-helpers/baseline_policy.h"
#include "sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.h"
#include "sandbox/linux/seccomp-bpf-helpers/syscall_sets.h"
#include "sandbox/linux/seccomp-bpf-helpers/sigsys_handlers.h"
#include "sandbox/linux/syscall_broker/broker_process.h"
#include "sandbox/linux/syscall_broker/broker_sandbox_config.h"
#include "sandbox/linux/syscall_broker/broker_command.h"
#include "sandbox/linux/syscall_broker/broker_file_permission.h"
#include "sandbox/linux/syscall_broker/broker_client.h"
#include "sandbox/linux/services/namespace_utils.h"
#include "sandbox/linux/services/proc_util.h"
#include "sandbox/linux/services/resource_limits.h"
#include "sandbox/linux/services/syscall_wrappers.h"
#include "sandbox/linux/services/yama.h"
#include "sandbox/linux/system_headers/linux_syscalls.h"
#include "sandbox/linux/system_headers/linux_seccomp.h"
#include "sandbox/linux/system_headers/linux_stat.h"
#include "sandbox/linux/system_headers/capability.h"

using sandbox::bpf_dsl::Allow;
using sandbox::bpf_dsl::ResultExpr;
using sandbox::bpf_dsl::Trap;
using sandbox::bpf_dsl::Trace;
using sandbox::bpf_dsl::Error;
using sandbox::bpf_dsl::Arg;

// =============================================================================
// Syscall name and risk classification (x86_64)
// =============================================================================

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
    case __NR_sendmsg: return "sendmsg";
    case __NR_recvmsg: return "recvmsg";
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
    case __NR_socketpair: return "socketpair";
    case __NR_getsockname: return "getsockname";
    default: return nullptr;
  }
}

static const char* syscall_risk(int nr) {
  // Risk categories aligned with Chrome's syscall_sets.cc classifications
  // CRITICAL: admin, kernel module, debug, filesystem control
  if (nr == __NR_ptrace || nr == __NR_process_vm_readv ||
      nr == __NR_process_vm_writev || nr == __NR_kcmp ||
      nr == __NR_mount || nr == __NR_umount2 || nr == __NR_pivot_root ||
      nr == __NR_chroot || nr == __NR_reboot || nr == __NR_seccomp ||
      nr == __NR_init_module || nr == __NR_finit_module ||
      nr == __NR_delete_module || nr == __NR_swapon || nr == __NR_swapoff ||
      nr == __NR_sethostname || nr == __NR_setdomainname || nr == __NR_syslog)
    return "CRITICAL";
  // HIGH: exec, process creation, networking, privilege changes
  if (nr == __NR_execve || nr == __NR_fork || nr == __NR_vfork ||
      nr == __NR_clone || nr == __NR_unshare || nr == __NR_setns ||
      nr == __NR_socket || nr == __NR_connect || nr == __NR_bind ||
      nr == __NR_listen || nr == __NR_accept || nr == __NR_accept4 ||
      nr == __NR_kill || nr == __NR_tgkill || nr == __NR_tkill ||
      nr == __NR_capset || nr == __NR_setuid || nr == __NR_setgid ||
      nr == __NR_setreuid || nr == __NR_setregid ||
      nr == __NR_setresuid || nr == __NR_setresgid)
    return "HIGH";
  // MEDIUM: filesystem mutation, sending data
  if (nr == __NR_open || nr == __NR_openat || nr == __NR_unlink ||
      nr == __NR_unlinkat || nr == __NR_rename || nr == __NR_renameat ||
      nr == __NR_mkdir || nr == __NR_mkdirat || nr == __NR_rmdir ||
      nr == __NR_chmod || nr == __NR_fchmod || nr == __NR_fchmodat ||
      nr == __NR_chown || nr == __NR_fchownat || nr == __NR_truncate ||
      nr == __NR_sendto || nr == __NR_sendmsg || nr == __NR_recvfrom ||
      nr == __NR_recvmsg || nr == __NR_link || nr == __NR_symlink ||
      nr == __NR_mknod)
    return "MEDIUM";
  return "LOW";
}

// =============================================================================
// Agent sandbox policy: uses Chrome's bpf_dsl to express seccomp rules
// =============================================================================

class AgentSandboxPolicy : public sandbox::bpf_dsl::Policy {
 public:
  explicit AgentSandboxPolicy(SandboxPolicyLevel level)
      : level_(level), policy_pid_(sandbox::sys_getpid()) {
    // Allocate crash keys for Chrome's SIGSYS handler logging
    sandbox::AllocateCrashKeys();
  }

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
  // Block helper: uses SECCOMP_RET_TRACE so the ptrace tracer can see and
  // record blocked syscalls. The tracer skips the syscall by setting
  // orig_rax=-1 and rax=-EPERM.
  // (SECCOMP_RET_ERRNO is invisible to ptrace in gVisor.)
  static ResultExpr Block() { return Trace(EPERM); }

  ResultExpr EvaluateStrict(int sysno) const {
    // ── Use Chrome's SyscallSets for comprehensive classification ────

    // Sendfile: return EPERM (allow fallback to read/write)
    if (sandbox::SyscallSets::IsSendfile(sysno)) {
      return Error(EPERM);
    }

    // Always-allowed: safe syscall categories from Chrome's BaselinePolicy
    if (sandbox::SyscallSets::IsAllowedAddressSpaceAccess(sysno) ||
        sandbox::SyscallSets::IsAllowedBasicScheduler(sysno) ||
        sandbox::SyscallSets::IsAllowedEpoll(sysno) ||
        sandbox::SyscallSets::IsEventFd(sysno) ||
        sandbox::SyscallSets::IsAllowedFileSystemAccessViaFd(sysno) ||
        sandbox::SyscallSets::IsAllowedFutex(sysno) ||
        sandbox::SyscallSets::IsAllowedGeneralIo(sysno) ||
        sandbox::SyscallSets::IsAllowedGettime(sysno) ||
        sandbox::SyscallSets::IsAllowedProcessStartOrDeath(sysno) ||
        sandbox::SyscallSets::IsAllowedSignalHandling(sysno) ||
        sandbox::SyscallSets::IsGetSimpleId(sysno) ||
        sandbox::SyscallSets::IsKernelInternalApi(sysno) ||
        sandbox::SyscallSets::IsAllowedOperationOnFd(sysno)) {
      return Allow();
    }

    // ── uname: always allowed ────────────────────────────────────────
    if (sysno == __NR_uname) return Allow();

    // ── rseq: always allowed (glibc registers it) ────────────────────
#if defined(__NR_rseq)
    if (sysno == __NR_rseq) return Allow();
#endif

    // ── mincore: allowed (used by various libraries) ─────────────────
    if (sysno == __NR_mincore) return Allow();

    // ── PARAMETER RESTRICTIONS (from Chrome's BaselinePolicy) ────────

    // clone: allow threads, EPERM for fork, crash for namespace flags
    if (sysno == __NR_clone) {
      return sandbox::RestrictCloneToThreadsAndEPERMFork();
    }
    // clone3: force libc to use clone (we can inspect clone args)
    if (sysno == __NR_clone3) return Error(ENOSYS);

    // mmap: restrict flags (no MAP_HUGETLB, etc.)
    if (sysno == __NR_mmap) {
      return sandbox::RestrictMmapFlags();
    }

    // mprotect: restrict prot flags
    if (sysno == __NR_mprotect || sysno == __NR_pkey_mprotect) {
      return sandbox::RestrictMprotectFlags();
    }

    // ioctl: only allow TCGETS and FIONREAD
    if (sysno == __NR_ioctl) {
      return sandbox::RestrictIoctl();
    }

    // fcntl: restrict commands
    if (sysno == __NR_fcntl) {
      return sandbox::RestrictFcntlCommands();
    }

    // prctl: restrict operations
    if (sysno == __NR_prctl) {
      return sandbox::RestrictPrctl();
    }

    // futex: block dangerous operations (FUTEX_CMP_REQUEUE_PI etc.)
    if (sysno == __NR_futex) {
      return sandbox::RestrictFutex();
    }

    // clock_gettime/clock_getres/clock_nanosleep: restrict clock IDs
    if (sandbox::SyscallSets::IsClockApi(sysno)) {
      return sandbox::RestrictClockID();
    }

    // getrandom: restrict flags
    if (sysno == __NR_getrandom) {
      return sandbox::RestrictGetRandom();
    }

    // madvise: only safe advice values
    if (sysno == __NR_madvise) {
      const Arg<int> advice(2);
      return sandbox::bpf_dsl::If(
          sandbox::bpf_dsl::AnyOf(
              advice == MADV_DONTNEED, advice == MADV_WILLNEED,
              advice == MADV_RANDOM, advice == MADV_REMOVE,
              advice == MADV_NORMAL
#if defined(MADV_FREE)
              , advice == MADV_FREE
#endif
          ),
          Allow()).Else(Error(EPERM));
    }

    // kill/tgkill: restrict to self only
    if (sandbox::SyscallSets::IsKill(sysno)) {
      return sandbox::RestrictKillTarget(policy_pid_, sysno);
    }

    // getpriority/setpriority: restrict to self
    if (sysno == __NR_getpriority || sysno == __NR_setpriority) {
      return sandbox::RestrictGetSetpriority(policy_pid_);
    }

    // sched_*: restrict to self
    if (sysno == __NR_sched_getaffinity || sysno == __NR_sched_getparam ||
        sysno == __NR_sched_getscheduler || sysno == __NR_sched_setscheduler) {
      return sandbox::RestrictSchedTarget(policy_pid_, sysno);
    }

    // socketpair: only AF_UNIX
    if (sysno == __NR_socketpair) {
      const Arg<int> domain(0);
      return sandbox::bpf_dsl::If(domain == AF_UNIX, Allow()).Else(Block());
    }

    // send flags: restrict MSG_OOB etc.
    if (sandbox::SyscallSets::IsSockSendOneMsg(sysno)) {
      return sandbox::RestrictSockSendFlags(sysno);
    }

    // getsockopt/setsockopt: only SO_PEEK_OFF
    if (sysno == __NR_getsockopt || sysno == __NR_setsockopt) {
      const Arg<int> level(1);
      const Arg<int> optname(2);
      return sandbox::bpf_dsl::If(
          sandbox::bpf_dsl::AllOf(level == SOL_SOCKET, optname == 42),
          Allow()).Else(Block());
    }

    // memfd_create: restrict flags
    if (sysno == __NR_memfd_create) {
      return sandbox::RestrictMemfdCreate();
    }

    // pipe/pipe2: allowed with flag restrictions
#if defined(__NR_pipe)
    if (sysno == __NR_pipe) return Allow();
#endif
    if (sysno == __NR_pipe2) {
      return sandbox::RestrictPipe2();
    }

    // pkey_alloc: restrict flags
    if (sysno == __NR_pkey_alloc) {
      return sandbox::RestrictPkeyAllocFlags();
    }
    if (sysno == __NR_pkey_free) return Allow();

    // set_robust_list: deny (used by futex)
    if (sysno == __NR_set_robust_list) return Error(EPERM);

    // pidfd_open: not supported
    if (sysno == __NR_pidfd_open) return Error(ENOSYS);

    // rt_tgsigqueueinfo: only to self
    if (sysno == __NR_rt_tgsigqueueinfo) {
      const Arg<pid_t> tgid(0);
      return sandbox::bpf_dsl::If(tgid == policy_pid_, Allow())
          .Else(Error(EPERM));
    }

    // ptrace: restrict to safe read-only operations for crash reporting
    if (sysno == __NR_ptrace) {
      return sandbox::RestrictPtrace();
    }

    // getrusage: restrict to self only
    if (sysno == __NR_getrusage) {
      return sandbox::RestrictGetrusage();
    }

    // prlimit64: restrict to self only, no modification
    if (sysno == __NR_prlimit64) {
      return sandbox::RestrictPrlimitToGetrlimit(policy_pid_);
    }

    // fstatat rewrite: glibc rewrites fstat() as fstatat(), handle this
    if (sysno == __NR_fstatat_default) {
      return sandbox::RewriteFstatatSIGSYS(EPERM);
    }

    // statx: return ENOSYS for basic stats (glibc falls back to stat)
    if (sysno == __NR_statx) {
      return Error(ENOSYS);
    }

    // ── BLOCK: Dangerous syscall categories ──────────────────────────

    // Network: block new socket creation (except AF_UNIX)
    if (sysno == __NR_socket) {
      Arg<int> domain(0);
      return sandbox::bpf_dsl::If(domain == AF_UNIX, Allow()).Else(Block());
    }
    if (sysno == __NR_bind || sysno == __NR_listen ||
        sysno == __NR_accept || sysno == __NR_accept4 ||
        sysno == __NR_connect) {
      return Block();
    }

    // Namespace escape
    if (sysno == __NR_unshare || sysno == __NR_setns) {
      return Block();
    }

    // Filesystem access: ALLOW within chroot isolation.
    //
    // Architecture difference from Chrome:
    //   Chrome: blocks IsFileSystem syscalls → SIGSYS handler → broker IPC
    //           → broker validates path against allowlist → returns fd
    //   Us:     exec commands after sandbox setup → SIGSYS handler lost on exec
    //           → filesystem isolation provided by chroot instead:
    //             - read-only bind mounts for /bin, /lib, /usr, /etc
    //             - writable /tmp (tmpfs)
    //             - user-configured allowed paths
    //   Net security effect is equivalent: process can only access
    //   pre-approved paths, system directories are read-only.
    if (sandbox::SyscallSets::IsFileSystem(sysno) ||
        sandbox::SyscallSets::IsCurrentDirectory(sysno)) {
      return Allow();
    }

    // Seccomp reconfiguration
    if (sandbox::SyscallSets::IsSeccomp(sysno)) return Error(EPERM);

    // SystemV IPC
    if (sandbox::SyscallSets::IsAnySystemV(sysno)) return Error(EPERM);

    // Privilege changes
    if (sandbox::SyscallSets::IsProcessPrivilegeChange(sysno)) {
      return Error(EPERM);
    }

    // Umask: block (could weaken file permissions)
    if (sandbox::SyscallSets::IsUmask(sysno)) return Error(EPERM);

    // Fd-based filesystem ops (fchmod, fchown, getdents64, fallocate):
    // Allow within chroot — read-only mounts return EROFS for mutations,
    // getdents64 is needed for directory listing (ls, find, etc.)
    if (sandbox::SyscallSets::IsDeniedFileSystemAccessViaFd(sysno)) {
      return Allow();
    }

    // Socket modifications: block
    if (sandbox::SyscallSets::IsDeniedGetOrModifySocket(sysno)) {
      return Error(EPERM);
    }

    // ── CRASH: Truly dangerous operations ────────────────────────────
    // These are so dangerous that they should crash, not just EPERM.
    // Uses Chrome's SIGSYS handler for logging.
    if (sandbox::SyscallSets::IsAdminOperation(sysno) ||
        sandbox::SyscallSets::IsDebug(sysno) ||
        sandbox::SyscallSets::IsKernelModule(sysno) ||
        sandbox::SyscallSets::IsGlobalFSViewChange(sysno) ||
        sandbox::SyscallSets::IsGlobalProcessEnvironment(sysno)) {
      return sandbox::CrashSIGSYS();
    }

    // Everything else: block with EPERM
    // (Chrome would CrashSIGSYS here, but we prefer observability)
    return Error(EPERM);
  }

  ResultExpr EvaluatePermissive(int sysno) const {
    // Only block truly dangerous operations that could escape the sandbox
    if (sysno == __NR_ptrace || sysno == __NR_process_vm_readv ||
        sysno == __NR_process_vm_writev) {
      return Block();
    }
    if (sysno == __NR_mount || sysno == __NR_umount2 ||
        sysno == __NR_chroot || sysno == __NR_pivot_root) {
      return Block();
    }
    if (sysno == __NR_reboot || sysno == __NR_init_module ||
        sysno == __NR_finit_module || sysno == __NR_delete_module) {
      return Block();
    }
    if (sysno == __NR_capset || sysno == __NR_setuid ||
        sysno == __NR_setgid) {
      return Block();
    }
    return Allow();
  }

  SandboxPolicyLevel level_;
  pid_t policy_pid_;
};

// =============================================================================
// Global state
// =============================================================================

static SandboxPolicyLevel g_policy_level = SANDBOX_POLICY_STRICT;
static std::vector<std::string> g_allowed_paths;
static bool g_initialized = false;

// Broker process (Chrome's real BrokerProcess)
static std::unique_ptr<sandbox::syscall_broker::BrokerProcess> g_broker;

// =============================================================================
// Ptrace-based syscall tracer
// =============================================================================

struct SyscallRecord {
  int nr;
  const char* name;
  const char* risk;
  bool blocked;
  std::string path;  // Resolved path for file-related syscalls
  long args[6];
};

// Escape a string for JSON output
static std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20)
          continue;  // skip other control chars
        out += c;
    }
  }
  return out;
}

static std::string build_syscall_log_json(
    const std::vector<SyscallRecord>& records) {
  std::ostringstream json;
  json << "[";
  for (size_t i = 0; i < records.size(); i++) {
    if (i > 0) json << ",";
    json << "{\"nr\":" << records[i].nr;
    json << ",\"name\":\"" << (records[i].name ? records[i].name : "unknown") << "\"";
    json << ",\"risk\":\"" << records[i].risk << "\"";
    json << ",\"blocked\":" << (records[i].blocked ? "true" : "false");
    if (!records[i].path.empty()) {
      json << ",\"path\":\"" << json_escape(records[i].path) << "\"";
    }
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
  if (addr == 0) return "";
  char proc_path[64];
  snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", pid);
  int fd = open(proc_path, O_RDONLY);
  if (fd < 0) return "";
  char buf[256];
  if (maxlen > sizeof(buf)) maxlen = sizeof(buf);
  ssize_t n = pread(fd, buf, maxlen, addr);
  close(fd);
  if (n <= 0) return "";
  for (ssize_t i = 0; i < n; i++) {
    if (buf[i] == '\0') return std::string(buf, i);
  }
  return std::string(buf, n);
}

// =============================================================================
// Layer 1: Namespace isolation (mirrors Chrome's Credentials::MoveToNewUserNS)
// =============================================================================
//
// Chrome's actual sequence (from credentials.cc + namespace_sandbox.cc):
//   1. unshare(CLONE_NEWUSER) to enter a new user namespace
//   2. DenySetgroups() + WriteToIdMapFile() to set up uid/gid maps
//   3. unshare(CLONE_NEWPID) for PID namespace isolation
//   4. unshare(CLONE_NEWNET) for network namespace isolation
//
// We use Chrome's extracted NamespaceUtils and syscall_wrappers directly.

static bool g_enable_namespaces = true;

// Set up user namespace and map current uid/gid.
// Returns true on success, false if namespaces unavailable (non-fatal).
static bool setup_user_namespace() {
  uid_t uid = getuid();
  gid_t gid = getgid();

  // unshare(CLONE_NEWUSER) — this is what Chrome's MoveToNewUserNS() does
  if (sandbox::sys_unshare(CLONE_NEWUSER) != 0) {
    // Not fatal: kernel may not support unprivileged user namespaces.
    // The seccomp-BPF layer still provides protection.
    return false;
  }

  // Write uid/gid maps using Chrome's NamespaceUtils (async-signal-safe)
  // This mirrors Chrome's Credentials::SetGidAndUidMaps()
  if (sandbox::NamespaceUtils::KernelSupportsDenySetgroups()) {
    if (!sandbox::NamespaceUtils::DenySetgroups()) {
      return false;
    }
  }
  if (!sandbox::NamespaceUtils::WriteToIdMapFile("/proc/self/gid_map", gid) ||
      !sandbox::NamespaceUtils::WriteToIdMapFile("/proc/self/uid_map", uid)) {
    return false;
  }

  return true;
}

// Set up PID namespace. After this, fork()ed children see PID 1.
// NOTE: The calling process itself stays in the old PID namespace;
// only its children will be in the new one. A subsequent fork()
// creates a child that IS PID 1 in the new namespace.
static bool setup_pid_namespace() {
  return sandbox::sys_unshare(CLONE_NEWPID) == 0;
}

// Set up IPC namespace. Isolates System V IPC objects and POSIX
// message queues so the sandboxed process can't interact with
// the host's IPC objects.
static bool setup_ipc_namespace() {
  return sandbox::sys_unshare(CLONE_NEWIPC) == 0;
}

// Set up network namespace. This gives the process an empty network
// stack — no interfaces except loopback, which starts DOWN.
// This is Chrome's CLONE_NEWNET from namespace_sandbox.cc.
static bool setup_net_namespace() {
  return sandbox::sys_unshare(CLONE_NEWNET) == 0;
}

// =============================================================================
// Layer 2: Filesystem isolation (mirrors Chrome's DropFileSystemAccess)
// =============================================================================
//
// Chrome's approach (credentials.cc):
//   1. Clone a helper process with CLONE_FS
//   2. Helper does chroot("/proc/self/fdinfo/") then exits
//   3. Since the process died, that /proc path vanishes → empty root
//
// We use a simpler but equally secure approach for our use case:
//   1. Mount a tmpfs at a temporary location (if in mount namespace)
//   2. Or use /proc/self/fdinfo/ trick like Chrome
//   3. chroot into it, chdir to "/"
//
// For execve to work, we need the target binary accessible. So we
// use a mount namespace with a minimal bind-mounted root instead
// of a fully empty chroot. The seccomp-BPF layer prevents escape.

static bool setup_mount_namespace() {
  // Enter a new mount namespace so our mounts don't affect the host
  if (sandbox::sys_unshare(CLONE_NEWNS) != 0) {
    return false;
  }

  // Make all mounts private so changes don't propagate to the host.
  // This is equivalent to what Chrome does before setting up the sandbox.
  if (mount("none", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
    return false;
  }

  return true;
}

// =============================================================================
// Filesystem isolation via chroot with minimal bind mounts
// =============================================================================
//
// Creates a minimal root filesystem with only essential directories
// bind-mounted read-only, then pivot_root into it. This prevents the
// sandboxed process from reading sensitive host files (/etc/shadow,
// /root/.ssh/, etc.) even if seccomp-BPF has a bug.
//
// The resulting filesystem contains:
//   /bin, /sbin, /lib, /lib64, /usr  (read-only, from host)
//   /proc                             (fresh mount, PID-namespaced)
//   /dev/null, /dev/urandom, /dev/zero (minimal devices)
//   /tmp                              (private tmpfs)
//   /etc                              (read-only from host)
//   + any user-configured allowed paths

static bool bind_mount_readonly(const char* src, const char* dst) {
  // Step 1: bind mount
  if (mount(src, dst, nullptr, MS_BIND | MS_REC, nullptr) != 0)
    return false;
  // Step 2: remount read-only
  if (mount(nullptr, dst, nullptr,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, nullptr) != 0)
    return false;
  return true;
}

static bool setup_chroot_filesystem() {
  // Create a temporary directory for our new root
  char sandbox_root[] = "/tmp/.sandbox_root_XXXXXX";
  if (mkdtemp(sandbox_root) == nullptr)
    return false;

  // Mount a tmpfs as our new root
  if (mount("tmpfs", sandbox_root, "tmpfs",
            MS_NOSUID | MS_NODEV, "size=64m,mode=0755") != 0) {
    rmdir(sandbox_root);
    return false;
  }

  // Create essential directories in new root
  const char* dirs[] = {
    "bin", "sbin", "lib", "lib64", "usr", "etc",
    "proc", "dev", "tmp", "var", "run",
    nullptr
  };
  char path[512];
  for (int i = 0; dirs[i]; i++) {
    snprintf(path, sizeof(path), "%s/%s", sandbox_root, dirs[i]);
    mkdir(path, 0755);
  }

  // Bind-mount essential host directories (read-only)
  struct { const char* src; const char* subdir; } ro_mounts[] = {
    {"/bin",   "bin"},
    {"/sbin",  "sbin"},
    {"/lib",   "lib"},
    {"/lib64", "lib64"},
    {"/usr",   "usr"},
    {"/etc",   "etc"},
    {nullptr, nullptr}
  };

  for (int i = 0; ro_mounts[i].src; i++) {
    struct stat st;
    if (stat(ro_mounts[i].src, &st) != 0) continue;  // Skip if doesn't exist
    snprintf(path, sizeof(path), "%s/%s", sandbox_root, ro_mounts[i].subdir);
    bind_mount_readonly(ro_mounts[i].src, path);
  }

  // Bind-mount user-configured allowed paths (read-write)
  for (const auto& allowed : g_allowed_paths) {
    if (allowed.empty() || allowed[0] != '/') continue;
    // Create the mount point in new root
    snprintf(path, sizeof(path), "%s%s", sandbox_root, allowed.c_str());
    // Create parent directories
    std::string parent = path;
    for (size_t j = 1; j < parent.size(); j++) {
      if (parent[j] == '/') {
        parent[j] = '\0';
        mkdir(parent.c_str(), 0755);
        parent[j] = '/';
      }
    }
    mkdir(path, 0755);
    mount(allowed.c_str(), path, nullptr, MS_BIND | MS_REC, nullptr);
  }

  // Mount minimal /dev entries
  snprintf(path, sizeof(path), "%s/dev/null", sandbox_root);
  close(open(path, O_WRONLY | O_CREAT, 0666));
  mount("/dev/null", path, nullptr, MS_BIND, nullptr);

  snprintf(path, sizeof(path), "%s/dev/urandom", sandbox_root);
  close(open(path, O_WRONLY | O_CREAT, 0444));
  mount("/dev/urandom", path, nullptr, MS_BIND, nullptr);

  snprintf(path, sizeof(path), "%s/dev/zero", sandbox_root);
  close(open(path, O_WRONLY | O_CREAT, 0666));
  mount("/dev/zero", path, nullptr, MS_BIND, nullptr);

  // Mount a private tmpfs for /tmp in new root
  snprintf(path, sizeof(path), "%s/tmp", sandbox_root);
  mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "size=32m,mode=1777");

  // pivot_root: switch the root filesystem
  // Create a directory for the old root
  snprintf(path, sizeof(path), "%s/.old_root", sandbox_root);
  mkdir(path, 0700);

  // pivot_root requires both paths to be mount points
  if (syscall(SYS_pivot_root, sandbox_root, path) != 0) {
    // pivot_root failed — fall back to chroot
    if (chroot(sandbox_root) != 0)
      return false;
    if (chdir("/") != 0)
      return false;
    return true;
  }

  // Successfully pivoted — unmount and remove old root
  if (umount2("/.old_root", MNT_DETACH) == 0) {
    rmdir("/.old_root");
  }

  // chdir to new root
  if (chdir("/") != 0)
    return false;

  return true;
}

// =============================================================================
// Layer 3: Drop capabilities (mirrors Chrome's DropAllCapabilities)
// =============================================================================
//
// Uses Chrome's sys_capset() wrapper from syscall_wrappers.cc.
// After entering a user namespace we get a full capability set in
// that namespace. We drop everything so the sandboxed process can't
// use CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_NET_ADMIN, etc.

static bool drop_all_capabilities() {
  struct cap_hdr hdr = {};
  hdr.version = _LINUX_CAPABILITY_VERSION_3;
  struct cap_data data[_LINUX_CAPABILITY_U32S_3] = {};
  // All zeros = no capabilities
  return sandbox::sys_capset(&hdr, data) == 0;
}

// =============================================================================
// Apply all namespace isolation layers
// =============================================================================
//
// This is called in the child process before seccomp-BPF installation.
// The order matches Chrome's sandbox initialization sequence:
//   1. User namespace (to get privileges for subsequent namespace ops)
//   2. PID namespace (isolate process tree)
//   3. Network namespace (isolate network)
//   4. Mount namespace (isolate filesystem view)
//   5. Drop capabilities (remove privileges granted by user namespace)
//   6. (Then seccomp-BPF is installed separately)

struct NamespaceStatus {
  bool user_ns;
  bool pid_ns;
  bool ipc_ns;
  bool net_ns;
  bool mount_ns;
  bool caps_dropped;
};

static NamespaceStatus apply_namespace_isolation() {
  NamespaceStatus status = {};

  if (!g_enable_namespaces) {
    return status;
  }

  // Layer 1a: User namespace first (gives us caps for the rest)
  status.user_ns = setup_user_namespace();
  if (!status.user_ns) {
    // If user namespaces aren't available, the other namespace
    // operations will also fail. Fall back to seccomp-BPF only.
    return status;
  }

  // Layer 1b: PID namespace
  // unshare(CLONE_NEWPID) makes our CHILDREN enter a new PID namespace.
  // We must fork() after this; the child becomes PID 1 in the new namespace.
  // The fork happens in exec_with_tracing() after apply_namespace_isolation().
  status.pid_ns = setup_pid_namespace();

  // Layer 1c: IPC namespace (isolates System V IPC + POSIX mqueues)
  status.ipc_ns = setup_ipc_namespace();

  // Layer 1d: Network namespace
  status.net_ns = setup_net_namespace();

  // Layer 2: Mount namespace for filesystem isolation
  status.mount_ns = setup_mount_namespace();

  // Layer 2b: Chroot filesystem isolation
  // Must be done after mount namespace (so bind mounts are private)
  // and before dropping capabilities (needs CAP_SYS_ADMIN for mount/pivot_root)
  if (status.mount_ns) {
    setup_chroot_filesystem();
  }

  // Layer 3: Drop all capabilities
  // After user namespace setup, we have full caps in the new namespace.
  // Drop them all — we don't need any for executing commands.
  // NOTE: We must do this AFTER mount namespace setup (which needs
  // CAP_SYS_ADMIN) but BEFORE seccomp-BPF installation.
  status.caps_dropped = drop_all_capabilities();

  // Layer 4: Process hardening
  // Disable core dumps (prevents leaking process memory)
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  // Disable core file generation
  struct rlimit no_core = {0, 0};
  setrlimit(RLIMIT_CORE, &no_core);

  // Yama ptrace restrictions: restrict ptrace to ancestors only.
  // This prevents other processes (even as same user) from ptracing us.
  sandbox::Yama::RestrictPtracersToAncestors();

  // Resource limits: prevent excessive memory allocation (heap spray defense)
  // Chrome's renderer uses ~32GB limit; we use 16GB for general sandboxing.
  static constexpr rlim_t kDataLimit = 16ULL * 1024 * 1024 * 1024;  // 16 GB
  (void)sandbox::ResourceLimits::Lower(RLIMIT_DATA, kDataLimit);

  return status;
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

    // === LAYER 1-5: Namespace isolation ===
    // Apply namespace isolation before seccomp-BPF.
    // This mirrors Chrome's defense-in-depth: even if BPF has a bug,
    // namespace isolation constrains what the process can reach.
    // Order: user NS → PID NS → IPC NS → net NS → mount NS → drop caps
    NamespaceStatus ns_status = apply_namespace_isolation();

    // === LAYER 2: PID namespace fork ===
    // After unshare(CLONE_NEWPID), our children enter a new PID namespace.
    // We fork here: the child becomes PID 1 in the new namespace.
    // The parent (this process) becomes a simple init reaper.
    // The ptrace tracer (grandparent) auto-traces the grandchild via
    // PTRACE_O_TRACEFORK.
    if (ns_status.pid_ns) {
      pid_t ns_child = fork();
      if (ns_child < 0) {
        _exit(125);  // Fork failed
      }
      if (ns_child > 0) {
        // Original child becomes init reaper for PID namespace.
        // Wait for the namespace child and exit with its status.
        int reaper_status;
        while (waitpid(ns_child, &reaper_status, 0) < 0 && errno == EINTR) {}
        _exit(WIFEXITED(reaper_status) ? WEXITSTATUS(reaper_status) : 1);
      }
      // Grandchild: PID 1 in new PID namespace.
      // Remount /proc to reflect the new PID namespace.
      // This ensures /proc only shows processes in our namespace.
      mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
            nullptr);
    }

    // === LAYER 6: seccomp-BPF ===
    // Install Chrome's seccomp-BPF sandbox using the actual Chromium code.
    // This is the innermost layer and filters every syscall.
    auto policy = std::make_unique<AgentSandboxPolicy>(g_policy_level);
    sandbox::SandboxBPF sandbox_bpf(std::move(policy));
    if (!sandbox_bpf.StartSandbox(sandbox::SandboxBPF::SeccompLevel::SINGLE_THREADED)) {
      _exit(126);
    }

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

  // ALWAYS use PTRACE_SYSCALL so we trace every syscall regardless of policy.
  // Chrome's seccomp-BPF filter still enforces the policy at the kernel level
  // (blocking dangerous syscalls via SECCOMP_RET_ERRNO), but ptrace gives us
  // independent visibility. These are two separate kernel mechanisms:
  //   - seccomp-BPF: enforces policy (block/allow/trap)
  //   - ptrace(PTRACE_SYSCALL): observes syscalls for tracing/analysis
  ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);

  // Trace loop
  std::vector<SyscallRecord> records;
  std::set<pid_t> traced_pids = {child};
  // Track syscall entry→exit per pid: maps pid → index into records[]
  std::map<pid_t, size_t> pending_entry;
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
      pending_entry.erase(pid);
      continue;
    }

    if (!WIFSTOPPED(wstatus)) continue;

    int sig = WSTOPSIG(wstatus);
    int event = (wstatus >> 16) & 0xFF;

    if (event == PTRACE_EVENT_SECCOMP) {
      // SECCOMP_RET_TRACE: seccomp-BPF flagged this syscall for tracer
      // decision. Our policy uses Trace(EPERM) for blocked syscalls, so
      // the data field contains EPERM (1).
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        // Record the blocked syscall
        SyscallRecord rec;
        rec.nr = (int)regs.orig_rax;
        rec.name = syscall_name(rec.nr);
        rec.risk = syscall_risk(rec.nr);
        rec.blocked = true;  // This was flagged by seccomp for blocking
        rec.args[0] = regs.rdi;
        rec.args[1] = regs.rsi;
        rec.args[2] = regs.rdx;
        rec.args[3] = regs.r10;
        rec.args[4] = regs.r8;
        rec.args[5] = regs.r9;

        // Read path for file-related blocked syscalls
        if (rec.nr == __NR_openat || rec.nr == __NR_faccessat ||
            rec.nr == __NR_newfstatat || rec.nr == __NR_mkdirat ||
            rec.nr == __NR_unlinkat) {
          rec.path = read_child_string(pid, regs.rsi);
        } else if (rec.nr == __NR_open || rec.nr == __NR_access ||
                   rec.nr == __NR_execve) {
          rec.path = read_child_string(pid, regs.rdi);
        }

        records.push_back(rec);
        blocked++;

        // Skip the syscall by setting orig_rax to -1 (invalid syscall nr).
        // The kernel will return -ENOSYS. To return -EPERM instead, we
        // also set rax to -EPERM so the child sees the right errno.
        regs.orig_rax = -1;  // Skip the syscall
        regs.rax = -EPERM;   // Child sees EPERM
        ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
      }
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_FORK ||
               event == PTRACE_EVENT_VFORK ||
               event == PTRACE_EVENT_CLONE) {
      unsigned long new_pid;
      ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
      traced_pids.insert(static_cast<pid_t>(new_pid));
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_EXEC ||
               event == PTRACE_EVENT_EXIT) {
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (sig == (SIGTRAP | 0x80)) {
      // Syscall-stop from PTRACE_SYSCALL: fires on entry AND exit.
      // On x86_64, the kernel sets rax = -ENOSYS on entry (before the syscall
      // executes). On exit, rax contains the return value. We use this to
      // distinguish entry from exit without a toggle (which desyncs in gVisor
      // when seccomp-blocked syscalls don't generate exit-stops).
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        long long rax_val = (long long)regs.rax;
        int nr = (int)regs.orig_rax;
        bool is_entry = (rax_val == -ENOSYS);

        if (is_entry) {
          // === SYSCALL ENTRY ===
          SyscallRecord rec;
          rec.nr = nr;
          rec.name = syscall_name(rec.nr);
          rec.risk = syscall_risk(rec.nr);
          rec.blocked = false;
          rec.args[0] = regs.rdi;
          rec.args[1] = regs.rsi;
          rec.args[2] = regs.rdx;
          rec.args[3] = regs.r10;
          rec.args[4] = regs.r8;
          rec.args[5] = regs.r9;

          // For file-related syscalls, read the path from child memory
          if (rec.nr == __NR_openat || rec.nr == __NR_faccessat ||
              rec.nr == __NR_newfstatat || rec.nr == __NR_mkdirat ||
              rec.nr == __NR_unlinkat || rec.nr == __NR_fchmodat ||
              rec.nr == __NR_readlinkat || rec.nr == __NR_renameat) {
            rec.path = read_child_string(pid, regs.rsi);
          } else if (rec.nr == __NR_open || rec.nr == __NR_access ||
                     rec.nr == __NR_stat || rec.nr == __NR_lstat ||
                     rec.nr == __NR_execve || rec.nr == __NR_unlink ||
                     rec.nr == __NR_mkdir || rec.nr == __NR_rmdir ||
                     rec.nr == __NR_chmod || rec.nr == __NR_chown ||
                     rec.nr == __NR_chdir || rec.nr == __NR_truncate) {
            rec.path = read_child_string(pid, regs.rdi);
          }

          records.push_back(rec);
          // Track this entry so we can match the exit
          pending_entry[pid] = records.size() - 1;
        } else {
          // === SYSCALL EXIT ===
          long retval = (long)rax_val;
          auto it = pending_entry.find(pid);
          if (it != pending_entry.end()) {
            size_t entry_idx = it->second;
            pending_entry.erase(it);

            // Check if seccomp-BPF blocked this syscall (returned -EPERM)
            if (retval == -EPERM && entry_idx < records.size()) {
              records[entry_idx].blocked = true;
              blocked++;
            }
          }
        }
      }
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (sig == SIGTRAP) {
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    } else if (sig == SIGSTOP) {
      // Suppress SIGSTOP for auto-traced children (from PTRACE_O_TRACEFORK).
      // The kernel delivers SIGSTOP when a new child starts being traced.
      // Delivering it would stop the child permanently.
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    } else {
      // Deliver signal to child
      ptrace(PTRACE_SYSCALL, pid, nullptr, sig);
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
// Broker implementation using Chrome's real BrokerProcess
// =============================================================================

static std::vector<sandbox::syscall_broker::BrokerFilePermission>
build_broker_permissions() {
  using sandbox::syscall_broker::BrokerFilePermission;
  std::vector<BrokerFilePermission> perms;

  // Always allow read access to essential system paths
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/lib"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/usr/lib"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/etc"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/proc"));

  // Add user-configured paths with full access
  for (const auto& path : g_allowed_paths) {
    if (!path.empty() && path[0] == '/') {
      perms.push_back(BrokerFilePermission::ReadWriteCreateRecursive(path));
    }
  }

  return perms;
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
  g_broker.reset();
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

void sandbox_set_namespaces_enabled(int enabled) {
  g_enable_namespaces = (enabled != 0);
}

int sandbox_get_namespaces_enabled(void) {
  return g_enable_namespaces ? 1 : 0;
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
  using namespace sandbox::syscall_broker;

  auto perms = build_broker_permissions();

  // Build the broker config using Chrome's real BrokerSandboxConfig
  BrokerCommandSet commands = MakeBrokerCommandSet({
      COMMAND_OPEN, COMMAND_ACCESS, COMMAND_STAT, COMMAND_STAT64,
      COMMAND_READLINK, COMMAND_MKDIR, COMMAND_UNLINK, COMMAND_RMDIR,
      COMMAND_RENAME});

  BrokerSandboxConfig config(commands, std::move(perms), EACCES);

  g_broker = std::make_unique<BrokerProcess>(
      std::move(config), BrokerProcess::BrokerType::SIGNAL_BASED);

  // Fork the broker process (this actually forks!)
  if (!g_broker->Fork(base::OnceCallback<bool(const BrokerSandboxConfig&)>())) {
    g_broker.reset();
    return -1;
  }

  return g_broker->broker_pid();
}

void sandbox_stop_broker(void) {
  if (g_broker) {
    int pid = g_broker->broker_pid();
    g_broker.reset();
    if (pid > 0) {
      kill(pid, SIGTERM);
      waitpid(pid, nullptr, 0);
    }
  }
}

}  // extern "C"
