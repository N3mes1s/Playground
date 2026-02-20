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
// Layer 1: Namespace isolation (user, PID, IPC, network, mount) via unshare(2)
// Layer 2: Filesystem isolation via chroot(2)/pivot_root with bind mounts
// Layer 3: Capability dropping via capset(2)
// Layer 4: Process hardening (PR_SET_DUMPABLE, RLIMIT_CORE, Yama, RLIMIT_DATA)
// Layer 5: seccomp-BPF syscall filtering via Chrome's SandboxBPF
// Layer 6: Ptrace-based filesystem broker (validates paths via BrokerPermissionList)
//          Equivalent to Chrome's SIGSYS-based broker but survives execve()

#include "harness/sandbox_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <asm/prctl.h>
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
#include <sys/ioctl.h>
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
#include <cstdarg>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
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
#include "sandbox/linux/syscall_broker/broker_permission_list.h"
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
    case __NR_execveat: return "execveat";
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
    case __NR_fadvise64: return "fadvise64";
    case __NR_statfs: return "statfs";
    case __NR_fstatfs: return "fstatfs";
    case __NR_readlink: return "readlink";
    case __NR_symlink: return "symlink";
    case __NR_symlinkat: return "symlinkat";
    case __NR_link: return "link";
    case __NR_linkat: return "linkat";
    case __NR_mknod: return "mknod";
    case __NR_lchown: return "lchown";
    case __NR_fchownat: return "fchownat";
    case __NR_creat: return "creat";
    case __NR_renameat2: return "renameat2";
    case __NR_faccessat2: return "faccessat2";
    case __NR_tkill: return "tkill";
    case __NR_accept4: return "accept4";
    case __NR_dup: return "dup";
    case __NR_shutdown: return "shutdown";
    case __NR_select: return "select";
    case __NR_pselect6: return "pselect6";
    case __NR_ppoll: return "ppoll";
    case __NR_eventfd2: return "eventfd2";
    case __NR_timerfd_create: return "timerfd_create";
    case __NR_timerfd_settime: return "timerfd_settime";
    case __NR_signalfd4: return "signalfd4";
    case __NR_inotify_init1: return "inotify_init1";
    case __NR_inotify_add_watch: return "inotify_add_watch";
    case __NR_inotify_rm_watch: return "inotify_rm_watch";
    case __NR_clone3: return "clone3";
    case __NR_memfd_create: return "memfd_create";
    case __NR_copy_file_range: return "copy_file_range";
    case __NR_pread64: return "pread64";
    case __NR_pwrite64: return "pwrite64";
    case __NR_sendfile: return "sendfile";
    case __NR_fchmod: return "fchmod";
    case __NR_fchown: return "fchown";
    case __NR_utimensat: return "utimensat";
    case __NR_fallocate: return "fallocate";
    case __NR_fdatasync: return "fdatasync";
    case __NR_waitid: return "waitid";
    case __NR_capget: return "capget";
    case __NR_capset: return "capset";
    case __NR_setuid: return "setuid";
    case __NR_setgid: return "setgid";
    case __NR_setresuid: return "setresuid";
    case __NR_setresgid: return "setresgid";
    case __NR_getresuid: return "getresuid";
    case __NR_getresgid: return "getresgid";
    case __NR_unshare: return "unshare";
    case __NR_setns: return "setns";
    case __NR_pivot_root: return "pivot_root";
    case __NR_init_module: return "init_module";
    case __NR_delete_module: return "delete_module";
    case __NR_process_vm_readv: return "process_vm_readv";
    case __NR_process_vm_writev: return "process_vm_writev";
    case __NR_sethostname: return "sethostname";
    case __NR_setdomainname: return "setdomainname";
    case __NR_swapon: return "swapon";
    case __NR_swapoff: return "swapoff";
    case __NR_syslog: return "syslog";
    case __NR_kcmp: return "kcmp";
    case __NR_setreuid: return "setreuid";
    case __NR_setregid: return "setregid";
    case __NR_fchdir: return "fchdir";
    case __NR_mremap: return "mremap";
    case __NR_msync: return "msync";
    case __NR_mincore: return "mincore";
    case __NR_shmget: return "shmget";
    case __NR_shmat: return "shmat";
    case __NR_shmctl: return "shmctl";
    case __NR_semget: return "semget";
    case __NR_semop: return "semop";
    case __NR_semctl: return "semctl";
    case __NR_msgget: return "msgget";
    case __NR_msgsnd: return "msgsnd";
    case __NR_msgrcv: return "msgrcv";
    case __NR_msgctl: return "msgctl";
    default: {
      // Return a static buffer with the numeric syscall number.
      // Thread-safe: uses thread-local storage.
      static thread_local char unknown_buf[32];
      snprintf(unknown_buf, sizeof(unknown_buf), "syscall_%d", nr);
      return unknown_buf;
    }
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
  AgentSandboxPolicy(SandboxPolicyLevel level,
                     std::set<unsigned long> extra_ioctls,
                     std::set<int> extra_sockopts,
                     bool allow_networking)
      : level_(level), policy_pid_(sandbox::sys_getpid()),
        extra_ioctls_(std::move(extra_ioctls)),
        extra_sockopts_(std::move(extra_sockopts)),
        allow_networking_(allow_networking) {
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

 public:
  // Trace data values for SECCOMP_RET_TRACE.
  // PTRACE_GETEVENTMSG returns these so the tracer can distinguish actions.
  static constexpr uint16_t TRACE_BLOCKED = 1;  // Always block (skip + EPERM)
  static constexpr uint16_t TRACE_BROKER  = 2;  // Broker: validate path first

 private:

  // Block helper: uses SECCOMP_RET_TRACE so the ptrace tracer can see and
  // record blocked syscalls. The tracer skips the syscall by setting
  // orig_rax=-1 and rax=-EPERM.
  // (SECCOMP_RET_ERRNO is invisible to ptrace in gVisor.)
  static ResultExpr Block() { return Trace(TRACE_BLOCKED); }

  // Broker helper: routes filesystem syscalls to the ptrace tracer which
  // validates paths against BrokerPermissionList before allowing/denying.
  // This is architecturally equivalent to Chrome's SIGSYS-based broker but
  // survives execve() because ptrace operates from the parent process.
  static ResultExpr Broker() { return Trace(TRACE_BROKER); }

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

    // ── set_tid_address: allowed (glibc TLS/thread setup after exec) ──
    if (sysno == __NR_set_tid_address) return Allow();

    // ── mincore: allowed (used by various libraries) ─────────────────
    if (sysno == __NR_mincore) return Allow();

    // ── PARAMETER RESTRICTIONS (from Chrome's BaselinePolicy) ────────

    // clone/fork/vfork: allow process creation, block namespace flags.
    // Chrome blocks fork (renderers use zygote), but we exec a shell that
    // needs fork to run external commands. The child is fully confined by
    // namespaces + seccomp + ptrace, so forking is safe.
    if (sysno == __NR_clone) {
      const Arg<unsigned long> flags(0);
      const unsigned long kDangerousCloneFlags =
          CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
          CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS;
      return sandbox::bpf_dsl::If(
          (flags & kDangerousCloneFlags) == 0, Allow())
          .Else(Error(EPERM));
    }
    // clone3: force libc to use clone (we can inspect clone args)
    if (sysno == __NR_clone3) return Error(ENOSYS);
#if !defined(__aarch64__)
    if (sysno == __NR_fork) return Allow();
#endif
#if !defined(__mips__) && !defined(__aarch64__)
    if (sysno == __NR_vfork) return Allow();
#endif

    // mmap: restrict flags (no MAP_HUGETLB, etc.)
    if (sysno == __NR_mmap) {
      return sandbox::RestrictMmapFlags();
    }

    // mprotect: restrict prot flags
    if (sysno == __NR_mprotect || sysno == __NR_pkey_mprotect) {
      return sandbox::RestrictMprotectFlags();
    }

    // ioctl: Chrome's default allows only TCGETS and FIONREAD.
    // We also allow FIOCLEX/FIONCLEX (set/clear close-on-exec via ioctl)
    // because glibc and runtimes use these during file operations.
    // Without FIOCLEX, Python can't open script files (fopen uses it
    // internally to set O_CLOEXEC when openat2 returns ENOSYS).
    // Additional ioctl commands can be allowed at runtime via
    // sandbox_allow_ioctls() for runtimes that need them.
    if (sysno == __NR_ioctl) {
      const Arg<unsigned long> request(1);
      // Chrome's allowlist + FIOCLEX/FIONCLEX for close-on-exec
      // + FIONBIO for non-blocking mode (used by Python socket.settimeout
      // and Node.js net.connect — safe, only affects I/O blocking behavior)
      ResultExpr result = Switch(request)
          .Cases({TCGETS, FIONREAD, FIOCLEX, FIONCLEX, FIONBIO}, Allow())
          .Default(Block());
      // Layer on runtime-configured extensions (additive only)
      for (unsigned long cmd : extra_ioctls_) {
        result = sandbox::bpf_dsl::If(request == cmd, Allow())
            .Else(std::move(result));
      }
      return result;
    }

    // fcntl: restrict commands
    if (sysno == __NR_fcntl) {
      return sandbox::RestrictFcntlCommands();
    }

    // prctl: restrict operations
    if (sysno == __NR_prctl) {
      return sandbox::RestrictPrctl();
    }

    // arch_prctl: allow ARCH_SET_FS/ARCH_SET_GS (TLS setup, critical for glibc)
#if defined(__x86_64__)
    if (sysno == __NR_arch_prctl) {
      const Arg<int> code(0);
      return sandbox::bpf_dsl::If(
          sandbox::bpf_dsl::AnyOf(code == ARCH_SET_FS, code == ARCH_SET_GS),
          Allow()).Else(Error(EPERM));
    }
#endif

    // futex: block dangerous operations (FUTEX_CMP_REQUEUE_PI etc.)
    if (sysno == __NR_futex) {
      return sandbox::RestrictFutex();
    }

    // clock_gettime/clock_nanosleep: restrict clock IDs
    if (sandbox::SyscallSets::IsClockApi(sysno)) {
      return sandbox::RestrictClockID();
    }

    // clock_getres: restrict clock IDs (same as clock_gettime).
    // Chrome's IsClockApi() excludes clock_getres on non-Android, but
    // runtimes (Python, Java, Go) call it during initialization to query
    // timer precision. Read-only, returns a single timespec — no risk.
    if (sysno == __NR_clock_getres) {
      return sandbox::RestrictClockID();
    }

    // timerfd_create: allow (creates a timer file descriptor).
    // Event loops (libuv, tokio, asyncio) need this for timer notifications.
    // Creates a local FD only — no privilege escalation, no info leak.
    // Resource exhaustion bounded by RLIMIT_NOFILE.
    if (sysno == __NR_timerfd_create) return Allow();
    // timerfd_settime/timerfd_gettime: operate on existing timer FDs.
    // Safe — equivalent to read/write on an already-opened FD.
    if (sysno == __NR_timerfd_settime || sysno == __NR_timerfd_gettime) {
      return Allow();
    }

    // sysinfo: allow (returns total/free RAM, uptime, process count).
    // Used by Node.js and Bun for os.totalmem()/os.freemem() and GC
    // heap sizing. Returns only system-wide metrics, no per-process
    // data. Not an info leak risk in a sandbox context.
    if (sysno == __NR_sysinfo) return Allow();

    // pwrite64: allow (positional write to an already-opened FD).
    // Essential for SQLite — writes database pages at specific offsets.
    // Same security model as write() — operates on an existing FD,
    // no new file access. Chrome's baseline omits it because Chrome
    // doesn't use SQLite from sandboxed renderers, but it's safe.
    if (sysno == __NR_pwrite64) return Allow();

    // fsync/fdatasync: allow (flush file buffers to disk).
    // Essential for SQLite — commits transactions durably. Without
    // these, SQLite returns "disk I/O error" on any write operation.
    // Operates on existing FDs only. No path access, no privilege
    // escalation. Chrome omits these because its renderer doesn't
    // do durable writes, but any tool using SQLite needs them.
    if (sysno == __NR_fsync || sysno == __NR_fdatasync) return Allow();

    // rt_sigsuspend: allow (atomically replaces signal mask and waits).
    // Used by Bun/Node.js for signal handling in async runtimes.
    // Only affects the calling thread's signal mask — no privilege
    // escalation, no cross-process effect.
    if (sysno == __NR_rt_sigsuspend) return Allow();

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

    // kill/tgkill/tkill: route through ptrace broker.
    // Chrome's RestrictKillTarget(policy_pid_) hardcodes the PID at filter
    // install time, but children inherit the filter with the wrong PID constant
    // — allowing them to kill PID 1 (the namespace init), tearing down the
    // entire PID namespace. We use Trace(TRACE_BROKER) instead so the ptrace
    // broker can check the target PID at runtime.
    if (sandbox::SyscallSets::IsKill(sysno)) {
      return Broker();
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
      return sandbox::bpf_dsl::If(domain == AF_UNIX, Allow())
          .Else(Block());
    }

    // send flags: restrict MSG_OOB etc.
    if (sandbox::SyscallSets::IsSockSendOneMsg(sysno)) {
      return sandbox::RestrictSockSendFlags(sysno);
    }

    // getsockopt/setsockopt: Chrome's default allows only SOL_SOCKET+SO_PEEK_OFF.
    // Additional socket options can be allowed at runtime via
    // sandbox_allow_sockopts() for runtimes that need them.
    if (sysno == __NR_getsockopt || sysno == __NR_setsockopt) {
      const Arg<int> level(1);
      const Arg<int> optname(2);
      // Start with Chrome's allowlist + standard socket options needed by
      // Python/Node.js TLS stacks. These are safe informational/tuning options:
      //   SO_PEEK_OFF (42): Chrome's original allowlist
      //   SO_TYPE (3): read-only, returns socket type (needed by ssl.wrap_socket)
      //   SO_ERROR (4): read-only, returns pending error (needed by connect())
      //   SO_KEEPALIVE (9): enable TCP keepalive (standard)
      //   SO_SNDBUF/SO_RCVBUF (7/8): buffer size tuning
      ResultExpr sockopt_result = Switch(optname)
          .Cases({SO_PEEK_OFF, SO_TYPE, SO_ERROR, SO_KEEPALIVE,
                  SO_SNDBUF, SO_RCVBUF}, Allow())
          .Default(Block());
      // Layer on runtime-configured extensions (additive only)
      for (int opt : extra_sockopts_) {
        sockopt_result = sandbox::bpf_dsl::If(optname == opt, Allow())
            .Else(std::move(sockopt_result));
      }
      // Also allow IPPROTO_TCP level for TCP_NODELAY (optname 1) and
      // TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT which are standard
      // performance/keepalive options used by Python's urllib, Node.js, etc.
      // These are safe: they only affect TCP segment behavior, not security.
      ResultExpr tcp_result = Switch(optname)
          .Cases({1 /* TCP_NODELAY */,
                  4 /* TCP_KEEPIDLE */, 5 /* TCP_KEEPINTVL */,
                  6 /* TCP_KEEPCNT */}, Allow())
          .Default(Block());
      return sandbox::bpf_dsl::If(level == SOL_SOCKET, std::move(sockopt_result))
          .ElseIf(level == 6 /* IPPROTO_TCP */, std::move(tcp_result))
          .Else(Block());
    }

    // memfd_create: block entirely in STRICT mode.
    // Chrome's RestrictMemfdCreate() only restricts flags, but memfd_create
    // enables fileless execution (write ELF to memfd, fexecve it) which
    // bypasses the filesystem broker. Block it completely.
    if (sysno == __NR_memfd_create) {
      return Block();
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

    // fstatat: glibc uses fstatat() for stat/fstat/lstat.
    // Chrome's RewriteFstatatSIGSYS uses Trap() which doesn't survive exec.
    // Instead: AT_EMPTY_PATH means fstat-on-fd (safe, allow directly).
    // With a path: route through broker for path validation.
    if (sysno == __NR_fstatat_default) {
      const Arg<int> flags(3);
      return sandbox::bpf_dsl::If(
          (flags & AT_EMPTY_PATH) == AT_EMPTY_PATH, Allow())
          .Else(Broker());
    }

    // statx: return ENOSYS to force glibc/coreutils fallback to fstatat,
    // which we route through the broker for path validation. Returning
    // ENOSYS (not EPERM) ensures correct fallback behavior.
    if (sysno == __NR_statx) {
      return Error(ENOSYS);
    }

    // ── BLOCK: Dangerous syscall categories ──────────────────────────

    // Network: when networking is disabled (Chrome default), block everything
    // except AF_UNIX. When enabled, allow TCP/UDP connections for API calls.
    if (sysno == __NR_socket) {
      Arg<int> domain(0);
      if (allow_networking_) {
        // Allow AF_UNIX, AF_INET, AF_INET6
        return sandbox::bpf_dsl::If(
            sandbox::bpf_dsl::AnyOf(domain == AF_UNIX, domain == AF_INET,
                                     domain == AF_INET6),
            Allow()).Else(Block());
      }
      return sandbox::bpf_dsl::If(domain == AF_UNIX, Allow()).Else(Block());
    }
    if (sysno == __NR_bind || sysno == __NR_listen ||
        sysno == __NR_accept || sysno == __NR_accept4 ||
        sysno == __NR_connect) {
      if (allow_networking_) return Allow();
      return Block();
    }

    // Namespace escape
    if (sysno == __NR_unshare || sysno == __NR_setns) {
      return Block();
    }

    // Filesystem access: route through ptrace-based broker.
    //
    // Chrome uses SIGSYS handler → broker IPC to validate filesystem paths.
    // We use SECCOMP_RET_TRACE → ptrace tracer validates paths against
    // BrokerPermissionList. This achieves the same per-path validation but
    // survives execve() (SIGSYS handlers are lost on exec; ptrace is not).
    //
    // The tracer checks PTRACE_GETEVENTMSG == TRACE_BROKER and validates
    // the path against the configured permission list. If allowed, the
    // syscall proceeds normally. If denied, it's skipped with -EACCES.
    if (sandbox::SyscallSets::IsFileSystem(sysno) ||
        sandbox::SyscallSets::IsCurrentDirectory(sysno)) {
      return Broker();
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
    // These operate on already-opened file descriptors, not paths.
    // getdents64 is needed for directory listing (ls, find, etc.)
    // fchmod/fchown on read-only mounts return EROFS from the kernel.
    // Allow these since they can't open new files — the broker already
    // controls which files can be opened in the first place.
    if (sandbox::SyscallSets::IsDeniedFileSystemAccessViaFd(sysno)) {
      return Allow();
    }

    // Socket operations: block unless networking is enabled.
    // Chrome blocks these because renderers don't need sockets.
    // When networking is enabled (for API calls, curl, etc.), allow
    // socket creation, connect, bind, listen, accept.
    // getsockopt/setsockopt are handled separately above with per-option
    // filtering.
    //
    // ESCAPE HYPOTHESIS (IsDeniedGetOrModifySocket + networking):
    //   socket+connect: LOW risk — outbound only, net NS limits reach
    //   bind+listen+accept: MEDIUM risk — enables inbound server,
    //     but net NS blocks external access (only loopback reachable)
    //   Raw/packet sockets: blocked by kernel (needs CAP_NET_RAW)
    if (sandbox::SyscallSets::IsDeniedGetOrModifySocket(sysno)) {
      if (allow_networking_) return Allow();
      return Error(EPERM);
    }

    // getsockname/getpeername: needed for TLS handshake (checking local
    // address after connect). These are query-only, read-only operations
    // on already-open sockets — no new attack surface.
    //
    // ESCAPE HYPOTHESIS (getsockname/getpeername + networking):
    //   Risk: LOW — read-only socket metadata, no data exfiltration
    //   Mitigated by: net NS isolation, broker controls socket creation
    if (sysno == __NR_getsockname || sysno == __NR_getpeername) {
      if (allow_networking_) return Allow();
      return Error(EPERM);
    }

    // ── BLOCK: Dangerous operations ──────────────────────────────────
    // These operations are blocked via ptrace (SECCOMP_RET_TRACE).
    // We use Block() instead of CrashSIGSYS() because SECCOMP_RET_TRAP
    // generates SIGSYS, whose handler is lost after execve().
    if (sandbox::SyscallSets::IsAdminOperation(sysno) ||
        sandbox::SyscallSets::IsDebug(sysno) ||
        sandbox::SyscallSets::IsKernelModule(sysno) ||
        sandbox::SyscallSets::IsGlobalFSViewChange(sysno) ||
        sandbox::SyscallSets::IsGlobalProcessEnvironment(sysno)) {
      return Block();
    }

    // Everything else: block via ptrace.
    // Unknown/unclassified syscalls are denied with -EACCES by the tracer.
    return Block();
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
  std::set<unsigned long> extra_ioctls_;   // runtime-configured ioctl extensions
  std::set<int> extra_sockopts_;           // runtime-configured sockopt extensions
  bool allow_networking_;                  // allow AF_INET/AF_INET6 + connect/bind
};

// =============================================================================
// Global state
// =============================================================================

static SandboxPolicyLevel g_policy_level = SANDBOX_POLICY_STRICT;
static SandboxExecPolicy g_exec_policy = SANDBOX_EXEC_BROKERED;
static std::vector<std::string> g_allowed_paths;       // read-write-create paths
static std::vector<std::string> g_readonly_paths;       // read-only paths (runtimes, tools)
static std::vector<std::string> g_denied_paths;         // blocklist — always denied even if in allowed dirs
static std::set<unsigned long> g_extra_ioctls;          // additional allowed ioctl cmds
static std::set<int> g_extra_sockopts;                  // additional allowed SOL_SOCKET options
static bool g_initialized = false;

// Broker process (Chrome's real BrokerProcess)
static std::unique_ptr<sandbox::syscall_broker::BrokerProcess> g_broker;

// =============================================================================
// Zygote process (mirrors Chrome's zygote model)
// =============================================================================
//
// Chrome's architecture:
//   Browser → forks Zygote → Zygote pre-loads renderer code
//   For each tab: Zygote forks (fast!) → child applies seccomp → runs renderer
//
// Our architecture:
//   Agent → sandbox_init() forks Zygote → Zygote applies namespace isolation
//   For each command: Zygote forks (fast!) → child applies PID NS + seccomp
//                     → child execs command → ptrace broker validates syscalls
//
// Benefits:
//   - Namespace isolation (user, mount, net, IPC, chroot, cap drop) done ONCE
//   - Each command fork inherits the sandbox — no re-setup cost
//   - Matches Chrome's process model exactly

static pid_t g_zygote_pid = -1;
static int g_zygote_fd = -1;     // Agent side of socketpair
static bool g_in_zygote = false;  // True inside the zygote process

// --- Zygote IPC protocol ---
// All messages are length-prefixed: [uint32_t total_len] [payload]

// Command message: agent → zygote
//   [uint32_t argc]
//   [for each arg: uint32_t len, char data[len]]
//   [int32_t exec_policy]
//   [int32_t sandbox_policy]
//   [uint32_t n_ioctls] [ioctl_data...]
//   [uint32_t n_sockopts] [sockopt_data...]
//   [uint8_t passthrough]    // 1 = interactive passthrough mode (no capture)

// Result message: zygote → agent
//   [int32_t exit_code]
//   [uint32_t stdout_len] [stdout_data]
//   [uint32_t stderr_len] [stderr_data]
//   [uint32_t log_len]    [log_data]
//   [int32_t total_syscalls]
//   [int32_t blocked_syscalls]
//   [double duration]

// Reliable write: writes all bytes or returns false
static bool write_all(int fd, const void* buf, size_t len) {
  const char* p = static_cast<const char*>(buf);
  while (len > 0) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += n;
    len -= n;
  }
  return true;
}

// Reliable read: reads all bytes or returns false
static bool read_all(int fd, void* buf, size_t len) {
  char* p = static_cast<char*>(buf);
  while (len > 0) {
    ssize_t n = read(fd, p, len);
    if (n <= 0) {
      if (n < 0 && errno == EINTR) continue;
      return false;
    }
    p += n;
    len -= n;
  }
  return true;
}

// Send a command to the zygote
static bool zygote_send_command(int fd, const char* const* argv,
                                SandboxExecPolicy exec_policy,
                                SandboxPolicyLevel sandbox_policy,
                                const std::set<unsigned long>& extra_ioctls,
                                const std::set<int>& extra_sockopts,
                                bool passthrough = false) {
  // Count args
  uint32_t argc = 0;
  for (const char* const* p = argv; *p; p++) argc++;

  // Calculate total size
  size_t total = sizeof(uint32_t);  // argc
  for (uint32_t i = 0; i < argc; i++) {
    total += sizeof(uint32_t) + strlen(argv[i]);
  }
  total += sizeof(int32_t) * 2;  // exec_policy + sandbox_policy
  total += sizeof(uint32_t) + extra_ioctls.size() * sizeof(unsigned long);
  total += sizeof(uint32_t) + extra_sockopts.size() * sizeof(int32_t);
  total += sizeof(uint8_t);  // passthrough flag

  // Write total length
  uint32_t total_len = (uint32_t)total;
  if (!write_all(fd, &total_len, sizeof(total_len))) return false;

  // Write argc
  if (!write_all(fd, &argc, sizeof(argc))) return false;

  // Write each arg
  for (uint32_t i = 0; i < argc; i++) {
    uint32_t slen = (uint32_t)strlen(argv[i]);
    if (!write_all(fd, &slen, sizeof(slen))) return false;
    if (!write_all(fd, argv[i], slen)) return false;
  }

  // Write policies
  int32_t ep = (int32_t)exec_policy;
  int32_t sp = (int32_t)sandbox_policy;
  if (!write_all(fd, &ep, sizeof(ep))) return false;
  if (!write_all(fd, &sp, sizeof(sp))) return false;

  // Write per-execution seccomp extensions
  uint32_t n_ioctls = (uint32_t)extra_ioctls.size();
  if (!write_all(fd, &n_ioctls, sizeof(n_ioctls))) return false;
  for (unsigned long cmd : extra_ioctls) {
    if (!write_all(fd, &cmd, sizeof(cmd))) return false;
  }

  uint32_t n_sockopts = (uint32_t)extra_sockopts.size();
  if (!write_all(fd, &n_sockopts, sizeof(n_sockopts))) return false;
  for (int opt : extra_sockopts) {
    int32_t opt32 = (int32_t)opt;
    if (!write_all(fd, &opt32, sizeof(opt32))) return false;
  }

  // Write passthrough flag
  uint8_t pt = passthrough ? 1 : 0;
  if (!write_all(fd, &pt, sizeof(pt))) return false;

  return true;
}

// Receive a command in the zygote
static bool zygote_recv_command(int fd, std::vector<std::string>& args,
                                SandboxExecPolicy& exec_policy,
                                SandboxPolicyLevel& sandbox_policy,
                                std::set<unsigned long>& extra_ioctls,
                                std::set<int>& extra_sockopts,
                                bool& passthrough) {
  uint32_t total_len;
  if (!read_all(fd, &total_len, sizeof(total_len))) return false;

  uint32_t argc;
  if (!read_all(fd, &argc, sizeof(argc))) return false;
  if (argc > 1024) return false;  // Sanity check

  args.clear();
  for (uint32_t i = 0; i < argc; i++) {
    uint32_t slen;
    if (!read_all(fd, &slen, sizeof(slen))) return false;
    if (slen > 65536) return false;  // Sanity check
    std::string s(slen, '\0');
    if (!read_all(fd, &s[0], slen)) return false;
    args.push_back(std::move(s));
  }

  int32_t ep, sp;
  if (!read_all(fd, &ep, sizeof(ep))) return false;
  if (!read_all(fd, &sp, sizeof(sp))) return false;
  exec_policy = (SandboxExecPolicy)ep;
  sandbox_policy = (SandboxPolicyLevel)sp;

  // Read per-execution seccomp extensions
  extra_ioctls.clear();
  uint32_t n_ioctls;
  if (!read_all(fd, &n_ioctls, sizeof(n_ioctls))) return false;
  if (n_ioctls > 256) return false;  // Sanity check
  for (uint32_t i = 0; i < n_ioctls; i++) {
    unsigned long cmd;
    if (!read_all(fd, &cmd, sizeof(cmd))) return false;
    extra_ioctls.insert(cmd);
  }

  extra_sockopts.clear();
  uint32_t n_sockopts;
  if (!read_all(fd, &n_sockopts, sizeof(n_sockopts))) return false;
  if (n_sockopts > 256) return false;  // Sanity check
  for (uint32_t i = 0; i < n_sockopts; i++) {
    int32_t opt;
    if (!read_all(fd, &opt, sizeof(opt))) return false;
    extra_sockopts.insert((int)opt);
  }

  // Read passthrough flag
  uint8_t pt = 0;
  if (!read_all(fd, &pt, sizeof(pt))) return false;
  passthrough = (pt != 0);

  return true;
}

// Send results from zygote back to agent
static bool zygote_send_result(int fd, const SandboxResult& result) {
  // Calculate total size
  size_t total = sizeof(int32_t)    // exit_code
               + sizeof(uint32_t) + result.stdout_len   // stdout
               + sizeof(uint32_t) + result.stderr_len   // stderr
               + sizeof(uint32_t) + result.syscall_log_len  // log
               + sizeof(int32_t) * 2  // total + blocked
               + sizeof(double);      // duration

  uint32_t total_len = (uint32_t)total;
  if (!write_all(fd, &total_len, sizeof(total_len))) return false;

  int32_t ec = result.exit_code;
  if (!write_all(fd, &ec, sizeof(ec))) return false;

  uint32_t slen;
  slen = (uint32_t)result.stdout_len;
  if (!write_all(fd, &slen, sizeof(slen))) return false;
  if (slen > 0 && !write_all(fd, result.stdout_buf, slen)) return false;

  slen = (uint32_t)result.stderr_len;
  if (!write_all(fd, &slen, sizeof(slen))) return false;
  if (slen > 0 && !write_all(fd, result.stderr_buf, slen)) return false;

  slen = (uint32_t)result.syscall_log_len;
  if (!write_all(fd, &slen, sizeof(slen))) return false;
  if (slen > 0 && !write_all(fd, result.syscall_log, slen)) return false;

  int32_t total_sc = result.num_syscalls_total;
  int32_t blocked_sc = result.num_syscalls_blocked;
  if (!write_all(fd, &total_sc, sizeof(total_sc))) return false;
  if (!write_all(fd, &blocked_sc, sizeof(blocked_sc))) return false;
  if (!write_all(fd, &result.duration_seconds, sizeof(result.duration_seconds))) return false;

  return true;
}

// Receive results in the agent
static bool zygote_recv_result(int fd, SandboxResult& result) {
  uint32_t total_len;
  if (!read_all(fd, &total_len, sizeof(total_len))) return false;

  int32_t ec;
  if (!read_all(fd, &ec, sizeof(ec))) return false;
  result.exit_code = ec;

  uint32_t slen;
  if (!read_all(fd, &slen, sizeof(slen))) return false;
  result.stdout_len = slen;
  result.stdout_buf = slen > 0 ? (char*)malloc(slen + 1) : nullptr;
  if (slen > 0) {
    if (!read_all(fd, result.stdout_buf, slen)) return false;
    result.stdout_buf[slen] = '\0';
  }

  if (!read_all(fd, &slen, sizeof(slen))) return false;
  result.stderr_len = slen;
  result.stderr_buf = slen > 0 ? (char*)malloc(slen + 1) : nullptr;
  if (slen > 0) {
    if (!read_all(fd, result.stderr_buf, slen)) return false;
    result.stderr_buf[slen] = '\0';
  }

  if (!read_all(fd, &slen, sizeof(slen))) return false;
  result.syscall_log_len = slen;
  result.syscall_log = slen > 0 ? (char*)malloc(slen + 1) : nullptr;
  if (slen > 0) {
    if (!read_all(fd, result.syscall_log, slen)) return false;
    result.syscall_log[slen] = '\0';
  }

  int32_t total_sc, blocked_sc;
  if (!read_all(fd, &total_sc, sizeof(total_sc))) return false;
  if (!read_all(fd, &blocked_sc, sizeof(blocked_sc))) return false;
  result.num_syscalls_total = total_sc;
  result.num_syscalls_blocked = blocked_sc;
  if (!read_all(fd, &result.duration_seconds, sizeof(result.duration_seconds))) return false;

  return true;
}

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

// Read a string from child process memory via ptrace(PTRACE_PEEKDATA).
//
// We use PTRACE_PEEKDATA instead of /proc/pid/mem because /proc may not
// be mountable inside the zygote's chroot. Mounting procfs requires the
// user namespace to own the PID namespace, but the zygote skips PID NS
// creation. PTRACE_PEEKDATA works regardless of /proc availability since
// the tracer is already attached via PTRACE_TRACEME.
static std::string read_child_string(pid_t pid, unsigned long addr, size_t maxlen = 256) {
  if (addr == 0) return "";
  std::string result;
  result.reserve(64);
  for (size_t offset = 0; offset < maxlen; offset += sizeof(long)) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, addr + offset, nullptr);
    if (errno != 0) break;
    const char* p = reinterpret_cast<const char*>(&word);
    for (size_t i = 0; i < sizeof(long) && offset + i < maxlen; i++) {
      if (p[i] == '\0') return result;
      result += p[i];
    }
  }
  return result;
}

// Write a string back into child memory at the given address.
// Used to defeat TOCTOU races: after validating a path, we rewrite the
// broker-approved path into child memory so the kernel reads OUR copy,
// not whatever the child's threads may have swapped in.
static bool write_child_string(pid_t pid, unsigned long addr,
                               const std::string& str) {
  if (addr == 0) return false;
  const char* src = str.c_str();
  size_t len = str.size() + 1;  // include null terminator

  for (size_t offset = 0; offset < len; offset += sizeof(long)) {
    // Read the current word (we need it for partial-word writes at the end)
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, addr + offset, nullptr);
    if (errno != 0) return false;

    // Overwrite bytes in the word with our string
    char* wp = reinterpret_cast<char*>(&word);
    for (size_t i = 0; i < sizeof(long) && offset + i < len; i++) {
      wp[i] = src[offset + i];
    }

    if (ptrace(PTRACE_POKEDATA, pid, addr + offset, word) != 0) {
      return false;
    }
  }
  return true;
}

// Lexical-only path normalization (no filesystem access, no TOCTOU risk).
// Resolves `.` and `..` segments, collapses duplicate slashes.
// This is the safe alternative to realpath() for sandbox brokers:
//   - No filesystem access: no TOCTOU race (unlike realpath which stats)
//   - No symlink resolution: doesn't follow symlinks outside allowlist
//   - Pure string operation: deterministic and async-signal-safe
//
// Why NOT realpath():
//   - CVE-2018-1000001: glibc buffer underflow via getcwd() interaction
//   - CVE-2018-11236: stack overflow on 32-bit with long paths
//   - TOCTOU: symlink swap between realpath() and kernel syscall execution
//     (exactly CVE-2018-15664 in Docker, ~12.5% success rate per attempt)
//   - /proc magic links resolve in broker context, not child context
//   - SEI CERT FIO02-C: "canonicalizing path names may need to be abandoned"
//
// Examples:
//   /usr/local/lib/python3.11/dist-packages/PIL/../pillow.libs/lib.so
//     → /usr/local/lib/python3.11/dist-packages/pillow.libs/lib.so
//   /usr/./lib/foo     → /usr/lib/foo
//   /usr//lib///foo    → /usr/lib/foo
//   /../etc/passwd     → /etc/passwd (can't go above root)
static std::string normalize_path_lexical(const std::string& path) {
  if (path.empty() || path[0] != '/') return path;  // only absolute paths

  std::vector<std::string> components;
  size_t i = 0;
  while (i < path.size()) {
    // Skip slashes
    while (i < path.size() && path[i] == '/') i++;
    if (i >= path.size()) break;

    // Extract component
    size_t start = i;
    while (i < path.size() && path[i] != '/') i++;
    std::string component = path.substr(start, i - start);

    if (component == ".") {
      continue;  // skip current dir reference
    } else if (component == "..") {
      if (!components.empty()) {
        components.pop_back();  // go up one level
      }
      // At root: can't go higher, silently clamp (same as kernel behavior)
    } else {
      components.push_back(std::move(component));
    }
  }

  // Reconstruct absolute path
  if (components.empty()) return "/";
  std::string result;
  for (const auto& c : components) {
    result += '/';
    result += c;
  }
  // Do NOT preserve trailing slash: Chrome's ValidatePath() rejects
  // paths ending with "/" (except root "/"). The kernel handles
  // trailing slashes internally during path resolution.
  return result;
}

// Resolve a relative path to an absolute path using a tracked CWD.
// This maintains broker enforcement for relative paths instead of
// blindly allowing them.
//
// Security rationale: Chrome's broker requires absolute paths because Chrome's
// renderers run without a chroot. Our sandbox IS chrooted, so relative paths
// are kernel-confined, but we STILL resolve and broker-check them to maintain:
//   1. The audit trail (all accesses logged with full paths)
//   2. Defense-in-depth (broker + mount namespace + chroot, not just chroot)
//   3. Fine-grained path restrictions beyond mount namespace
//
// Implementation: Use tracer-tracked CWD (maintained via chdir interception
// and fork/clone inheritance) rather than /proc/pid/cwd, because the /proc
// inside the chroot is remounted for the inner PID namespace and the tracer's
// PIDs may not be visible there. PTRACE_PEEKDATA works regardless of /proc,
// but readlink on /proc does not.
static std::string resolve_relative_path(const std::string& cwd,
                                         const std::string& relpath) {
  // CWD must be absolute
  if (cwd.empty() || cwd[0] != '/') return "";

  // Join CWD with relative path and normalize
  // e.g., cwd="/tmp/workspace" + relpath="." → "/tmp/workspace/."
  //     → normalize → "/tmp/workspace"
  std::string joined = cwd + "/" + relpath;
  return normalize_path_lexical(joined);
}

// Check if a normalized absolute path is in the deny list.
// Deny list takes priority over allow list — used for sensitive files
// that should never be accessible even if inside an allowed directory.
static bool is_path_denied(const std::string& path) {
  for (const auto& denied : g_denied_paths) {
    if (path == denied) return true;
    // Also deny if path is under a denied directory prefix
    if (!denied.empty() && denied.back() == '/' && path.compare(0, denied.size(), denied) == 0) {
      return true;
    }
    // Deny directory prefix: path starts with denied + "/"
    if (path.size() > denied.size() && path[denied.size()] == '/' &&
        path.compare(0, denied.size(), denied) == 0) {
      return true;
    }
  }
  return false;
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
static bool g_enable_network_isolation = true;  // default: Chrome's behavior

// Audit mode: structured logging of all broker decisions
static bool g_audit_mode = false;
static int g_audit_fd = -1;            // fd for audit log output (-1 = stderr)
static bool g_audit_owns_fd = false;   // true if we opened the fd (need to close)

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
    {nullptr, nullptr}
  };

  for (int i = 0; ro_mounts[i].src; i++) {
    struct stat st;
    if (stat(ro_mounts[i].src, &st) != 0) continue;  // Skip if doesn't exist
    snprintf(path, sizeof(path), "%s/%s", sandbox_root, ro_mounts[i].subdir);
    bind_mount_readonly(ro_mounts[i].src, path);
  }

  // /etc: selective bind-mount of ONLY safe configuration files.
  // We mount a tmpfs for /etc and copy/bind only the files needed for
  // program execution. This prevents access to /etc/shadow, /etc/sudoers,
  // /etc/ssh/, /etc/gshadow, etc.
  snprintf(path, sizeof(path), "%s/etc", sandbox_root);
  mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "size=4m,mode=0755");

  // Safe /etc files needed by libc, DNS, SSL, locale, timezone, users
  static const char* safe_etc_files[] = {
    "ld.so.cache", "ld.so.conf", "ld.so.conf.d",
    "nsswitch.conf", "resolv.conf", "hosts", "hostname",
    "passwd", "group",             // User info (public, no password hashes)
    "localtime", "timezone",       // Timezone
    "ssl", "ca-certificates",      // TLS certificates
    "alternatives",                // Debian alternatives
    "locale.conf", "locale.gen",   // Locale settings
    "profile", "profile.d", "bash.bashrc", "environment",
    "login.defs",                  // Login defaults (not credentials)
    "default", "skel",             // System defaults
    "mime.types",                  // MIME type mappings
    "protocols", "services",       // Network service name mappings
    "gai.conf",                    // getaddrinfo config
    "host.conf",                   // Resolver config
    nullptr
  };
  for (int i = 0; safe_etc_files[i]; i++) {
    char src[512], dst[512];
    snprintf(src, sizeof(src), "/etc/%s", safe_etc_files[i]);
    snprintf(dst, sizeof(dst), "%s/etc/%s", sandbox_root, safe_etc_files[i]);
    struct stat st;
    if (stat(src, &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      mkdir(dst, 0755);
      bind_mount_readonly(src, dst);
    } else {
      // Create file and bind-mount
      int fd = open(dst, O_WRONLY | O_CREAT, 0644);
      if (fd >= 0) close(fd);
      mount(src, dst, nullptr, MS_BIND, nullptr);
      mount(nullptr, dst, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
    }
  }

  // Bind-mount user-configured read-only paths (runtimes, tools)
  for (const auto& ro_path : g_readonly_paths) {
    if (ro_path.empty() || ro_path[0] != '/') continue;
    struct stat st;
    if (stat(ro_path.c_str(), &st) != 0) continue;  // Skip if doesn't exist
    // Create the mount point in new root
    snprintf(path, sizeof(path), "%s%s", sandbox_root, ro_path.c_str());
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
    bind_mount_readonly(ro_path.c_str(), path);
  }

  // Mount minimal /dev entries
  snprintf(path, sizeof(path), "%s/dev/null", sandbox_root);
  close(open(path, O_WRONLY | O_CREAT, 0666));
  mount("/dev/null", path, nullptr, MS_BIND, nullptr);

  snprintf(path, sizeof(path), "%s/dev/urandom", sandbox_root);
  close(open(path, O_WRONLY | O_CREAT, 0444));
  mount("/dev/urandom", path, nullptr, MS_BIND, nullptr);

  snprintf(path, sizeof(path), "%s/dev/random", sandbox_root);
  close(open(path, O_WRONLY | O_CREAT, 0444));
  mount("/dev/random", path, nullptr, MS_BIND, nullptr);

  snprintf(path, sizeof(path), "%s/dev/zero", sandbox_root);
  close(open(path, O_WRONLY | O_CREAT, 0666));
  mount("/dev/zero", path, nullptr, MS_BIND, nullptr);

  // Mount a private tmpfs for /tmp in new root
  // NOTE: This MUST come BEFORE allowed_paths bind-mounts so that workspace
  // directories under /tmp (e.g. /tmp/workspace) can be bind-mounted on top
  // of the tmpfs. Otherwise the tmpfs would shadow the workspace bind-mount.
  snprintf(path, sizeof(path), "%s/tmp", sandbox_root);
  mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "size=256m,mode=1777");

  // Bind-mount user-configured allowed paths (read-write)
  // Mounted AFTER tmpfs /tmp so workspace dirs under /tmp overlay the tmpfs.
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

  // Mount procfs in new root (needed by ptrace broker to read child memory
  // via /proc/pid/mem, and by tools like ps, top, /proc/self/*)
  snprintf(path, sizeof(path), "%s/proc", sandbox_root);
  mkdir(path, 0555);
  mount("proc", path, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);

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

// Drop all capabilities, optionally keeping CAP_SYS_ADMIN.
// keep_sys_admin: when true, preserves CAP_SYS_ADMIN in the user namespace.
// This is needed by the zygote so forked workers can create PID namespaces
// and remount /proc. Workers drop CAP_SYS_ADMIN after PID NS setup.
static bool drop_capabilities(bool keep_sys_admin = false) {
  struct cap_hdr hdr = {};
  hdr.version = _LINUX_CAPABILITY_VERSION_3;
  struct cap_data data[_LINUX_CAPABILITY_U32S_3] = {};
  if (keep_sys_admin) {
    // CAP_SYS_ADMIN = 21 → bit 21 in the first 32-bit word
    data[0].effective = (1U << 21);
    data[0].permitted = (1U << 21);
    data[0].inheritable = 0;  // Don't inherit across exec
  }
  return sandbox::sys_capset(&hdr, data) == 0;
}

static bool drop_all_capabilities() {
  return drop_capabilities(false);
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

// skip_pid_ns: when true, skips PID namespace setup (for zygote — PID NS
// is per-command, not per-zygote, so each command gets its own PID NS).
static NamespaceStatus apply_namespace_isolation(bool skip_pid_ns = false) {
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
  // In zygote mode, PID NS is per-command (not per-zygote).
  if (!skip_pid_ns) {
    status.pid_ns = setup_pid_namespace();
  }

  // Layer 1c: IPC namespace (isolates System V IPC + POSIX mqueues)
  status.ipc_ns = setup_ipc_namespace();

  // Layer 1d: Network namespace
  // When network isolation is disabled, sandboxed processes inherit the host
  // network stack (needed for API calls, curl, etc.). All other isolation
  // layers (user NS, PID NS, mount NS, seccomp-BPF) remain active.
  if (g_enable_network_isolation) {
    status.net_ns = setup_net_namespace();
  }

  // Layer 2: Mount namespace for filesystem isolation
  status.mount_ns = setup_mount_namespace();

  // Layer 2b: Chroot filesystem isolation
  // Must be done after mount namespace (so bind mounts are private)
  // and before dropping capabilities (needs CAP_SYS_ADMIN for mount/pivot_root)
  if (status.mount_ns) {
    setup_chroot_filesystem();
  }

  // Layer 3: Drop capabilities
  // After user namespace setup, we have full caps in the new namespace.
  // NOTE: We must do this AFTER mount namespace setup (which needs
  // CAP_SYS_ADMIN) but BEFORE seccomp-BPF installation.
  //
  // When skip_pid_ns is true (zygote mode), we preserve CAP_SYS_ADMIN
  // so forked workers can create per-command PID namespaces and remount
  // /proc. Each worker drops CAP_SYS_ADMIN after setting up its PID NS.
  // The seccomp-BPF filter still blocks mount/unshare syscalls, so
  // CAP_SYS_ADMIN alone cannot be used to escape.
  status.caps_dropped = drop_capabilities(/*keep_sys_admin=*/skip_pid_ns);

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

  // Limit number of processes to prevent fork bombs.
  // 256 is enough for shells, interpreters, and build tools, but prevents
  // unbounded fork() that could exhaust host PID space.
  static constexpr rlim_t kNprocLimit = 256;
  (void)sandbox::ResourceLimits::Lower(RLIMIT_NPROC, kNprocLimit);

  // Disk space is bounded by tmpfs size (32MB) + workspace quotas.

  return status;
}

// Forward declaration for broker permissions builder
static std::vector<sandbox::syscall_broker::BrokerFilePermission>
build_broker_permissions();

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

    // Allow ptrace from parent.
    //
    // The zygote drops all capabilities AND sets PR_SET_DUMPABLE=0.
    // Children inherit both settings. The kernel's cap_ptrace_traceme()
    // check fails when the parent has no CAP_SYS_PTRACE and the child
    // is not dumpable. Fix: temporarily set dumpable=1 so PTRACE_TRACEME
    // can establish the tracing relationship, then restore dumpable=0
    // for defense-in-depth (prevents other processes from ptracing us).
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    raise(SIGSTOP);  // Wait for parent to set up tracing

    // === LAYER 1-5: Namespace isolation ===
    // In zygote mode: namespaces (user, mount, net, IPC, chroot, caps)
    // are already applied by the zygote. We only need PID NS per-command.
    // In direct mode: apply everything now.
    NamespaceStatus ns_status = {};
    if (g_in_zygote) {
      // Zygote already applied: user NS, mount NS, net NS, IPC NS, chroot.
      // The zygote preserves CAP_SYS_ADMIN so we can create per-command
      // PID namespaces. We'll drop it after PID NS setup.
      ns_status.user_ns = true;
      ns_status.mount_ns = true;
      ns_status.net_ns = true;
      ns_status.ipc_ns = true;
      ns_status.caps_dropped = false;
      // Create PID namespace for this command
      ns_status.pid_ns = setup_pid_namespace();
    } else {
      // Direct mode: full namespace isolation
      ns_status = apply_namespace_isolation();
    }

    // === PID namespace fork ===
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
        // Init reaper: as PID 1 in a PID namespace, we must reap ALL
        // orphaned children (not just our direct child). This matches
        // Chrome's CreateInitProcessReaper() which uses waitid(P_ALL).
        int exit_code = 1;
        for (;;) {
          int reaper_status;
          pid_t reaped = waitpid(-1, &reaper_status, 0);
          if (reaped < 0) {
            if (errno == EINTR) continue;
            break;  // ECHILD: no more children
          }
          if (reaped == ns_child) {
            // Our main child exited — record its exit code
            exit_code = WIFEXITED(reaper_status)
                            ? WEXITSTATUS(reaper_status)
                            : 1;
          }
          // Continue reaping other orphaned children
        }
        _exit(exit_code);
      }
      // Grandchild: PID 1 in new PID namespace.
      // Remount /proc to reflect the new PID namespace.
      // This ensures /proc only shows processes in our namespace.
      mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
            nullptr);
    }

    // Drop CAP_SYS_ADMIN if still held (zygote path preserves it for PID NS).
    // Must happen AFTER proc mount but BEFORE seccomp-BPF install.
    if (!ns_status.caps_dropped) {
      drop_all_capabilities();
    }

    // === LAYER 6: seccomp-BPF ===
    // Install Chrome's seccomp-BPF sandbox using the actual Chromium code.
    // This is the innermost layer and filters every syscall.
    auto policy = std::make_unique<AgentSandboxPolicy>(
        g_policy_level, g_extra_ioctls, g_extra_sockopts,
        !g_enable_network_isolation);
    sandbox::SandboxBPF sandbox_bpf(std::move(policy));
    if (!sandbox_bpf.StartSandbox(sandbox::SandboxBPF::SeccompLevel::SINGLE_THREADED)) {
      _exit(126);
    }

    // chdir to workspace (first allowed path) so tools that write to CWD
    // (e.g. Bun's JIT .so extraction) land in a writable directory.
    if (!g_allowed_paths.empty()) {
      chdir(g_allowed_paths[0].c_str());
    }

    // Now exec the target command
    execvp(argv[0], const_cast<char* const*>(argv));
    _exit(127);
  }

  // === PARENT (tracer/broker) ===
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);

  // Start pipe reader threads BEFORE the ptrace loop.
  // This prevents deadlock when the child produces more output than the pipe
  // buffer (64KB). Without concurrent draining, the child blocks on write(),
  // the parent blocks on waitpid(), and we deadlock.
  std::string stdout_data, stderr_data;
  std::thread stdout_reader([fd = stdout_pipe[0], &stdout_data]() {
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
      stdout_data.append(buf, n);
  });
  std::thread stderr_reader([fd = stderr_pipe[0], &stderr_data]() {
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
      stderr_data.append(buf, n);
  });

  // Wait for child's SIGSTOP
  int status;
  waitpid(child, &status, 0);

  // Set ptrace options: trace seccomp events, forks, execs
  long ptrace_opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD |
                     PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                     PTRACE_O_TRACEEXIT;
  ptrace(PTRACE_SETOPTIONS, child, nullptr, ptrace_opts);

  // === Ptrace-based syscall broker ===
  // Build the broker permission list (matches Chrome's BrokerHost validation).
  // The seccomp policy routes filesystem syscalls via Trace(TRACE_BROKER).
  // The tracer validates paths against this list, allowing or denying each call.
  auto broker_perms = build_broker_permissions();
  sandbox::syscall_broker::BrokerPermissionList broker_policy(
      EACCES, std::move(broker_perms));

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
  int brokered = 0;

  // Exec policy tracking: count execs per PID for Chrome-like enforcement.
  // Chrome blocks ALL execs (zygote model). We allow the initial exec
  // (launching the command) and optionally block subsequent ones.
  std::map<pid_t, int> exec_count;

  // CWD tracking per PID: used to resolve relative paths to absolute.
  // /proc/pid/cwd is unreliable because the inner PID namespace remounts
  // /proc, making the tracer's (outer namespace) PIDs invisible.
  // Instead, we track chdir() calls and fork() inheritance.
  std::map<pid_t, std::string> cwd_map;
  std::string initial_cwd = g_allowed_paths.empty() ? "/" : g_allowed_paths[0];
  cwd_map[child] = initial_cwd;  // Child starts at workspace (or / if none)
  std::string last_fork_cwd = initial_cwd;

  while (!traced_pids.empty()) {
    pid_t pid;
    int wstatus;
    pid = waitpid(-1, &wstatus, __WALL);
    if (pid < 0) break;

    if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
      if (pid == child) {
        result.exit_code = WIFEXITED(wstatus)
            ? WEXITSTATUS(wstatus)
            : -(WTERMSIG(wstatus));
      }
      traced_pids.erase(pid);
      pending_entry.erase(pid);
      exec_count.erase(pid);
      cwd_map.erase(pid);
      continue;
    }

    if (!WIFSTOPPED(wstatus)) continue;

    int sig = WSTOPSIG(wstatus);
    int event = (wstatus >> 16) & 0xFF;

    if (event == PTRACE_EVENT_SECCOMP) {
      // Auto-assign CWD for PIDs not yet in cwd_map (PID namespace mismatch)
      if (cwd_map.find(pid) == cwd_map.end()) {
        cwd_map[pid] = last_fork_cwd;
      }

      // SECCOMP_RET_TRACE: seccomp-BPF flagged this syscall for tracer
      // decision. Read the trace data to determine action:
      //   TRACE_BLOCKED (1): always block
      //   TRACE_BROKER  (2): validate path via BrokerPermissionList
      unsigned long trace_data = 0;
      ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &trace_data);

      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        int nr = (int)regs.orig_rax;

        // Read path from child memory (depends on syscall convention)
        std::string path_str;
        int open_flags = 0;
        bool is_at_syscall = false;
        unsigned long path_addr = 0;  // Address of path in child memory (for TOCTOU defense)

        // *at syscalls: path in rsi (2nd arg), dirfd in rdi (1st arg)
        if (nr == __NR_openat || nr == __NR_faccessat ||
            nr == __NR_faccessat2 || nr == __NR_newfstatat ||
            nr == __NR_mkdirat || nr == __NR_unlinkat ||
            nr == __NR_fchmodat || nr == __NR_fchownat ||
            nr == __NR_readlinkat || nr == __NR_linkat ||
            nr == __NR_symlinkat || nr == __NR_utimensat ||
            nr == __NR_execveat) {
          path_addr = regs.rsi;
          path_str = read_child_string(pid, path_addr);
          is_at_syscall = true;
          if (nr == __NR_openat) open_flags = (int)regs.rdx;
        } else if (nr == __NR_renameat || nr == __NR_renameat2) {
          path_addr = regs.rsi;
          path_str = read_child_string(pid, path_addr);  // old path
          is_at_syscall = true;
        }
        // Non-at syscalls: path in rdi (1st arg)
        else if (nr == __NR_open || nr == __NR_access ||
                 nr == __NR_stat || nr == __NR_lstat ||
                 nr == __NR_execve || nr == __NR_unlink ||
                 nr == __NR_mkdir || nr == __NR_rmdir ||
                 nr == __NR_chmod || nr == __NR_chown ||
                 nr == __NR_chdir || nr == __NR_truncate ||
                 nr == __NR_readlink || nr == __NR_creat ||
                 nr == __NR_link || nr == __NR_symlink ||
                 nr == __NR_rename || nr == __NR_statfs ||
                 nr == __NR_lchown || nr == __NR_mknod) {
          path_addr = regs.rdi;
          path_str = read_child_string(pid, path_addr);
          if (nr == __NR_open) open_flags = (int)regs.rsi;
          if (nr == __NR_creat) open_flags = O_CREAT | O_WRONLY | O_TRUNC;
        }
        // getcwd: no path to validate, always allow
        else if (nr == __NR_getcwd) {
          path_str = "";  // No path validation needed
        }

        // Lexical path normalization: resolve .. and . segments without
        // touching the filesystem. Handles PIL/../pillow.libs/ style paths
        // from RPATH ($ORIGIN/../) that Chrome's broker rejects outright.
        std::string original_path_str = path_str;  // Save for TOCTOU decision
        if (!path_str.empty() && path_str[0] == '/') {
          path_str = normalize_path_lexical(path_str);
        }

        // Resolve relative paths to absolute using child's CWD within chroot.
        // Chrome's broker requires absolute paths, but programs commonly use
        // relative paths (stat("."), open("./file"), etc.). Instead of blindly
        // allowing these (which would bypass broker enforcement), we resolve
        // them to absolute paths and let the broker validate normally.
        // This maintains the full audit trail and defense-in-depth.
        //
        // IMPORTANT: Do NOT write back resolved paths — the child's buffer
        // only has room for the original relative path (e.g., "."). Writing
        // the resolved absolute path (e.g., "/tmp/workspace") would overflow
        // the buffer and corrupt adjacent memory. The kernel handles relative
        // path resolution safely within the chroot.
        bool skip_writeback = false;
        if (!path_str.empty() && path_str[0] != '/') {
          std::string resolved = resolve_relative_path(cwd_map[pid], path_str);
          if (!resolved.empty()) {
            path_str = resolved;
            skip_writeback = true;  // Buffer too small for resolved path
          }
          // If resolution fails, path_str stays relative — the broker will
          // reject it (requires absolute), which is the safe default.
        }

        // Record the syscall
        SyscallRecord rec;
        rec.nr = nr;
        rec.name = syscall_name(nr);
        rec.risk = syscall_risk(nr);
        rec.blocked = false;
        rec.path = path_str;
        rec.args[0] = regs.rdi;
        rec.args[1] = regs.rsi;
        rec.args[2] = regs.rdx;
        rec.args[3] = regs.r10;
        rec.args[4] = regs.r8;
        rec.args[5] = regs.r9;

        if (trace_data == AgentSandboxPolicy::TRACE_BLOCKED) {
          // === BLOCKED: always skip syscall ===
          rec.blocked = true;
          blocked++;
          regs.orig_rax = -1;
          regs.rax = -EPERM;
          ptrace(PTRACE_SETREGS, pid, nullptr, &regs);

        } else if (trace_data == AgentSandboxPolicy::TRACE_BROKER) {
          // === BROKER: validate path against BrokerPermissionList ===
          // This mirrors Chrome's broker validation:
          //   Chrome:  SIGSYS → BrokerClient::Open() → IPC → BrokerHost
          //            → CommandOpenIsSafe() → BrokerPermissionList
          //   Us:      SECCOMP_RET_TRACE → ptrace tracer
          //            → BrokerPermissionList directly
          brokered++;
          bool allowed = false;
          const char* path_c = path_str.c_str();

          // === kill/tgkill/tkill: protect namespace init (PID 1) ===
          // Chrome's RestrictKillTarget hardcodes the PID at BPF install time,
          // but after fork() children inherit the wrong PID constant. We validate
          // at ptrace-time instead: allow signals to self and process group 0,
          // block signals to PID 1 (namespace init — killing it tears down the
          // entire PID namespace).
          if (nr == __NR_kill) {
            pid_t target = (pid_t)regs.rdi;
            if (target == 1) {
              allowed = false;  // Protect namespace init
            } else {
              allowed = true;   // Allow kill to self, children, groups
            }
          } else if (nr == __NR_tgkill) {
            pid_t tgid = (pid_t)regs.rdi;
            if (tgid == 1) {
              allowed = false;
            } else {
              allowed = true;
            }
          } else if (nr == __NR_tkill) {
            pid_t tid = (pid_t)regs.rdi;
            if (tid == 1) {
              allowed = false;
            } else {
              allowed = true;
            }
          } else if (path_str.empty() && nr != __NR_getcwd) {
            // No path — can't validate, deny
            allowed = false;
          } else if (nr == __NR_getcwd || nr == __NR_fchdir) {
            // getcwd/fchdir: always allow (no path-based risk)
            allowed = true;
          } else if (path_str.size() > 8 && path_str.compare(0, 8, "/$bunfs/") == 0) {
            // Bun virtual filesystem: /$bunfs/ paths are Bun's in-process
            // embedded asset store. They don't exist on the real filesystem —
            // the kernel returns ENOENT, then Bun serves from embedded memory.
            // Safe to allow: no real file access occurs, no escape vector.
            allowed = true;
          } else if (nr == __NR_open || nr == __NR_openat || nr == __NR_creat) {
            // open/openat/creat: check with flags.
            // Strip O_CLOEXEC before validation — Chrome's CommandOpenIsSafe()
            // does the same (flags & ~kCurrentProcessOpenFlagsMask). O_CLOEXEC
            // only affects close-on-exec behavior, not which file is opened.
            // Chrome's IPC-based broker handles O_CLOEXEC via MSG_CMSG_CLOEXEC
            // on the receiving end. Our ptrace broker doesn't proxy FDs, so the
            // kernel applies O_CLOEXEC directly. We just need to not reject it.
            int broker_flags = open_flags & ~O_CLOEXEC;
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, broker_flags);
            allowed = (result.first != nullptr);
          } else if (nr == __NR_access || nr == __NR_faccessat ||
                     nr == __NR_faccessat2) {
            // access/faccessat: check with mode
            int mode = is_at_syscall ? (int)regs.rdx : (int)regs.rsi;
            allowed = (broker_policy.GetFileNameIfAllowedToAccess(
                path_c, mode) != nullptr);
          } else if (nr == __NR_stat || nr == __NR_lstat ||
                     nr == __NR_newfstatat || nr == __NR_statfs) {
            // stat family: use stat permission check
            allowed = (broker_policy.GetFileNameIfAllowedToStat(
                path_c) != nullptr);
          } else if (nr == __NR_execve || nr == __NR_execveat) {
            // execve/execveat: enforce exec policy.
            //
            // Chrome blocks ALL execs (zygote model: fork, never exec).
            // We support three modes:
            //   CHROME:   allow first exec per PID, block all subsequent
            //   BROKERED: validate every exec path against broker perms
            //   BLOCKED:  block all execs
            int& pid_execs = exec_count[pid];
            switch (g_exec_policy) {
              case SANDBOX_EXEC_BLOCKED:
                allowed = false;
                break;
              case SANDBOX_EXEC_CHROME:
                // Allow exactly one exec per PID (the initial command launch).
                // After that, block — matching Chrome's renderer sandbox.
                allowed = (pid_execs == 0);
                break;
              case SANDBOX_EXEC_BROKERED:
              default:
                // Validate path against broker permissions
                allowed = (broker_policy.GetFileNameIfAllowedToAccess(
                    path_c, R_OK) != nullptr);
                break;
            }
            if (allowed) pid_execs++;
          } else if (nr == __NR_readlink || nr == __NR_readlinkat) {
            // readlink: check read access
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_RDONLY);
            allowed = (result.first != nullptr);
          } else if (nr == __NR_chdir) {
            // chdir: check stat (need to access directory)
            allowed = (broker_policy.GetFileNameIfAllowedToStat(
                path_c) != nullptr);
          } else if (nr == __NR_mkdir || nr == __NR_mkdirat) {
            // mkdir: check create permission (O_RDWR|O_CREAT|O_EXCL)
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_RDWR | O_CREAT | O_EXCL);
            allowed = (result.first != nullptr);
          } else if (nr == __NR_unlink || nr == __NR_unlinkat ||
                     nr == __NR_rmdir) {
            // unlink/rmdir: check write permission
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_RDWR | O_CREAT | O_EXCL);
            allowed = (result.first != nullptr);
          } else if (nr == __NR_rename || nr == __NR_renameat ||
                     nr == __NR_renameat2) {
            // rename: check both old and new paths
            auto result_old = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_RDWR);
            // Read new path (rsi for rename, r10 for renameat/renameat2)
            std::string new_path;
            if (nr == __NR_rename) {
              new_path = read_child_string(pid, regs.rsi);
            } else {
              new_path = read_child_string(pid, regs.r10);
            }
            auto result_new = broker_policy.GetFileNameIfAllowedToOpen(
                new_path.c_str(), O_RDWR | O_CREAT);
            allowed = (result_old.first != nullptr &&
                       result_new.first != nullptr);
          } else if (nr == __NR_chmod || nr == __NR_fchmodat ||
                     nr == __NR_chown || nr == __NR_fchownat ||
                     nr == __NR_lchown) {
            // chmod/chown: check write permission
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_RDWR);
            allowed = (result.first != nullptr);
          } else if (nr == __NR_truncate) {
            // truncate: check write permission
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_WRONLY);
            allowed = (result.first != nullptr);
          } else if (nr == __NR_link || nr == __NR_linkat ||
                     nr == __NR_symlink || nr == __NR_symlinkat) {
            // link/symlink: check write on target
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_RDWR | O_CREAT);
            allowed = (result.first != nullptr);
          } else if (nr == __NR_mknod || nr == __NR_mknodat) {
            // mknod: deny (creating device nodes is dangerous)
            allowed = false;
          } else if (nr == __NR_utimensat || nr == __NR_utimes ||
                     nr == __NR_futimesat) {
            // utimes: check write permission
            auto result = broker_policy.GetFileNameIfAllowedToOpen(
                path_c, O_RDWR);
            allowed = (result.first != nullptr);
          } else {
            // Unknown filesystem syscall — deny by default
            allowed = false;
          }

          // Deny-list override: block even if broker allowed the path.
          // This provides runtime-configurable path blocking for sensitive
          // files (e.g., /etc/shadow) within otherwise-allowed directories.
          if (allowed && !path_str.empty() && is_path_denied(path_str)) {
            allowed = false;
          }

          if (!allowed) {
            rec.blocked = true;
            blocked++;
            regs.orig_rax = -1;
            regs.rax = -broker_policy.denied_errno();
            ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
          } else {
            // Track CWD changes for relative path resolution
            if (nr == __NR_chdir && !path_str.empty()) {
              cwd_map[pid] = path_str;
            }
            if (path_addr != 0 && !path_str.empty() && !skip_writeback) {
              // === TOCTOU defense ===
              // Rewrite the broker-validated path back into child memory.
              // Between our read and the kernel's read, another thread could
              // have swapped the path to a forbidden target. By rewriting,
              // the kernel reads OUR validated copy, not the attacker's.
              //
              // EXCEPTION: skip write-back when normalization shortened the
              // path. The dynamic linker (ld.so) reuses path buffers and
              // modifies them in-place between hwcaps iterations. Writing a
              // shorter string corrupts the linker's offset calculations,
              // causing garbled paths on subsequent searches. The kernel
              // resolves ".." natively, so the original path reaches the
              // same file — TOCTOU write-back is unnecessary here.
              if (path_str.size() >= original_path_str.size()) {
                write_child_string(pid, path_addr, path_str);
              }
            }
          }
        }

        records.push_back(rec);
      }
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_FORK ||
               event == PTRACE_EVENT_VFORK ||
               event == PTRACE_EVENT_CLONE) {
      unsigned long new_pid;
      ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
      traced_pids.insert(static_cast<pid_t>(new_pid));
      // Child inherits parent's CWD (see passthrough section for PID NS note)
      cwd_map[static_cast<pid_t>(new_pid)] = cwd_map[pid];
      last_fork_cwd = cwd_map[pid];
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
    } else if (sig == SIGSYS) {
      // Suppress SIGSYS from SECCOMP_RET_TRAP.
      // Chrome's helper functions (RestrictPrctl, RestrictClone, RestrictIoctl,
      // etc.) internally use Trap()/CrashSIGSYS() which generates SIGSYS.
      // After execve(), signal handlers are reset to SIG_DFL, so SIGSYS would
      // kill the process. We suppress the signal and set the syscall return
      // value to -ENOSYS so the caller gets a clean error.
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        regs.rax = (unsigned long long)(-ENOSYS);
        ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
      }
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    } else {
      // Deliver signal to child
      ptrace(PTRACE_SYSCALL, pid, nullptr, sig);
    }
  }

  // Wait for pipe reader threads to finish.
  // The threads exit when all write-end references are closed (i.e., all child
  // processes have exited), so this join completes shortly after the ptrace loop.
  stdout_reader.join();
  stderr_reader.join();
  close(stdout_pipe[0]);
  close(stderr_pipe[0]);

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
// Audit mode: structured logging of broker decisions and sandbox events
// =============================================================================
//
// When g_audit_mode is true, every broker decision, exec, fork/clone,
// process exit, and policy violation is logged as one JSON line per event.
// This enables post-hoc security review without modifying the security model.
//
// Log format (one JSON object per line):
//   {"ts":1234567890.123,"pid":42,"event":"broker","syscall":"openat",
//    "nr":257,"path":"/etc/passwd","flags":"O_RDONLY","decision":"allow",
//    "risk":"LOW"}
//
// Event types:
//   "broker"  - filesystem syscall validated by ptrace broker
//   "block"   - syscall blocked by SECCOMP_RET_TRACE(TRACE_BLOCKED)
//   "exec"    - execve/execveat attempt (with allow/deny)
//   "kill"    - kill/tgkill/tkill to PID 1 (always logged)
//   "fork"    - new process created (fork/vfork/clone)
//   "exit"    - process exited
//   "signal"  - signal delivered to sandboxed process
//   "sigsys"  - SIGSYS from SECCOMP_RET_TRAP (seccomp violation)
//   "init"    - sandbox initialized (logs configuration)
//   "empty_path" - empty-path denial (fd-based bypass attempt)

static void audit_log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void audit_log(const char* fmt, ...) {
  if (!g_audit_mode) return;

  int fd = (g_audit_fd >= 0) ? g_audit_fd : STDERR_FILENO;

  char buf[4096];
  va_list ap;
  va_start(ap, fmt);
  int len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (len > 0 && len < (int)sizeof(buf)) {
    // Append newline if not present
    if (buf[len - 1] != '\n') {
      buf[len++] = '\n';
    }
    // Write atomically (single write call)
    (void)write(fd, buf, len);
  }
}

// Get monotonic timestamp as fractional seconds (for audit log ordering)
static double audit_timestamp() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec / 1e9;
}

// Format open flags as human-readable string
static std::string format_open_flags(int flags) {
  std::string s;
  int access = flags & O_ACCMODE;
  if (access == O_RDONLY) s = "O_RDONLY";
  else if (access == O_WRONLY) s = "O_WRONLY";
  else if (access == O_RDWR) s = "O_RDWR";
  if (flags & O_CREAT)  s += "|O_CREAT";
  if (flags & O_EXCL)   s += "|O_EXCL";
  if (flags & O_TRUNC)  s += "|O_TRUNC";
  if (flags & O_APPEND) s += "|O_APPEND";
  if (flags & O_CLOEXEC) s += "|O_CLOEXEC";
  return s;
}

// =============================================================================
// Interactive execution: fork + ptrace broker + seccomp, stdio on terminal
// =============================================================================
//
// For running interactive commands (like `claude`) inside the sandbox WITH
// the full Chrome security model including the filesystem broker.
//
// Same as exec_with_tracing() EXCEPT:
//   - Does NOT redirect stdin/stdout/stderr (terminal passthrough)
//   - Does NOT collect detailed syscall logs (performance)
//   - Still uses ptrace for the filesystem broker (path validation)
//   - Still applies seccomp-BPF filtering (STRICT/PERMISSIVE/TRACE_ALL)
//   - Forwards signals (SIGINT, SIGTERM) to the sandboxed child
//
// Security model is IDENTICAL to exec_with_tracing():
//   All 8 layers active including the ptrace-based filesystem broker.
//   The only difference is stdio routing and log collection.

static pid_t g_passthrough_child = -1;

static void passthrough_signal_handler(int sig) {
  // Forward signals to the sandboxed child
  if (g_passthrough_child > 0) {
    kill(g_passthrough_child, sig);
  }
}

static int exec_passthrough(const char* const* argv) {
  pid_t child = fork();
  if (child < 0) return -1;

  if (child == 0) {
    // === CHILD (sandboxed target) ===
    // stdin/stdout/stderr are inherited from parent (terminal passthrough)
    // NO pipe redirection — interactive I/O flows directly to the terminal.

    // Allow ptrace from parent (same as exec_with_tracing)
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    raise(SIGSTOP);  // Wait for parent to set up tracing

    // Namespace isolation (same as exec_with_tracing)
    NamespaceStatus ns_status = {};
    if (g_in_zygote) {
      ns_status.user_ns = true;
      ns_status.mount_ns = true;
      ns_status.net_ns = true;
      ns_status.ipc_ns = true;
      ns_status.caps_dropped = false;
      // Create PID namespace for this command
      ns_status.pid_ns = setup_pid_namespace();
    } else {
      ns_status = apply_namespace_isolation();
    }

    // PID namespace fork (same as exec_with_tracing)
    if (ns_status.pid_ns) {
      pid_t ns_child = fork();
      if (ns_child < 0) _exit(125);
      if (ns_child > 0) {
        int exit_code = 1;
        for (;;) {
          int reaper_status;
          pid_t reaped = waitpid(-1, &reaper_status, 0);
          if (reaped < 0) { if (errno == EINTR) continue; break; }
          if (reaped == ns_child) {
            exit_code = WIFEXITED(reaper_status)
                            ? WEXITSTATUS(reaper_status) : 1;
          }
        }
        _exit(exit_code);
      }
      mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);
    }

    // Drop CAP_SYS_ADMIN if still held (zygote path preserves it for PID NS)
    if (!ns_status.caps_dropped) {
      drop_all_capabilities();
    }

    // Install seccomp-BPF (same as exec_with_tracing - STRICT policy works!)
    auto policy = std::make_unique<AgentSandboxPolicy>(
        g_policy_level, g_extra_ioctls, g_extra_sockopts,
        !g_enable_network_isolation);
    sandbox::SandboxBPF sandbox_bpf(std::move(policy));
    if (!sandbox_bpf.StartSandbox(sandbox::SandboxBPF::SeccompLevel::SINGLE_THREADED)) {
      _exit(126);
    }

    // chdir to workspace (same as exec_with_tracing)
    if (!g_allowed_paths.empty()) {
      chdir(g_allowed_paths[0].c_str());
    }

    execvp(argv[0], const_cast<char* const*>(argv));
    perror("exec");
    _exit(127);
  }

  // === PARENT (tracer/broker - same security as exec_with_tracing) ===
  g_passthrough_child = child;

  // Forward SIGINT and SIGTERM to the child
  struct sigaction sa = {};
  sa.sa_handler = passthrough_signal_handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);

  // Wait for child's SIGSTOP
  int status;
  waitpid(child, &status, 0);

  // Set ptrace options (same as exec_with_tracing)
  long ptrace_opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD |
                     PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                     PTRACE_O_TRACEEXIT;
  ptrace(PTRACE_SETOPTIONS, child, nullptr, ptrace_opts);

  // Build the broker permission list (same as exec_with_tracing)
  auto broker_perms = build_broker_permissions();
  sandbox::syscall_broker::BrokerPermissionList broker_policy(
      EACCES, std::move(broker_perms));

  // Resume the child to start execution.
  //
  // On kernel 4.4, PTRACE_CONT does NOT stop for SECCOMP_RET_TRACE events
  // (this was fixed in kernel 4.8+). We must use PTRACE_SYSCALL to see
  // seccomp events on older kernels. This causes more tracer stops but is
  // necessary for correctness.
  //
  // Performance optimization for interactive passthrough mode:
  // - STRICT policy: only dangerous/filesystem syscalls trigger SECCOMP_RET_TRACE,
  //   so the overhead is bounded to ~100 broker decisions during startup.
  // - TRACE_ALL policy: every syscall triggers SECCOMP_RET_TRACE, which is slow
  //   with multi-threaded programs. Use STRICT for production workloads.
  ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);

  // Exec policy tracking
  std::map<pid_t, int> exec_count;
  std::set<pid_t> traced_pids = {child};
  int exit_code = 0;

  // CWD tracking per PID (same as exec_with_tracing — see comment there)
  std::map<pid_t, std::string> cwd_map;
  std::string pt_initial_cwd = g_allowed_paths.empty() ? "/" : g_allowed_paths[0];
  cwd_map[child] = pt_initial_cwd;
  // Last fork parent's CWD: used to assign CWD to new PIDs that appear
  // in waitpid but weren't added via PTRACE_GETEVENTMSG (PID namespace
  // mapping causes GETEVENTMSG to return inner-namespace PIDs while
  // waitpid returns outer-namespace PIDs).
  std::string last_fork_cwd = pt_initial_cwd;

  // Ptrace broker loop — same security as exec_with_tracing but:
  //   - Uses PTRACE_CONT for performance (no entry/exit stops)
  //   - No syscall log collection
  //   - No stdout/stderr pipe reading
  //   - Full broker validation still active via SECCOMP_RET_TRACE
  while (!traced_pids.empty()) {
    pid_t pid;
    int wstatus;
    pid = waitpid(-1, &wstatus, __WALL);
    if (pid < 0) {
      if (errno == EINTR) continue;
      audit_log("{\"ts\":%.3f,\"event\":\"waitpid_error\",\"errno\":%d}", audit_timestamp(), errno);
      break;
    }

    if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
      if (pid == child) {
        exit_code = WIFEXITED(wstatus)
            ? WEXITSTATUS(wstatus)
            : 128 + WTERMSIG(wstatus);
      }
      if (WIFEXITED(wstatus)) {
        audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"exit\",\"code\":%d}",
                  audit_timestamp(), pid, WEXITSTATUS(wstatus));
      } else {
        audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"exit\",\"signal\":%d}",
                  audit_timestamp(), pid, WTERMSIG(wstatus));
      }
      traced_pids.erase(pid);
      exec_count.erase(pid);
      cwd_map.erase(pid);
      continue;
    }

    if (!WIFSTOPPED(wstatus)) continue;

    int sig = WSTOPSIG(wstatus);
    int event = (wstatus >> 16) & 0xFF;

    if (event == PTRACE_EVENT_SECCOMP) {
      // Auto-assign CWD for PIDs not yet in cwd_map (PID namespace mismatch:
      // PTRACE_GETEVENTMSG returns inner-namespace PID, waitpid returns outer)
      if (cwd_map.find(pid) == cwd_map.end()) {
        cwd_map[pid] = last_fork_cwd;
      }

      // SECCOMP_RET_TRACE: handle broker/block decisions (SAME as exec_with_tracing)
      unsigned long trace_data = 0;
      ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &trace_data);

      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        int nr = (int)regs.orig_rax;

        if (trace_data == AgentSandboxPolicy::TRACE_BLOCKED) {
          // Block: skip syscall, return -EPERM
          regs.orig_rax = -1;
          regs.rax = (unsigned long long)(-EPERM);
          ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
          audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"block\",\"syscall\":\"%s\",\"nr\":%d,\"decision\":\"deny\",\"risk\":\"%s\"}",
                    audit_timestamp(), pid, syscall_name(nr), nr, syscall_risk(nr));

        } else if (trace_data == AgentSandboxPolicy::TRACE_BROKER) {
          // Broker: validate filesystem path (same logic as exec_with_tracing)
          std::string path_str;
          int open_flags = 0;
          unsigned long path_addr = 0;  // For TOCTOU defense

          // Extract path from syscall args (same as exec_with_tracing)
          if (nr == __NR_openat || nr == __NR_faccessat ||
              nr == __NR_faccessat2 || nr == __NR_newfstatat ||
              nr == __NR_mkdirat || nr == __NR_unlinkat ||
              nr == __NR_fchmodat || nr == __NR_fchownat ||
              nr == __NR_readlinkat || nr == __NR_linkat ||
              nr == __NR_symlinkat || nr == __NR_utimensat ||
              nr == __NR_execveat) {
            path_addr = regs.rsi;
            path_str = read_child_string(pid, path_addr);
            if (nr == __NR_openat) open_flags = (int)regs.rdx;
          } else if (nr == __NR_renameat || nr == __NR_renameat2) {
            path_addr = regs.rsi;
            path_str = read_child_string(pid, path_addr);
          } else if (nr == __NR_open || nr == __NR_access ||
                     nr == __NR_stat || nr == __NR_lstat ||
                     nr == __NR_execve || nr == __NR_unlink ||
                     nr == __NR_mkdir || nr == __NR_rmdir ||
                     nr == __NR_chmod || nr == __NR_chown ||
                     nr == __NR_chdir || nr == __NR_truncate ||
                     nr == __NR_readlink || nr == __NR_creat ||
                     nr == __NR_link || nr == __NR_symlink ||
                     nr == __NR_rename || nr == __NR_statfs ||
                     nr == __NR_lchown || nr == __NR_mknod) {
            path_addr = regs.rdi;
            path_str = read_child_string(pid, path_addr);
            if (nr == __NR_open) open_flags = (int)regs.rsi;
            if (nr == __NR_creat) open_flags = O_CREAT | O_WRONLY | O_TRUNC;
          }

          // Lexical path normalization (same as exec_with_tracing).
          std::string original_path_str = path_str;
          if (!path_str.empty() && path_str[0] == '/') {
            path_str = normalize_path_lexical(path_str);
          }

          // Resolve relative paths to absolute (same as exec_with_tracing).
          // See comment there for security rationale and skip_writeback note.
          bool skip_writeback = false;
          if (!path_str.empty() && path_str[0] != '/') {
            std::string resolved = resolve_relative_path(cwd_map[pid], path_str);
            if (!resolved.empty()) {
              path_str = resolved;
              skip_writeback = true;
            }
          }

          // Handle kill/tgkill/tkill: protect namespace init (PID 1)
          // Same as exec_with_tracing — block signals to PID 1.
          if (nr == __NR_kill || nr == __NR_tgkill || nr == __NR_tkill) {
            pid_t target = (pid_t)regs.rdi;
            if (target == 1) {
              regs.orig_rax = -1;
              regs.rax = (unsigned long long)(-EPERM);
              ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
              audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"kill\",\"syscall\":\"%s\",\"nr\":%d,\"target\":1,\"decision\":\"deny\",\"risk\":\"HIGH\"}",
                        audit_timestamp(), pid, syscall_name(nr), nr);
            } else {
              audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"kill\",\"syscall\":\"%s\",\"nr\":%d,\"target\":%d,\"decision\":\"allow\",\"risk\":\"HIGH\"}",
                        audit_timestamp(), pid, syscall_name(nr), nr, (int)target);
            }
          }
          // Handle exec policy (same as exec_with_tracing)
          else if (nr == __NR_execve || nr == __NR_execveat) {
            exec_count[pid]++;
            bool allow_exec = true;
            if (g_exec_policy == SANDBOX_EXEC_BLOCKED) {
              allow_exec = false;
            } else if (g_exec_policy == SANDBOX_EXEC_CHROME) {
              allow_exec = (exec_count[pid] <= 1);
            } else {
              // BROKERED: check path
              if (!path_str.empty()) {
                const char* path_c = path_str.c_str();
                auto result = broker_policy.GetFileNameIfAllowedToOpen(
                    path_c, O_RDONLY);
                allow_exec = (result.first != nullptr);
              }
            }
            if (!allow_exec) {
              regs.orig_rax = -1;
              regs.rax = (unsigned long long)(-EACCES);
              ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
            }
            audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"exec\",\"syscall\":\"%s\",\"nr\":%d,\"path\":\"%s\",\"decision\":\"%s\",\"risk\":\"HIGH\"}",
                      audit_timestamp(), pid, syscall_name(nr), nr,
                      json_escape(path_str).c_str(),
                      allow_exec ? "allow" : "deny");
          }
          // getcwd: always allow (no path to validate, safe in chroot)
          else if (nr == __NR_getcwd) {
            // Allow — no security risk, returns the chroot-relative CWD
          }
          // Empty path for non-kill/exec/getcwd broker syscalls: deny.
          // Prevents fchdir and other fd-based syscalls from bypassing the broker.
          else if (path_str.empty()) {
            regs.orig_rax = -1;
            regs.rax = (unsigned long long)(-EACCES);
            ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
            audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"empty_path\",\"syscall\":\"%s\",\"nr\":%d,\"decision\":\"deny\",\"risk\":\"%s\"}",
                      audit_timestamp(), pid, syscall_name(nr), nr, syscall_risk(nr));
          }
          // Bun virtual filesystem: /$bunfs/ (same rationale as exec_with_tracing)
          else if (path_str.size() > 8 && path_str.compare(0, 8, "/$bunfs/") == 0) {
            // Allow: paths don't exist on disk, kernel returns ENOENT,
            // Bun serves from embedded memory. No escape vector.
          }
          // Handle filesystem broker (same validation as exec_with_tracing)
          else {
            const char* path_c = path_str.c_str();
            bool allowed = false;

            // Strip O_CLOEXEC: Chrome's SIGSYS broker also strips it because
            // the broker proxies file operations but not FD flags. We check
            // the access mode (read/write/create) only.
            int broker_flags = open_flags & ~O_CLOEXEC;

            if (nr == __NR_open || nr == __NR_openat || nr == __NR_creat) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, broker_flags);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_access || nr == __NR_faccessat ||
                       nr == __NR_faccessat2 || nr == __NR_stat ||
                       nr == __NR_lstat || nr == __NR_newfstatat ||
                       nr == __NR_readlink || nr == __NR_readlinkat ||
                       nr == __NR_statfs || nr == __NR_chdir) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_RDONLY);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_mkdir || nr == __NR_mkdirat) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_RDWR | O_CREAT);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_unlink || nr == __NR_unlinkat ||
                       nr == __NR_rmdir) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_RDWR);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_rename || nr == __NR_renameat ||
                       nr == __NR_renameat2) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_RDWR);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_chmod || nr == __NR_fchmodat ||
                       nr == __NR_chown || nr == __NR_fchownat ||
                       nr == __NR_lchown) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_RDWR);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_truncate) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_WRONLY);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_link || nr == __NR_linkat ||
                       nr == __NR_symlink || nr == __NR_symlinkat) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_RDWR | O_CREAT);
              allowed = (result.first != nullptr);
            } else if (nr == __NR_mknod || nr == __NR_mknodat) {
              allowed = false;
            } else if (nr == __NR_utimensat || nr == __NR_utimes ||
                       nr == __NR_futimesat) {
              auto result = broker_policy.GetFileNameIfAllowedToOpen(
                  path_c, O_RDWR);
              allowed = (result.first != nullptr);
            } else {
              allowed = false;
            }

            // Deny-list override (same as exec_with_tracing broker).
            if (allowed && !path_str.empty() && is_path_denied(path_str)) {
              allowed = false;
            }

            if (!allowed) {
              regs.orig_rax = -1;
              regs.rax = -broker_policy.denied_errno();
              ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
            } else {
              // Track CWD changes for relative path resolution
              if (nr == __NR_chdir && !path_str.empty()) {
                cwd_map[pid] = path_str;
              }
              if (path_addr != 0 && !path_str.empty() && !skip_writeback) {
                // TOCTOU defense: rewrite validated path (same as exec_with_tracing).
                // Skip when normalization shortened the path — see exec_with_tracing
                // comment for why (ld.so in-place buffer modification).
                if (path_str.size() >= original_path_str.size()) {
                  write_child_string(pid, path_addr, path_str);
                }
              }
            }

            // Audit: log broker decision (only for non-trivial paths to reduce noise)
            if (g_audit_mode) {
              const char* name = syscall_name(nr);
              const char* risk = syscall_risk(nr);
              std::string flags_str = (nr == __NR_open || nr == __NR_openat || nr == __NR_creat)
                  ? format_open_flags(open_flags) : "";
              if (flags_str.empty()) {
                audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"broker\",\"syscall\":\"%s\",\"nr\":%d,\"path\":\"%s\",\"decision\":\"%s\",\"risk\":\"%s\"}",
                          audit_timestamp(), pid, name, nr,
                          json_escape(path_str).c_str(),
                          allowed ? "allow" : "deny", risk);
              } else {
                audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"broker\",\"syscall\":\"%s\",\"nr\":%d,\"path\":\"%s\",\"flags\":\"%s\",\"decision\":\"%s\",\"risk\":\"%s\"}",
                          audit_timestamp(), pid, name, nr,
                          json_escape(path_str).c_str(),
                          flags_str.c_str(),
                          allowed ? "allow" : "deny", risk);
              }
            }
          }
        }
      }
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_FORK ||
               event == PTRACE_EVENT_VFORK ||
               event == PTRACE_EVENT_CLONE) {
      unsigned long new_pid;
      ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
      traced_pids.insert(static_cast<pid_t>(new_pid));
      // Child inherits parent's CWD.
      // Note: new_pid may be from inner PID namespace (GETEVENTMSG returns
      // namespace-relative PID), so we also save last_fork_cwd for PIDs
      // that appear in waitpid with outer-namespace PIDs.
      cwd_map[static_cast<pid_t>(new_pid)] = cwd_map[pid];
      last_fork_cwd = cwd_map[pid];
      audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"fork\",\"child\":%lu,\"type\":\"%s\"}",
                audit_timestamp(), pid, new_pid,
                event == PTRACE_EVENT_FORK ? "fork" :
                event == PTRACE_EVENT_VFORK ? "vfork" : "clone");
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_EXEC) {
      audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"exec_complete\"}",
                audit_timestamp(), pid);
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (event == PTRACE_EVENT_EXIT) {
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (sig == (SIGTRAP | 0x80)) {
      // Syscall entry/exit stop from PTRACE_SYSCALL — just continue.
      // We use PTRACE_SYSCALL (not PTRACE_CONT) because kernel 4.4 requires it
      // to see SECCOMP_RET_TRACE events. The cost is extra stops for every
      // syscall entry/exit, but this is necessary for correctness.
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);

    } else if (sig == SIGTRAP) {
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    } else if (sig == SIGSTOP) {
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    } else if (sig == SIGSYS) {
      // SIGSYS from SECCOMP_RET_TRAP: suppress and return -ENOSYS
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"sigsys\",\"syscall\":\"%s\",\"nr\":%d,\"risk\":\"%s\"}",
                  audit_timestamp(), pid, syscall_name((int)regs.orig_rax), (int)regs.orig_rax,
                  syscall_risk((int)regs.orig_rax));
        regs.rax = (unsigned long long)(-ENOSYS);
        ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
      }
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    } else {
      // Deliver other signals to child
      audit_log("{\"ts\":%.3f,\"pid\":%d,\"event\":\"signal\",\"signal\":%d}",
                audit_timestamp(), pid, sig);
      ptrace(PTRACE_SYSCALL, pid, nullptr, sig);
    }
  }

  g_passthrough_child = -1;
  signal(SIGINT, SIG_DFL);
  signal(SIGTERM, SIG_DFL);

  return exit_code;
}

// =============================================================================
// Broker implementation using Chrome's real BrokerProcess
// =============================================================================

static std::vector<sandbox::syscall_broker::BrokerFilePermission>
build_broker_permissions() {
  using sandbox::syscall_broker::BrokerFilePermission;
  std::vector<BrokerFilePermission> perms;

  // Root directory: read-only (needed for ls /, directory listing)
  perms.push_back(BrokerFilePermission::ReadOnly("/"));

  // System paths: read-only (same as Chrome's renderer broker)
  // These are the paths needed for dynamic linking, library loading,
  // and basic command execution within the sandbox.
  //
  // Each directory needs BOTH:
  //   ReadOnly("/path")           - so stat/lstat on the directory itself works
  //   ReadOnlyRecursive("/path/") - so files inside can be read
  // Without the ReadOnly on the dir itself, stat("/usr/lib") returns EACCES
  // which breaks runtimes that walk parent directories (Python, Ruby, etc.).
  perms.push_back(BrokerFilePermission::ReadOnly("/lib"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/lib/"));
  perms.push_back(BrokerFilePermission::ReadOnly("/lib64"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/lib64/"));
  perms.push_back(BrokerFilePermission::ReadOnly("/usr"));
  perms.push_back(BrokerFilePermission::ReadOnly("/usr/lib"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/usr/lib/"));
  perms.push_back(BrokerFilePermission::ReadOnly("/usr/share"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/usr/share/"));
  // /etc: restricted read-only access (matches selective bind-mount).
  // Only safe configuration files are mounted; sensitive files like
  // /etc/shadow, /etc/sudoers, /etc/ssh/ are NOT in the chroot.
  // The broker still needs to allow reads for whatever IS mounted.
  perms.push_back(BrokerFilePermission::ReadOnly("/etc"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/etc/"));

  // Executable paths: read-only (needed for execve, which the broker validates)
  perms.push_back(BrokerFilePermission::ReadOnly("/bin"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/bin/"));
  perms.push_back(BrokerFilePermission::ReadOnly("/sbin"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/sbin/"));
  perms.push_back(BrokerFilePermission::ReadOnly("/usr/bin"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/usr/bin/"));
  perms.push_back(BrokerFilePermission::ReadOnly("/usr/sbin"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/usr/sbin/"));

  // /proc: read-only access.
  // Security relies on PID namespace isolation (each command gets its own
  // PID NS) so /proc only shows sandbox processes — NOT broker restrictions.
  // This allows ps, top, /proc/self/* to work naturally inside the sandbox.
  perms.push_back(BrokerFilePermission::ReadOnly("/proc"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/proc/"));

  // Device files: specific devices only
  perms.push_back(BrokerFilePermission::ReadWriteCreate("/dev/null"));
  perms.push_back(BrokerFilePermission::ReadOnly("/dev/urandom"));
  perms.push_back(BrokerFilePermission::ReadOnly("/dev/random"));
  perms.push_back(BrokerFilePermission::ReadOnly("/dev/zero"));

  // /tmp: read-write-create (sandboxed scratch space)
  // ReadOnly on /tmp itself so stat/lstat works (Node.js mkdirSync checks
  // existence before creating). Recursive write on contents.
  perms.push_back(BrokerFilePermission::ReadOnly("/tmp"));
  perms.push_back(BrokerFilePermission::ReadWriteCreateRecursive("/tmp/"));

  // Add user-configured read-only paths (runtimes, tools, SDKs)
  for (const auto& path : g_readonly_paths) {
    if (!path.empty() && path[0] == '/') {
      // Add the directory itself (without slash) so lstat works on it
      perms.push_back(BrokerFilePermission::ReadOnly(path));
      // Add recursive access to contents
      std::string p = path;
      if (p.back() != '/') p += '/';
      perms.push_back(BrokerFilePermission::ReadOnlyRecursive(p));
      // Add parent directories so realpathSync() can walk the path.
      // Only the directory entries themselves (not contents) are exposed.
      std::string parent = path;
      while (parent.size() > 1) {
        size_t pos = parent.rfind('/');
        if (pos == 0) break;  // root already in perms
        parent = parent.substr(0, pos);
        perms.push_back(BrokerFilePermission::ReadOnly(parent));
      }
    }
  }

  // Add user-configured paths with full access (workspaces, scratch dirs)
  for (const auto& path : g_allowed_paths) {
    if (!path.empty() && path[0] == '/') {
      // Ensure trailing slash for recursive matching
      std::string p = path;
      if (p.back() != '/') p += '/';
      perms.push_back(BrokerFilePermission::ReadWriteCreateRecursive(p));
    }
  }

  return perms;
}

// =============================================================================
// Zygote main loop
// =============================================================================
//
// The zygote process sits in a pre-sandboxed state (namespaces applied,
// chroot active, capabilities dropped) and waits for commands from the
// agent process via socketpair. For each command:
//   1. Read command + policies from agent
//   2. Fork a worker (worker inherits sandbox from zygote!)
//   3. Worker calls exec_with_tracing() (applies PID NS + seccomp + exec)
//   4. Send results back to agent
//
// This matches Chrome's zygote model:
//   Chrome: Zygote fork → child applies seccomp → runs renderer code
//   Us:     Zygote fork → child applies PID NS + seccomp → execs command

[[noreturn]] static void zygote_main(int zygote_fd) {
  g_in_zygote = true;

  // Apply namespace isolation ONCE in the zygote.
  // All forked children will inherit this sandbox.
  // Layers applied here: user NS, IPC NS, net NS, mount NS, chroot,
  // capability drop, PR_SET_DUMPABLE, RLIMIT_CORE, Yama, RLIMIT_DATA.
  // PID NS is NOT applied here — it's per-command (each command gets its own).
  apply_namespace_isolation(/*skip_pid_ns=*/true);

  // Main command loop.
  for (;;) {
    std::vector<std::string> args;
    SandboxExecPolicy exec_policy;
    SandboxPolicyLevel sandbox_policy;
    std::set<unsigned long> cmd_extra_ioctls;
    std::set<int> cmd_extra_sockopts;
    bool passthrough = false;

    if (!zygote_recv_command(zygote_fd, args, exec_policy, sandbox_policy,
                             cmd_extra_ioctls, cmd_extra_sockopts,
                             passthrough)) {
      break;  // Agent closed the socket or sent invalid data
    }

    // Apply per-command policies
    g_exec_policy = exec_policy;
    g_policy_level = sandbox_policy;
    // Per-exec seccomp extensions (scoped to this single command)
    g_extra_ioctls = std::move(cmd_extra_ioctls);
    g_extra_sockopts = std::move(cmd_extra_sockopts);

    // Audit log: report active extensions
    if (!g_extra_ioctls.empty() || !g_extra_sockopts.empty()) {
      fprintf(stderr, "[sandbox-audit] exec extensions: %zu ioctls, %zu sockopts\n",
              g_extra_ioctls.size(), g_extra_sockopts.size());
    }

    // Build argv
    std::vector<const char*> argv;
    for (const auto& a : args) argv.push_back(a.c_str());
    argv.push_back(nullptr);

    if (passthrough) {
      // Passthrough mode: stdio stays on terminal, full broker active.
      // Security model is IDENTICAL to standard mode (all 8 layers):
      //   namespace isolation + chroot + capability drop + seccomp-BPF
      //   + ptrace filesystem broker. Only difference: no stdio capture,
      //   no syscall log collection.
      int exit_code = exec_passthrough(argv.data());

      // Send a minimal result back (no stdout/stderr/syscall data)
      SandboxResult cmd_result = {};
      cmd_result.exit_code = exit_code;
      zygote_send_result(zygote_fd, cmd_result);

    } else {
      // Standard mode: capture stdout/stderr, full ptrace tracing
      SandboxResult cmd_result = exec_with_tracing(argv.data());

      // Clear per-exec extensions (auto-reset after each command)
      g_extra_ioctls.clear();
      g_extra_sockopts.clear();

      // Send results back to the agent
      zygote_send_result(zygote_fd, cmd_result);

      // Free result buffers
      free(cmd_result.stdout_buf);
      free(cmd_result.stderr_buf);
      free(cmd_result.syscall_log);
    }
  }

  _exit(0);
}

// =============================================================================
// C API implementation
// =============================================================================

extern "C" {

int sandbox_init(void) {
  if (g_initialized) return 0;

  // Create socketpair for agent ↔ zygote IPC
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    return -1;
  }

  // Fork the zygote process
  pid_t zygote = fork();
  if (zygote < 0) {
    close(sv[0]);
    close(sv[1]);
    return -1;
  }

  if (zygote == 0) {
    // === ZYGOTE PROCESS ===
    close(sv[0]);  // Close agent side
    zygote_main(sv[1]);
    // zygote_main never returns
  }

  // === AGENT PROCESS ===
  close(sv[1]);  // Close zygote side
  g_zygote_pid = zygote;
  g_zygote_fd = sv[0];
  g_initialized = true;

  // Audit: log sandbox initialization with configuration
  if (g_audit_mode) {
    std::string allowed_str, readonly_str;
    for (const auto& p : g_allowed_paths) {
      if (!allowed_str.empty()) allowed_str += ":";
      allowed_str += p;
    }
    for (const auto& p : g_readonly_paths) {
      if (!readonly_str.empty()) readonly_str += ":";
      readonly_str += p;
    }
    const char* policy_name =
        g_policy_level == SANDBOX_POLICY_STRICT ? "STRICT" :
        g_policy_level == SANDBOX_POLICY_PERMISSIVE ? "PERMISSIVE" : "TRACE_ALL";
    const char* exec_name =
        g_exec_policy == SANDBOX_EXEC_CHROME ? "CHROME" :
        g_exec_policy == SANDBOX_EXEC_BROKERED ? "BROKERED" : "BLOCKED";
    audit_log("{\"ts\":%.3f,\"event\":\"init\",\"zygote_pid\":%d,\"policy\":\"%s\",\"exec_policy\":\"%s\",\"network\":%s,\"namespaces\":%s,\"allowed_paths\":\"%s\",\"readonly_paths\":\"%s\"}",
              audit_timestamp(), (int)zygote, policy_name, exec_name,
              g_enable_network_isolation ? "false" : "true",
              g_enable_namespaces ? "true" : "false",
              json_escape(allowed_str).c_str(),
              json_escape(readonly_str).c_str());
  }

  return 0;
}

void sandbox_shutdown(void) {
  if (g_zygote_pid > 0) {
    // Close the socket — this will cause the zygote to exit its loop
    if (g_zygote_fd >= 0) {
      close(g_zygote_fd);
      g_zygote_fd = -1;
    }
    // Wait for zygote to exit
    int status;
    waitpid(g_zygote_pid, &status, 0);
    g_zygote_pid = -1;
  }
  g_broker.reset();
  g_initialized = false;

  // Close audit log fd
  if (g_audit_owns_fd && g_audit_fd >= 0) {
    close(g_audit_fd);
    g_audit_fd = -1;
    g_audit_owns_fd = false;
  }
  g_audit_mode = false;
}

void sandbox_set_policy(SandboxPolicyLevel level) {
  g_policy_level = level;
}

void sandbox_set_exec_policy(SandboxExecPolicy policy) {
  g_exec_policy = policy;
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

int sandbox_set_readonly_paths(const char* paths) {
  g_readonly_paths.clear();
  if (!paths) return 0;
  std::string p(paths);
  size_t pos = 0;
  while ((pos = p.find(':')) != std::string::npos) {
    g_readonly_paths.push_back(p.substr(0, pos));
    p.erase(0, pos + 1);
  }
  if (!p.empty()) g_readonly_paths.push_back(p);
  return 0;
}

int sandbox_set_denied_paths(const char* paths) {
  g_denied_paths.clear();
  if (!paths) return 0;
  std::string p(paths);
  size_t pos = 0;
  while ((pos = p.find(':')) != std::string::npos) {
    g_denied_paths.push_back(p.substr(0, pos));
    p.erase(0, pos + 1);
  }
  if (!p.empty()) g_denied_paths.push_back(p);
  return 0;
}

int sandbox_allow_ioctls(const unsigned long* cmds, int count) {
  if (!cmds || count <= 0) return -1;
  for (int i = 0; i < count; i++) {
    g_extra_ioctls.insert(cmds[i]);
  }
  return 0;
}

int sandbox_allow_sockopts(const int* optnames, int count) {
  if (!optnames || count <= 0) return -1;
  for (int i = 0; i < count; i++) {
    g_extra_sockopts.insert(optnames[i]);
  }
  return 0;
}

void sandbox_clear_extensions(void) {
  g_extra_ioctls.clear();
  g_extra_sockopts.clear();
}

void sandbox_set_network_enabled(int enabled) {
  g_enable_network_isolation = (enabled == 0);  // enabled=1 means allow network
}

SandboxResult sandbox_exec(const char* const* argv) {
  // Capture current extensions (will be sent via IPC then auto-cleared)
  std::set<unsigned long> exec_ioctls = g_extra_ioctls;
  std::set<int> exec_sockopts = g_extra_sockopts;

  // Auto-clear extensions after capturing (per-exec scoping)
  g_extra_ioctls.clear();
  g_extra_sockopts.clear();

  // If zygote is running, dispatch via zygote for inherited namespace isolation
  if (g_zygote_pid > 0 && g_zygote_fd >= 0) {
    if (zygote_send_command(g_zygote_fd, argv, g_exec_policy, g_policy_level,
                            exec_ioctls, exec_sockopts)) {
      SandboxResult result = {};
      if (zygote_recv_result(g_zygote_fd, result)) {
        return result;
      }
    }
    // Zygote IPC failed — fall back to direct execution
    SandboxResult err = {};
    err.exit_code = -1;
    return err;
  }
  // No zygote — run directly (applies namespace isolation per-call)
  // Set globals for exec_with_tracing to pick up
  g_extra_ioctls = std::move(exec_ioctls);
  g_extra_sockopts = std::move(exec_sockopts);
  SandboxResult result = exec_with_tracing(argv);
  g_extra_ioctls.clear();
  g_extra_sockopts.clear();
  return result;
}

SandboxResult sandbox_exec_shell(const char* cmd) {
  const char* argv[] = {"/bin/sh", "-c", cmd, nullptr};
  return sandbox_exec(argv);
}

int sandbox_exec_interactive(const char* const* argv) {
  // Interactive execution with FULL Chrome security model.
  //
  // ALL 8 security layers active (identical to sandbox_exec):
  //   1. User namespace isolation
  //   2. PID namespace isolation
  //   3. IPC namespace isolation
  //   4. Network namespace (unless explicitly disabled)
  //   5. Mount namespace + chroot/pivot_root
  //   6. Capability dropping
  //   7. seccomp-BPF filtering (STRICT/PERMISSIVE/TRACE_ALL)
  //   8. ptrace-based filesystem broker (path validation on every FS syscall)
  //
  // Only difference from sandbox_exec: stdio stays on the terminal.
  // No syscall log collection (performance optimization for interactive use).

  // Capture and clear extensions
  std::set<unsigned long> exec_ioctls = g_extra_ioctls;
  std::set<int> exec_sockopts = g_extra_sockopts;
  g_extra_ioctls.clear();
  g_extra_sockopts.clear();

  if (g_zygote_pid > 0 && g_zygote_fd >= 0) {
    // Dispatch via zygote with passthrough flag
    if (zygote_send_command(g_zygote_fd, argv, g_exec_policy, g_policy_level,
                            exec_ioctls, exec_sockopts,
                            /*passthrough=*/true)) {
      SandboxResult result = {};
      if (zygote_recv_result(g_zygote_fd, result)) {
        int exit_code = result.exit_code;
        sandbox_result_free(&result);
        return exit_code;
      }
    }
    return -1;  // IPC failed
  }

  // No zygote — direct passthrough execution
  g_extra_ioctls = std::move(exec_ioctls);
  g_extra_sockopts = std::move(exec_sockopts);

  int code = exec_passthrough(argv);

  g_extra_ioctls.clear();
  g_extra_sockopts.clear();
  return code;
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

int sandbox_set_audit_mode(int enabled, const char* log_path) {
  // Close previous audit fd if we own it
  if (g_audit_owns_fd && g_audit_fd >= 0) {
    close(g_audit_fd);
    g_audit_fd = -1;
    g_audit_owns_fd = false;
  }

  g_audit_mode = (enabled != 0);
  if (!g_audit_mode) return 0;

  if (log_path && log_path[0] != '\0') {
    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
      g_audit_mode = false;
      return -1;
    }
    g_audit_fd = fd;
    g_audit_owns_fd = true;
  } else {
    // Default to stderr
    g_audit_fd = -1;
    g_audit_owns_fd = false;
  }

  return 0;
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
