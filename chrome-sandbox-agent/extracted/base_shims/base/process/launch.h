// Copyright 2013 The Chromium Authors
// Standalone shim: base/process/launch.h

#ifndef BASE_PROCESS_LAUNCH_H_
#define BASE_PROCESS_LAUNCH_H_

#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/files/file_path.h"
#include "base/files/scoped_file.h"
#include "base/process/process.h"
#include "base/process/process_handle.h"

namespace base {

struct LaunchOptions {
  bool wait = false;
  bool allow_new_privs = false;
  bool kill_on_parent_death = false;
  bool new_process_group = false;
  std::string current_directory;
  std::map<std::string, std::string> environment;
  // fds_to_remap: vector of (target_fd, source_fd) pairs
  std::vector<std::pair<int, int>> fds_to_remap;

  // Pre-exec delegate: called in the child after fork, before exec.
  std::function<void()> pre_exec_delegate;

  // Clone flags for namespace isolation
  int clone_flags = 0;
};

// LaunchProcess: fork+exec with options.
inline Process LaunchProcess(const std::vector<std::string>& argv,
                              const LaunchOptions& options) {
  pid_t pid = fork();
  if (pid < 0) return Process();
  if (pid == 0) {
    // Child
    for (auto& [target_fd, source_fd] : options.fds_to_remap) {
      if (target_fd != source_fd) {
        dup2(source_fd, target_fd);
      }
    }
    if (!options.current_directory.empty()) {
      if (chdir(options.current_directory.c_str()) != 0) _exit(127);
    }
    if (options.pre_exec_delegate) {
      options.pre_exec_delegate();
    }

    std::vector<const char*> c_argv;
    for (const auto& a : argv) c_argv.push_back(a.c_str());
    c_argv.push_back(nullptr);
    execvp(c_argv[0], const_cast<char**>(c_argv.data()));
    _exit(127);
  }
  // Parent
  if (options.wait) {
    int status;
    waitpid(pid, &status, 0);
  }
  return Process(pid);
}

// ForkWithFlags: clone() with specific flags. Used by namespace/credential code.
inline pid_t ForkWithFlags(unsigned long flags, pid_t* ptid, pid_t* ctid) {
  // Use clone() with the specified flags
  // For simple cases where CLONE_VM is not set, we can emulate with fork()
  // and then apply namespace flags. But the real need is for CLONE_NEWUSER etc.
  const size_t kStackSize = 1024 * 1024;
  // We use syscall(SYS_clone, ...) for maximum compatibility
  // But for the sandbox tests, fork-like semantics suffice
  pid_t pid = syscall(SYS_clone, flags, nullptr, ptid, ctid, 0);
  return pid;
}

}  // namespace base

#endif  // BASE_PROCESS_LAUNCH_H_
