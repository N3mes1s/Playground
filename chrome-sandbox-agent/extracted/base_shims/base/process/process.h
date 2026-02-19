// Copyright 2011 The Chromium Authors
// Standalone shim: base/process/process.h

#ifndef BASE_PROCESS_PROCESS_H_
#define BASE_PROCESS_PROCESS_H_

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "base/process/process_handle.h"

namespace base {

class Process {
 public:
  Process() : pid_(kNullProcessHandle) {}
  explicit Process(ProcessHandle handle) : pid_(handle) {}
  ~Process() = default;

  Process(Process&& other) noexcept : pid_(other.pid_) {
    other.pid_ = kNullProcessHandle;
  }
  Process& operator=(Process&& other) noexcept {
    pid_ = other.pid_;
    other.pid_ = kNullProcessHandle;
    return *this;
  }
  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;

  ProcessHandle Handle() const { return pid_; }
  ProcessId Pid() const { return GetProcId(pid_); }
  bool IsValid() const { return pid_ != kNullProcessHandle; }

  bool Terminate(int exit_code, bool wait) const {
    if (!IsValid()) return false;
    if (kill(pid_, SIGTERM) != 0) return false;
    if (wait) {
      int status;
      waitpid(pid_, &status, 0);
    }
    return true;
  }

  int WaitForExit() const {
    int status = 0;
    waitpid(pid_, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
  }

  static Process Current() { return Process(GetCurrentProcessHandle()); }

 private:
  ProcessHandle pid_;
};

}  // namespace base

#endif  // BASE_PROCESS_PROCESS_H_
