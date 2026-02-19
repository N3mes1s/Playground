// Copyright 2013 The Chromium Authors
// Standalone shim: base/process/process_handle.h

#ifndef BASE_PROCESS_PROCESS_HANDLE_H_
#define BASE_PROCESS_PROCESS_HANDLE_H_

#include <cstdio>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>

namespace base {

typedef pid_t ProcessHandle;
typedef pid_t ProcessId;

constexpr ProcessHandle kNullProcessHandle = 0;
constexpr ProcessId kNullProcessId = 0;

#define CrPRIdPid "d"

inline ProcessId GetCurrentProcId() { return getpid(); }
inline ProcessHandle GetCurrentProcessHandle() { return getpid(); }

inline ProcessId GetProcId(ProcessHandle process) {
  return static_cast<ProcessId>(process);
}

}  // namespace base

#endif  // BASE_PROCESS_PROCESS_HANDLE_H_
