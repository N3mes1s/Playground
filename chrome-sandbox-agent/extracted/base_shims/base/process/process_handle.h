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

// Path to current process executable via /proc
inline constexpr const char kProcSelfExe[] = "/proc/self/exe";

#define CrPRIdPid "d"

inline ProcessId GetCurrentProcId() { return getpid(); }
inline ProcessHandle GetCurrentProcessHandle() { return getpid(); }

inline ProcessId GetProcId(ProcessHandle process) {
  return static_cast<ProcessId>(process);
}

inline ProcessId GetParentProcessId(ProcessHandle process) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/stat", static_cast<int>(process));
  FILE* f = fopen(path, "r");
  if (!f) return kNullProcessId;
  int pid;
  char comm[256];
  char state;
  int ppid;
  if (fscanf(f, "%d %255s %c %d", &pid, comm, &state, &ppid) != 4) {
    fclose(f);
    return kNullProcessId;
  }
  fclose(f);
  return static_cast<ProcessId>(ppid);
}

}  // namespace base

#endif  // BASE_PROCESS_PROCESS_HANDLE_H_
