// Copyright 2013 The Chromium Authors
// Standalone shim: base/process/process_metrics.h

#ifndef BASE_PROCESS_PROCESS_METRICS_H_
#define BASE_PROCESS_PROCESS_METRICS_H_

#include <cstddef>
#include <dirent.h>
#include <sys/resource.h>
#include <unistd.h>

#include "base/process/process_handle.h"

namespace base {

inline size_t GetMaxFds() {
  struct rlimit nofile;
  if (getrlimit(RLIMIT_NOFILE, &nofile) == 0)
    return static_cast<size_t>(nofile.rlim_cur);
  return 256;
}

inline size_t GetSystemCommitCharge() { return 0; }

inline void IncreaseFdLimitTo(unsigned int max_descriptors) {
  struct rlimit fdlimit;
  if (getrlimit(RLIMIT_NOFILE, &fdlimit) == 0) {
    if (fdlimit.rlim_cur < max_descriptors) {
      fdlimit.rlim_cur = max_descriptors;
      if (fdlimit.rlim_cur > fdlimit.rlim_max)
        fdlimit.rlim_cur = fdlimit.rlim_max;
      setrlimit(RLIMIT_NOFILE, &fdlimit);
    }
  }
}

// GetNumberOfThreads: count threads via /proc/<pid>/task
inline int GetNumberOfThreads(ProcessHandle process) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/task", static_cast<int>(process));
  int count = 0;
  if (auto* dir = opendir(path)) {
    while (readdir(dir)) count++;
    closedir(dir);
    count -= 2;  // skip . and ..
  }
  return count > 0 ? count : 1;
}

}  // namespace base

#endif  // BASE_PROCESS_PROCESS_METRICS_H_
