// thread_helpers_stub.cc - Minimal stub for standalone sandbox build.
// Provides ThreadHelpers methods called by sandbox_bpf.cc without
// pulling in full base::Thread dependency.

#include "sandbox/linux/services/thread_helpers.h"

#include <fcntl.h>
#include <sys/stat.h>

#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "sandbox/linux/services/proc_util.h"

namespace sandbox {

namespace {

bool IsSingleThreadedImpl(int proc_fd) {
  struct stat task_stat;
  int ret = fstatat(proc_fd, "self/task/", &task_stat, 0);
  if (ret < 0) return true;  // Assume single-threaded if can't check
  return task_stat.st_nlink == 3;
}

}  // namespace

// static
bool ThreadHelpers::IsSingleThreaded(int proc_fd) {
  return IsSingleThreadedImpl(proc_fd);
}

// static
bool ThreadHelpers::IsSingleThreaded() {
  base::ScopedFD task_fd(ProcUtil::OpenProc());
  return IsSingleThreaded(task_fd.get());
}

// static
void ThreadHelpers::AssertSingleThreaded(int proc_fd) {
  // In standalone mode, just check once (no exponential backoff loop)
  if (!IsSingleThreadedImpl(proc_fd)) {
    LOG(WARNING) << "Process is not single-threaded (non-fatal in standalone mode)";
  }
}

// static
void ThreadHelpers::AssertSingleThreaded() {
  base::ScopedFD task_fd(ProcUtil::OpenProc());
  AssertSingleThreaded(task_fd.get());
}

// static - test helper, stubbed
bool ThreadHelpers::StartThreadAndWatchProcFS(int, base::Thread*) {
  return false;
}

// static - test helper, stubbed
bool ThreadHelpers::StopThreadAndWatchProcFS(int, base::Thread*) {
  return false;
}

// static
const char* ThreadHelpers::GetAssertSingleThreadedErrorMessageForTests() {
  return "Current process is not mono-threaded!";
}

}  // namespace sandbox
