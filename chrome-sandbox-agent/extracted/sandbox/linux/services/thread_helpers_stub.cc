// thread_helpers_stub.cc - Standalone sandbox build implementation.
// Provides ThreadHelpers methods for sandbox_bpf.cc and tests.

#include "sandbox/linux/services/thread_helpers.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "base/threading/thread.h"
#include "sandbox/linux/services/proc_util.h"

namespace sandbox {

namespace {

int CountThreadsFromProcFS(int proc_fd) {
  int task_fd = openat(proc_fd, "self/task", O_RDONLY | O_DIRECTORY);
  if (task_fd < 0) return 1;
  DIR* dir = fdopendir(task_fd);
  if (!dir) {
    close(task_fd);
    return 1;
  }
  int count = 0;
  while (struct dirent* entry = readdir(dir)) {
    if (entry->d_name[0] == '.') continue;
    count++;
  }
  closedir(dir);  // also closes task_fd
  return count > 0 ? count : 1;
}

bool IsSingleThreadedImpl(int proc_fd) {
  return CountThreadsFromProcFS(proc_fd) == 1;
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
  // Exponential backoff loop: wait for /proc to settle, then fail fatally
  for (unsigned int i = 0; i < 25; ++i) {
    if (IsSingleThreadedImpl(proc_fd)) return;
    struct timespec ts = {0, 1L << i /* nanoseconds */};
    nanosleep(&ts, &ts);
  }
  LOG(FATAL) << "Current process is not mono-threaded!";
}

// static
void ThreadHelpers::AssertSingleThreaded() {
  base::ScopedFD task_fd(ProcUtil::OpenProc());
  AssertSingleThreaded(task_fd.get());
}

// static
bool ThreadHelpers::StartThreadAndWatchProcFS(int proc_fd,
                                               base::Thread* thread) {
  int before = CountThreadsFromProcFS(proc_fd);
  if (!thread->Start())
    return false;
  // Wait for /proc/self/task to show the new thread.
  for (unsigned int i = 0; i < 25; ++i) {
    if (CountThreadsFromProcFS(proc_fd) > before)
      return true;
    struct timespec ts = {0, 1L << i /* nanoseconds */};
    nanosleep(&ts, &ts);
  }
  return false;
}

// static
bool ThreadHelpers::StopThreadAndWatchProcFS(int proc_fd,
                                              base::Thread* thread) {
  int before = CountThreadsFromProcFS(proc_fd);
  thread->Stop();
  // Wait for /proc/self/task to reflect the stopped thread.
  for (unsigned int i = 0; i < 25; ++i) {
    if (CountThreadsFromProcFS(proc_fd) < before)
      return true;
    struct timespec ts = {0, 1L << i /* nanoseconds */};
    nanosleep(&ts, &ts);
  }
  return false;
}

// static
const char* ThreadHelpers::GetAssertSingleThreadedErrorMessageForTests() {
  return "Current process is not mono-threaded!";
}

}  // namespace sandbox
