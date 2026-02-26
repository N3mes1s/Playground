// Standalone shim: base/run_loop.h
// Chrome-compatible RunLoop that blocks Run() until Quit() is called.
// While waiting, polls the InotifyReader for events (matching Chrome's
// message loop IO integration).

#ifndef BASE_RUN_LOOP_H_
#define BASE_RUN_LOOP_H_

#include <atomic>
#include <functional>
#include <poll.h>

#include "base/files/file_path_watcher.h"

namespace base {

class RunLoop {
 public:
  RunLoop() = default;
  ~RunLoop() = default;

  void Run() {
    auto& reader = InotifyReader::Instance();
    int inotify_fd = reader.inotify_fd();

    while (!quit_.load()) {
      if (inotify_fd >= 0) {
        struct pollfd pfd = {inotify_fd, POLLIN, 0};
        poll(&pfd, 1, 10);  // 10ms timeout
        if (pfd.revents & POLLIN) {
          reader.PollAndDispatch();
        }
      } else {
        // No inotify fd, just spin-wait with small sleep
        usleep(1000);
      }
    }
  }

  void RunUntilIdle() {
    // Process pending inotify events without blocking
    InotifyReader::Instance().PollAndDispatch();
  }

  void Quit() {
    quit_.store(true);
  }

  void QuitWhenIdle() { Quit(); }

  auto QuitClosure() {
    return [this]() { Quit(); };
  }

 private:
  std::atomic<bool> quit_{false};
};

}  // namespace base

#endif  // BASE_RUN_LOOP_H_
