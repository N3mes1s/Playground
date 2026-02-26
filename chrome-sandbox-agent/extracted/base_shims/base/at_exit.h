// Standalone shim: base/at_exit.h
#ifndef BASE_AT_EXIT_H_
#define BASE_AT_EXIT_H_

#include <cstdlib>
#include <functional>
#include <vector>

namespace base {

class AtExitManager {
 public:
  AtExitManager() = default;
  ~AtExitManager() {
    for (auto it = callbacks_.rbegin(); it != callbacks_.rend(); ++it)
      (*it)();
  }

  static void RegisterCallback(void (*func)(void*), void* param) {
    // Simplified: use atexit for standalone
  }

 private:
  std::vector<std::function<void()>> callbacks_;
};

}  // namespace base

#endif  // BASE_AT_EXIT_H_
