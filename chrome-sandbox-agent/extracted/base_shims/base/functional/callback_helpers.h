// Standalone shim: base/functional/callback_helpers.h
// Provides DoNothing, ScopedClosureRunner, etc.

#ifndef BASE_FUNCTIONAL_CALLBACK_HELPERS_H_
#define BASE_FUNCTIONAL_CALLBACK_HELPERS_H_

#include <functional>
#include <utility>

namespace base {

// DoNothing: returns a no-op callable when invoked as base::DoNothing().
// In Chromium, DoNothing() returns a helper convertible to any callback type.
inline auto DoNothing() {
  return [](auto&&...) {};
}

// ScopedClosureRunner: runs a closure on destruction.
class ScopedClosureRunner {
 public:
  ScopedClosureRunner() = default;
  explicit ScopedClosureRunner(std::function<void()> closure)
      : closure_(std::move(closure)) {}

  ScopedClosureRunner(ScopedClosureRunner&& other) noexcept
      : closure_(std::move(other.closure_)) {
    other.closure_ = nullptr;
  }

  ScopedClosureRunner& operator=(ScopedClosureRunner&& other) noexcept {
    RunAndReset();
    closure_ = std::move(other.closure_);
    other.closure_ = nullptr;
    return *this;
  }

  ~ScopedClosureRunner() { RunAndReset(); }

  void RunAndReset() {
    if (closure_) {
      auto c = std::move(closure_);
      closure_ = nullptr;
      c();
    }
  }

  void ReplaceClosure(std::function<void()> closure) {
    closure_ = std::move(closure);
  }

 private:
  std::function<void()> closure_;
};

}  // namespace base

#endif  // BASE_FUNCTIONAL_CALLBACK_HELPERS_H_
