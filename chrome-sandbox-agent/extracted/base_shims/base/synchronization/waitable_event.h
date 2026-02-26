// Stub: base/synchronization/waitable_event.h
#ifndef BASE_SYNCHRONIZATION_WAITABLE_EVENT_H_
#define BASE_SYNCHRONIZATION_WAITABLE_EVENT_H_

#include <chrono>
#include <condition_variable>
#include <mutex>

#include "base/time/time.h"

namespace base {

class WaitableEvent {
 public:
  enum class ResetPolicy { MANUAL, AUTOMATIC };
  enum class InitialState { NOT_SIGNALED, SIGNALED };

  explicit WaitableEvent(ResetPolicy reset = ResetPolicy::MANUAL,
                         InitialState initial = InitialState::NOT_SIGNALED)
      : signaled_(initial == InitialState::SIGNALED),
        auto_reset_(reset == ResetPolicy::AUTOMATIC) {}

  void Signal() {
    std::lock_guard<std::mutex> lock(mu_);
    signaled_ = true;
    cv_.notify_all();
  }

  void Wait() {
    std::unique_lock<std::mutex> lock(mu_);
    cv_.wait(lock, [this] { return signaled_; });
    if (auto_reset_) signaled_ = false;
  }

  bool TimedWait(const TimeDelta& timeout) {
    std::unique_lock<std::mutex> lock(mu_);
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::microseconds(timeout.InMicroseconds());
    bool result = cv_.wait_until(lock, deadline, [this] { return signaled_; });
    if (result && auto_reset_) signaled_ = false;
    return result;
  }

  bool IsSignaled() {
    std::lock_guard<std::mutex> lock(mu_);
    return signaled_;
  }

  void Reset() {
    std::lock_guard<std::mutex> lock(mu_);
    signaled_ = false;
  }

 private:
  std::mutex mu_;
  std::condition_variable cv_;
  bool signaled_;
  bool auto_reset_;
};

}  // namespace base

#endif  // BASE_SYNCHRONIZATION_WAITABLE_EVENT_H_
