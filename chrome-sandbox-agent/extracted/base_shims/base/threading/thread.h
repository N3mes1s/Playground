// Copyright 2012 The Chromium Authors
// Standalone shim: base/threading/thread.h
// Provides a real Thread implementation using pthread_create.

#ifndef BASE_THREADING_THREAD_H_
#define BASE_THREADING_THREAD_H_

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>

#include "base/threading/platform_thread.h"

namespace base {

class Thread {
 public:
  class Options {};

  explicit Thread(const char* name) : name_(name) {}

  ~Thread() { Stop(); }

  bool Start() {
    if (running_.load()) return false;
    running_.store(true);
    int ret = pthread_create(&thread_, nullptr, &ThreadMain, this);
    if (ret != 0) {
      running_.store(false);
      return false;
    }
    // Wait for the thread to actually start and record its tid
    while (tid_.load() == 0) {
      sched_yield();
    }
    return true;
  }

  void Stop() {
    if (!running_.load()) return;
    running_.store(false);
    pthread_join(thread_, nullptr);
    tid_.store(0);
  }

  bool IsRunning() const { return running_.load(); }

  PlatformThreadId GetThreadId() const {
    return tid_.load();
  }

 private:
  static void* ThreadMain(void* arg) {
    Thread* self = static_cast<Thread*>(arg);
    self->tid_.store(
        static_cast<PlatformThreadId>(syscall(SYS_gettid)));
    while (self->running_.load()) {
      usleep(1000);  // Sleep 1ms between checks
    }
    return nullptr;
  }

  const char* name_;
  pthread_t thread_{};
  std::atomic<bool> running_{false};
  std::atomic<PlatformThreadId> tid_{0};
};

}  // namespace base

#endif  // BASE_THREADING_THREAD_H_
