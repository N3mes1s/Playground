// Copyright 2012 The Chromium Authors
// Standalone shim: base/threading/thread.h
// Provides a real Thread implementation with task posting support.

#ifndef BASE_THREADING_THREAD_H_
#define BASE_THREADING_THREAD_H_

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>

#include "base/location.h"
#include "base/threading/platform_thread.h"

namespace base {

// Simple task runner that queues and executes closures on a thread.
class SimpleTaskRunner {
 public:
  void PostTask(const Location&, std::function<void()> task) {
    std::lock_guard<std::mutex> lock(mu_);
    tasks_.push(std::move(task));
  }

  bool RunPendingTask() {
    std::function<void()> task;
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (tasks_.empty()) return false;
      task = std::move(tasks_.front());
      tasks_.pop();
    }
    task();
    return true;
  }

 private:
  std::mutex mu_;
  std::queue<std::function<void()>> tasks_;
};

class Thread {
 public:
  class Options {};

  explicit Thread(const char* name)
      : name_(name), task_runner_(std::make_shared<SimpleTaskRunner>()) {}

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

  std::shared_ptr<SimpleTaskRunner> task_runner() const { return task_runner_; }

  PlatformThreadId GetThreadId() const {
    return tid_.load();
  }

 private:
  static void* ThreadMain(void* arg) {
    Thread* self = static_cast<Thread*>(arg);
    self->tid_.store(
        static_cast<PlatformThreadId>(syscall(SYS_gettid)));
    while (self->running_.load()) {
      // Try to run a pending task
      if (!self->task_runner_->RunPendingTask()) {
        usleep(500);  // Sleep 0.5ms if no tasks
      }
    }
    // Drain remaining tasks
    while (self->task_runner_->RunPendingTask()) {}
    return nullptr;
  }

  const char* name_;
  pthread_t thread_{};
  std::atomic<bool> running_{false};
  std::atomic<PlatformThreadId> tid_{0};
  std::shared_ptr<SimpleTaskRunner> task_runner_;
};

}  // namespace base

#endif  // BASE_THREADING_THREAD_H_
