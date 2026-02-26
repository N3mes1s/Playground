// Standalone shim: base/task/thread_pool.h
// Provides minimal ThreadPool with PostTaskAndReply.

#ifndef BASE_TASK_THREAD_POOL_H_
#define BASE_TASK_THREAD_POOL_H_

#include <functional>
#include <thread>
#include <utility>

#include "base/location.h"

namespace base {

class ThreadPool {
 public:
  // PostTaskAndReply: run task on a background thread, then run reply on the
  // calling thread. For our standalone build, we run task synchronously on a
  // new thread and then call reply inline (since we don't have a message loop).
  static void PostTaskAndReply(const Location&,
                               std::function<void()> task,
                               std::function<void()> reply) {
    std::thread t([task = std::move(task), reply = std::move(reply)]() mutable {
      task();
      reply();
    });
    t.detach();
  }
};

}  // namespace base

#endif  // BASE_TASK_THREAD_POOL_H_
