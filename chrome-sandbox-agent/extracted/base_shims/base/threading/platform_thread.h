// Copyright 2012 The Chromium Authors
// Standalone shim: base/threading/platform_thread.h

#ifndef BASE_THREADING_PLATFORM_THREAD_H_
#define BASE_THREADING_PLATFORM_THREAD_H_

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>

#include "base/time/time.h"

namespace base {

class PlatformThread {
 public:
  using PlatformThreadId = pid_t;

  static PlatformThreadId CurrentId() {
    return static_cast<PlatformThreadId>(syscall(SYS_gettid));
  }

  static void YieldCurrentThread() {
    sched_yield();
  }

  static void Sleep(const TimeDelta& duration) {
    usleep(duration.InMicroseconds());
  }
  static void Sleep(int ms) {
    usleep(ms * 1000);
  }
};

using PlatformThreadId = PlatformThread::PlatformThreadId;

}  // namespace base

#endif  // BASE_THREADING_PLATFORM_THREAD_H_
