// Copyright 2012 The Chromium Authors
// Standalone shim: base/threading/thread.h

#ifndef BASE_THREADING_THREAD_H_
#define BASE_THREADING_THREAD_H_

#include "base/threading/platform_thread.h"

namespace base {

// Minimal Thread stub for sandbox thread_helpers.cc
class Thread {
 public:
  class Options {};
  explicit Thread(const char* name) {}
  ~Thread() = default;
  bool Start() { return false; }
  void Stop() {}
  bool IsRunning() const { return false; }
};

}  // namespace base

#endif  // BASE_THREADING_THREAD_H_
