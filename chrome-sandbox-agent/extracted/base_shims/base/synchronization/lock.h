// Copyright 2011 The Chromium Authors
// Standalone shim: base/synchronization/lock.h

#ifndef BASE_SYNCHRONIZATION_LOCK_H_
#define BASE_SYNCHRONIZATION_LOCK_H_

#include <mutex>

namespace base {

class Lock {
 public:
  void Acquire() { mu_.lock(); }
  void Release() { mu_.unlock(); }
  bool Try() { return mu_.try_lock(); }

 private:
  std::mutex mu_;
};

class AutoLock {
 public:
  explicit AutoLock(Lock& lock) : lock_(lock) { lock_.Acquire(); }
  ~AutoLock() { lock_.Release(); }
  AutoLock(const AutoLock&) = delete;
  AutoLock& operator=(const AutoLock&) = delete;

 private:
  Lock& lock_;
};

}  // namespace base

#endif  // BASE_SYNCHRONIZATION_LOCK_H_
