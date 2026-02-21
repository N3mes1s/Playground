// Stub: base/synchronization/lock_impl.h
#ifndef BASE_SYNCHRONIZATION_LOCK_IMPL_H_
#define BASE_SYNCHRONIZATION_LOCK_IMPL_H_

#include <pthread.h>

namespace base {
namespace internal {

class LockImpl {
 public:
  LockImpl() { pthread_mutex_init(&mu_, nullptr); }
  ~LockImpl() { pthread_mutex_destroy(&mu_); }

  void Lock() { pthread_mutex_lock(&mu_); }
  void Unlock() { pthread_mutex_unlock(&mu_); }
  bool Try() { return pthread_mutex_trylock(&mu_) == 0; }

  using NativeHandle = pthread_mutex_t;
  NativeHandle* native_handle() { return &mu_; }

 private:
  pthread_mutex_t mu_;
};

}  // namespace internal
}  // namespace base

#endif  // BASE_SYNCHRONIZATION_LOCK_IMPL_H_
