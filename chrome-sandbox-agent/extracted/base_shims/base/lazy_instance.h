// Standalone shim: base/lazy_instance.h
#ifndef BASE_LAZY_INSTANCE_H_
#define BASE_LAZY_INSTANCE_H_

#include <mutex>

namespace base {

// Simplified LazyInstance using C++11 magic statics.
template <typename T>
class LazyInstance {
 public:
  class Leaky {
   public:
    T& Get() {
      static T instance;
      return instance;
    }
    T* Pointer() { return &Get(); }
  };
};

// LAZY_INSTANCE_INITIALIZER: no-op for our leaky pattern
#define LAZY_INSTANCE_INITIALIZER {}

}  // namespace base

#endif  // BASE_LAZY_INSTANCE_H_
