// Copyright 2012 The Chromium Authors
// Standalone shim: base/posix/global_descriptors.h

#ifndef BASE_POSIX_GLOBAL_DESCRIPTORS_H_
#define BASE_POSIX_GLOBAL_DESCRIPTORS_H_

#include <map>
#include <cstdint>

namespace base {

// Minimal global descriptor table used by libc_interceptor.
class GlobalDescriptors {
 public:
  typedef uint32_t Key;
  struct Descriptor {
    int fd;
    uint64_t region_offset;
    uint64_t region_size;
  };

  static GlobalDescriptors* GetInstance() {
    static GlobalDescriptors instance;
    return &instance;
  }

  int Get(Key key) const {
    auto it = descriptors_.find(key);
    return (it != descriptors_.end()) ? it->second.fd : -1;
  }

  int MaybeGet(Key key) const { return Get(key); }

  void Set(Key key, int fd) {
    descriptors_[key] = {fd, 0, 0};
  }

 private:
  GlobalDescriptors() = default;
  std::map<Key, Descriptor> descriptors_;
};

}  // namespace base

#endif  // BASE_POSIX_GLOBAL_DESCRIPTORS_H_
