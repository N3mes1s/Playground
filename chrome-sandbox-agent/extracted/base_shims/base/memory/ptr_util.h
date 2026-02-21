// Copyright 2015 The Chromium Authors
// Standalone shim: base/memory/ptr_util.h

#ifndef BASE_MEMORY_PTR_UTIL_H_
#define BASE_MEMORY_PTR_UTIL_H_

#include <memory>

namespace base {

// WrapUnique: takes ownership of a raw pointer via unique_ptr.
template <typename T>
std::unique_ptr<T> WrapUnique(T* ptr) {
  return std::unique_ptr<T>(ptr);
}

}  // namespace base

#endif  // BASE_MEMORY_PTR_UTIL_H_
