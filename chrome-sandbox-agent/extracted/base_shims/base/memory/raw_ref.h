// Copyright 2022 The Chromium Authors
// Standalone shim: base/memory/raw_ref.h

#ifndef BASE_MEMORY_RAW_REF_H_
#define BASE_MEMORY_RAW_REF_H_

#include "base/memory/raw_ptr.h"

namespace base {

// raw_ref<T>: non-nullable reference wrapper, standalone version.
template <typename T, RawPtrTraits Traits = RawPtrTraits::kEmpty>
class raw_ref {
 public:
  // NOLINTNEXTLINE(google-explicit-constructor)
  raw_ref(T& ref) noexcept : ptr_(&ref) {}

  raw_ref(const raw_ref&) noexcept = default;
  raw_ref(raw_ref&&) noexcept = default;
  raw_ref& operator=(const raw_ref&) noexcept = default;
  raw_ref& operator=(raw_ref&&) noexcept = default;

  T& operator*() const { return *ptr_; }
  T* operator->() const { return ptr_; }
  T& get() const { return *ptr_; }

  // Allow conversion to const ref
  template <typename U>
  operator raw_ref<U>() const {
    return raw_ref<U>(*ptr_);
  }

  friend bool operator==(const raw_ref& lhs, const raw_ref& rhs) {
    return lhs.ptr_ == rhs.ptr_;
  }
  friend bool operator!=(const raw_ref& lhs, const raw_ref& rhs) {
    return lhs.ptr_ != rhs.ptr_;
  }

 private:
  T* ptr_;
};

}  // namespace base

#endif  // BASE_MEMORY_RAW_REF_H_
