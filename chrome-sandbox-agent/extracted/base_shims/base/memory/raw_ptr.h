// Copyright 2020 The Chromium Authors
// Standalone shim: base/memory/raw_ptr.h
// In Chromium, raw_ptr<T> is MiraclePtr - a pointer with use-after-free
// detection. For standalone extraction, we provide a thin wrapper that
// behaves like a raw pointer.

#ifndef BASE_MEMORY_RAW_PTR_H_
#define BASE_MEMORY_RAW_PTR_H_

#include <cstddef>
#include <type_traits>

// RawPtrTraits: empty in standalone build.
enum class RawPtrTraits : unsigned {
  kEmpty = 0,
};

inline constexpr RawPtrTraits operator|(RawPtrTraits a, RawPtrTraits b) {
  return static_cast<RawPtrTraits>(static_cast<unsigned>(a) |
                                   static_cast<unsigned>(b));
}

// AllowPtrArithmetic trait stub
inline constexpr RawPtrTraits AllowPtrArithmetic = RawPtrTraits::kEmpty;
inline constexpr RawPtrTraits DisableDanglingPtrDetection = RawPtrTraits::kEmpty;
inline constexpr RawPtrTraits LeakedDanglingUntriaged = RawPtrTraits::kEmpty;
inline constexpr RawPtrTraits DanglingUntriaged = RawPtrTraits::kEmpty;

// raw_ptr<T>: thin wrapper around T* that mimics Chromium's MiraclePtr API.
template <typename T, RawPtrTraits Traits = RawPtrTraits::kEmpty>
class raw_ptr {
 public:
  using element_type = T;

  constexpr raw_ptr() noexcept : ptr_(nullptr) {}
  constexpr raw_ptr(std::nullptr_t) noexcept : ptr_(nullptr) {}

  // NOLINTNEXTLINE(google-explicit-constructor)
  raw_ptr(T* ptr) noexcept : ptr_(ptr) {}

  raw_ptr(const raw_ptr&) noexcept = default;
  raw_ptr(raw_ptr&&) noexcept = default;
  raw_ptr& operator=(const raw_ptr&) noexcept = default;
  raw_ptr& operator=(raw_ptr&&) noexcept = default;

  raw_ptr& operator=(T* ptr) noexcept {
    ptr_ = ptr;
    return *this;
  }
  raw_ptr& operator=(std::nullptr_t) noexcept {
    ptr_ = nullptr;
    return *this;
  }

  ~raw_ptr() = default;

  T* get() const { return ptr_; }
  template <typename U = T, typename = std::enable_if_t<!std::is_void_v<U>>>
  U& operator*() const { return *ptr_; }
  template <typename U = T, typename = std::enable_if_t<!std::is_void_v<U>>>
  U* operator->() const { return ptr_; }

  // NOLINTNEXTLINE(google-explicit-constructor)
  operator T*() const { return ptr_; }
  explicit operator bool() const { return ptr_ != nullptr; }

  raw_ptr& operator++() { ++ptr_; return *this; }
  raw_ptr& operator--() { --ptr_; return *this; }
  raw_ptr operator++(int) { raw_ptr tmp = *this; ++ptr_; return tmp; }
  raw_ptr operator--(int) { raw_ptr tmp = *this; --ptr_; return tmp; }
  raw_ptr& operator+=(ptrdiff_t delta) { ptr_ += delta; return *this; }
  raw_ptr& operator-=(ptrdiff_t delta) { ptr_ -= delta; return *this; }

  template <typename U>
  friend bool operator==(const raw_ptr& lhs, const raw_ptr<U>& rhs) {
    return lhs.ptr_ == rhs.get();
  }
  template <typename U>
  friend bool operator==(const raw_ptr& lhs, U* rhs) {
    return lhs.ptr_ == rhs;
  }
  friend bool operator==(const raw_ptr& lhs, std::nullptr_t) {
    return lhs.ptr_ == nullptr;
  }

 private:
  T* ptr_;
};

#endif  // BASE_MEMORY_RAW_PTR_H_
