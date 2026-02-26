// Copyright 2017 The Chromium Authors
// Standalone shim: base/numerics/safe_math.h

#ifndef BASE_NUMERICS_SAFE_MATH_H_
#define BASE_NUMERICS_SAFE_MATH_H_

#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace base {

// CheckedNumeric: wraps a value with overflow checking.
// Minimal implementation covering what sandbox code uses.
template <typename T>
class CheckedNumeric {
 public:
  constexpr CheckedNumeric() : value_(0), valid_(true) {}
  constexpr CheckedNumeric(T value) : value_(value), valid_(true) {}

  constexpr bool IsValid() const { return valid_; }
  constexpr T ValueOrDie() const {
    assert(valid_);
    return value_;
  }
  constexpr T ValueOrDefault(T default_val) const {
    return valid_ ? value_ : default_val;
  }

  template <typename U>
  constexpr CheckedNumeric<T> operator+(U rhs) const {
    CheckedNumeric result;
    if (__builtin_add_overflow(value_, static_cast<T>(rhs), &result.value_))
      result.valid_ = false;
    else
      result.valid_ = valid_;
    return result;
  }

  template <typename U>
  constexpr CheckedNumeric<T> operator*(U rhs) const {
    CheckedNumeric result;
    if (__builtin_mul_overflow(value_, static_cast<T>(rhs), &result.value_))
      result.valid_ = false;
    else
      result.valid_ = valid_;
    return result;
  }

  template <typename U>
  constexpr CheckedNumeric<T>& operator+=(U rhs) {
    *this = *this + rhs;
    return *this;
  }

  template <typename Dst>
  constexpr bool AssignIfValid(Dst* result) const {
    if (!valid_) return false;
    *result = static_cast<Dst>(value_);
    return true;
  }

  // Cast to another type
  template <typename Dst>
  constexpr CheckedNumeric<Dst> Cast() const {
    return CheckedNumeric<Dst>(static_cast<Dst>(value_));
  }

 private:
  T value_;
  bool valid_;
};

// Convenience type aliases
using CheckedInt32 = CheckedNumeric<int32_t>;
using CheckedUint32 = CheckedNumeric<uint32_t>;
using CheckedInt64 = CheckedNumeric<int64_t>;
using CheckedUint64 = CheckedNumeric<uint64_t>;

template <typename T>
constexpr CheckedNumeric<T> MakeCheckedNum(T value) {
  return CheckedNumeric<T>(value);
}

}  // namespace base

#endif  // BASE_NUMERICS_SAFE_MATH_H_
