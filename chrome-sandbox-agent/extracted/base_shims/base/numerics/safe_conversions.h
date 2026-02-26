// Copyright 2014 The Chromium Authors
// Standalone shim: base/numerics/safe_conversions.h

#ifndef BASE_NUMERICS_SAFE_CONVERSIONS_H_
#define BASE_NUMERICS_SAFE_CONVERSIONS_H_

#include <cassert>
#include <limits>
#include <type_traits>

namespace base {

template <typename Dst, typename Src>
constexpr Dst checked_cast(Src value) {
  assert(value >= std::numeric_limits<Dst>::min());
  assert(value <= std::numeric_limits<Dst>::max());
  return static_cast<Dst>(value);
}

template <typename Dst, typename Src>
constexpr Dst saturated_cast(Src value) {
  if (value <= std::numeric_limits<Dst>::min())
    return std::numeric_limits<Dst>::min();
  if (value >= std::numeric_limits<Dst>::max())
    return std::numeric_limits<Dst>::max();
  return static_cast<Dst>(value);
}

template <typename Dst, typename Src>
constexpr bool IsValueInRangeForNumericType(Src value) {
  return value >= std::numeric_limits<Dst>::min() &&
         value <= std::numeric_limits<Dst>::max();
}

}  // namespace base

#endif  // BASE_NUMERICS_SAFE_CONVERSIONS_H_
