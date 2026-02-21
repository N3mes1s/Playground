// Standalone shim: base/bits.h
#ifndef BASE_BITS_H_
#define BASE_BITS_H_

#include <cstddef>
#include <type_traits>

namespace base::bits {

template <typename T>
constexpr T AlignUp(T value, T alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

template <typename T>
constexpr T AlignDown(T value, T alignment) {
  return value & ~(alignment - 1);
}

template <typename T>
constexpr bool IsPowerOfTwo(T value) {
  return value > 0 && (value & (value - 1)) == 0;
}

}  // namespace base::bits

#endif  // BASE_BITS_H_
