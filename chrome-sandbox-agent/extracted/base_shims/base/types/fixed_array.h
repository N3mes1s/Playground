// Stub: base/types/fixed_array.h
// Chrome's FixedArray is a stack-or-heap allocated fixed-size array.
// We implement it as a simple wrapper around std::vector for tests.
#ifndef BASE_TYPES_FIXED_ARRAY_H_
#define BASE_TYPES_FIXED_ARRAY_H_

#include <cstddef>
#include <vector>

namespace base {

template <typename T>
class FixedArray {
 public:
  explicit FixedArray(size_t n) : data_(n) {}
  T& operator[](size_t i) { return data_[i]; }
  const T& operator[](size_t i) const { return data_[i]; }
  T* data() { return data_.data(); }
  const T* data() const { return data_.data(); }
  size_t size() const { return data_.size(); }
  T* begin() { return data_.data(); }
  T* end() { return data_.data() + data_.size(); }
  const T* begin() const { return data_.data(); }
  const T* end() const { return data_.data() + data_.size(); }

 private:
  std::vector<T> data_;
};

}  // namespace base

#endif  // BASE_TYPES_FIXED_ARRAY_H_
