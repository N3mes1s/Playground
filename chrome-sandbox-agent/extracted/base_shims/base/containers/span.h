// Copyright 2017 The Chromium Authors
// Standalone shim: base/containers/span.h
// Maps base::span to std::span (C++20) with Chromium-specific extensions.

#ifndef BASE_CONTAINERS_SPAN_H_
#define BASE_CONTAINERS_SPAN_H_

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <type_traits>
#include <vector>

namespace base {

inline constexpr size_t dynamic_extent = static_cast<size_t>(-1);

template <size_t N>
using fixed_extent = std::integral_constant<size_t, N>;

// Minimal span implementation that covers what Chromium sandbox code needs.
// We implement our own rather than using std::span because some sandbox
// code uses Chromium-specific span features (3rd template param, copy_from, etc.)
template <typename T, size_t Extent = dynamic_extent, typename InternalPtr = T*>
class span {
 public:
  using element_type = T;
  using value_type = std::remove_cv_t<T>;
  using size_type = size_t;
  using difference_type = ptrdiff_t;
  using pointer = T*;
  using const_pointer = const T*;
  using reference = T&;
  using const_reference = const T&;
  using iterator = T*;
  using reverse_iterator = std::reverse_iterator<iterator>;

  constexpr span() noexcept : data_(nullptr), size_(0) {}
  constexpr span(T* data, size_t size) noexcept : data_(data), size_(size) {}
  constexpr span(T* first, T* last) noexcept : data_(first), size_(last - first) {}

  template <size_t N>
  constexpr span(T (&arr)[N]) noexcept : data_(arr), size_(N) {}

  template <typename Container,
            typename = std::enable_if_t<
                !std::is_same_v<std::remove_cv_t<Container>, span> &&
                std::is_convertible_v<decltype(std::declval<Container&>().data()), T*>>>
  constexpr span(Container& c) noexcept : data_(c.data()), size_(c.size()) {}

  // Conversion from span<U> to span<const U>
  template <typename U, size_t E2, typename P2,
            typename = std::enable_if_t<std::is_convertible_v<U*, T*>>>
  constexpr span(const span<U, E2, P2>& other) noexcept
      : data_(other.data()), size_(other.size()) {}

  // Copy/move
  constexpr span(const span&) noexcept = default;
  constexpr span& operator=(const span&) noexcept = default;

  constexpr T* data() const noexcept { return data_; }
  constexpr size_t size() const noexcept { return size_; }
  constexpr size_t size_bytes() const noexcept { return size_ * sizeof(T); }
  constexpr bool empty() const noexcept { return size_ == 0; }

  constexpr T& operator[](size_t idx) const { return data_[idx]; }
  constexpr T& front() const { return data_[0]; }
  constexpr T& back() const { return data_[size_ - 1]; }

  constexpr iterator begin() const noexcept { return data_; }
  constexpr iterator end() const noexcept { return data_ + size_; }
  constexpr reverse_iterator rbegin() const noexcept { return reverse_iterator(end()); }
  constexpr reverse_iterator rend() const noexcept { return reverse_iterator(begin()); }

  constexpr span subspan(size_t offset, size_t count = dynamic_extent) const {
    if (count == dynamic_extent) count = size_ - offset;
    return span(data_ + offset, count);
  }

  // Template version: subspan<Offset>() and subspan<Offset, Count>()
  template <size_t Offset, size_t Count = dynamic_extent>
  constexpr span subspan() const {
    if constexpr (Count == dynamic_extent)
      return span(data_ + Offset, size_ - Offset);
    else
      return span(data_ + Offset, Count);
  }

  constexpr span first(size_t count) const { return span(data_, count); }
  constexpr span last(size_t count) const { return span(data_ + size_ - count, count); }

  // Chromium-specific extensions used by sandbox code
  void copy_from(span<const T> source) {
    assert(source.size() == size_);
    std::copy(source.begin(), source.end(), data_);
  }

  void copy_from_nonoverlapping(span<const T> source) {
    assert(source.size() <= size_);
    memcpy(data_, source.data(), source.size() * sizeof(T));
  }

  // split_at returns pair of subspans
  constexpr std::pair<span, span> split_at(size_t offset) const {
    return {first(offset), subspan(offset)};
  }

  // take_first: return first N elements, shrink span
  constexpr span take_first(size_t count) {
    span result(data_, count);
    data_ += count;
    size_ -= count;
    return result;
  }

 private:
  T* data_;
  size_t size_;
};

// Comparison operators
template <typename T1, size_t E1, typename P1, typename T2, size_t E2, typename P2>
bool operator==(const span<T1, E1, P1>& lhs, const span<T2, E2, P2>& rhs) {
  if (lhs.size() != rhs.size()) return false;
  for (size_t i = 0; i < lhs.size(); ++i) {
    if (!(lhs[i] == rhs[i])) return false;
  }
  return true;
}

template <typename T1, size_t E1, typename P1, typename T2, size_t E2, typename P2>
bool operator!=(const span<T1, E1, P1>& lhs, const span<T2, E2, P2>& rhs) {
  return !(lhs == rhs);
}

// Deduction guides
template <typename T, size_t N>
span(T (&)[N]) -> span<T, N>;

template <typename Container>
span(Container&) -> span<typename Container::value_type>;

template <typename Container>
span(const Container&) -> span<const typename Container::value_type>;

// as_bytes / as_writable_bytes
template <typename T, size_t E>
span<const uint8_t> as_bytes(span<T, E> s) {
  return span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                             s.size_bytes());
}

template <typename T, size_t E>
span<uint8_t> as_writable_bytes(span<T, E> s) {
  return span<uint8_t>(reinterpret_cast<uint8_t*>(s.data()), s.size_bytes());
}

// span_from_ref
template <typename T>
span<T, 1> span_from_ref(T& ref) {
  return span<T, 1>(&ref, 1u);
}

// byte_span_from_ref
template <typename T>
span<const uint8_t> byte_span_from_ref(const T& ref) {
  return span<const uint8_t>(reinterpret_cast<const uint8_t*>(&ref), sizeof(T));
}

template <typename T>
span<uint8_t> byte_span_from_ref(T& ref) {
  return span<uint8_t>(reinterpret_cast<uint8_t*>(&ref), sizeof(T));
}

// as_byte_span for containers
template <typename T>
span<const uint8_t> as_byte_span(const T& container) {
  return as_bytes(span(container));
}

// make_span helper
template <typename T>
span<T> make_span(T* data, size_t size) {
  return span<T>(data, size);
}

template <typename Container>
auto make_span(Container& c) {
  return span(c);
}

// byte_span_from_cstring: returns span of bytes from a C string (without nul)
inline span<const uint8_t> byte_span_from_cstring(const char* s) {
  return span<const uint8_t>(reinterpret_cast<const uint8_t*>(s), strlen(s));
}

// byte_span_with_nul_from_cstring: returns span of bytes including the nul terminator
inline span<const uint8_t> byte_span_with_nul_from_cstring(const char* s) {
  return span<const uint8_t>(reinterpret_cast<const uint8_t*>(s), strlen(s) + 1);
}

}  // namespace base

#endif  // BASE_CONTAINERS_SPAN_H_
