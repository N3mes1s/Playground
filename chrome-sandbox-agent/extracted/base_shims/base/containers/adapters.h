// Stub: base/containers/adapters.h
#ifndef BASE_CONTAINERS_ADAPTERS_H_
#define BASE_CONTAINERS_ADAPTERS_H_

#include <iterator>
#include <type_traits>

namespace base {

// Adapter to iterate over a container in reverse
template <typename T>
class ReversedAdapter {
 public:
  explicit ReversedAdapter(T& t) : t_(t) {}
  auto begin() { return std::rbegin(t_); }
  auto end() { return std::rend(t_); }
  auto begin() const { return std::rbegin(t_); }
  auto end() const { return std::rend(t_); }
 private:
  T& t_;
};

template <typename T>
ReversedAdapter<T> Reversed(T& t) {
  return ReversedAdapter<T>(t);
}

}  // namespace base

#endif  // BASE_CONTAINERS_ADAPTERS_H_
