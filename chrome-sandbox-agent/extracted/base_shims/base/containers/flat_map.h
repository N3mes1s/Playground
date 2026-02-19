// Copyright 2017 The Chromium Authors
// Standalone shim: base/containers/flat_map.h
// Maps base::flat_map to a sorted std::vector-based map.

#ifndef BASE_CONTAINERS_FLAT_MAP_H_
#define BASE_CONTAINERS_FLAT_MAP_H_

#include <algorithm>
#include <functional>
#include <utility>
#include <vector>

namespace base {

// Minimal flat_map: a sorted vector of pairs.
// Matches the API surface used by the sandbox syscall_broker code.
template <typename Key, typename Value, typename Compare = std::less<Key>>
class flat_map {
 public:
  using key_type = Key;
  using mapped_type = Value;
  using value_type = std::pair<Key, Value>;
  using iterator = typename std::vector<value_type>::iterator;
  using const_iterator = typename std::vector<value_type>::const_iterator;
  using size_type = size_t;

  flat_map() = default;
  flat_map(std::initializer_list<value_type> init) : data_(init) {
    std::sort(data_.begin(), data_.end(), compare_pair);
  }

  iterator begin() { return data_.begin(); }
  iterator end() { return data_.end(); }
  const_iterator begin() const { return data_.begin(); }
  const_iterator end() const { return data_.end(); }
  const_iterator cbegin() const { return data_.cbegin(); }
  const_iterator cend() const { return data_.cend(); }

  bool empty() const { return data_.empty(); }
  size_type size() const { return data_.size(); }
  void clear() { data_.clear(); }

  iterator find(const Key& key) {
    auto it = lower_bound(key);
    if (it != end() && !Compare{}(key, it->first) && !Compare{}(it->first, key))
      return it;
    return end();
  }

  const_iterator find(const Key& key) const {
    auto it = lower_bound(key);
    if (it != end() && !Compare{}(key, it->first) && !Compare{}(it->first, key))
      return it;
    return end();
  }

  bool contains(const Key& key) const { return find(key) != end(); }

  size_type count(const Key& key) const { return contains(key) ? 1 : 0; }

  Value& operator[](const Key& key) {
    auto it = find(key);
    if (it != end()) return it->second;
    data_.push_back({key, Value{}});
    std::sort(data_.begin(), data_.end(), compare_pair);
    return find(key)->second;
  }

  std::pair<iterator, bool> insert(const value_type& val) {
    auto it = find(val.first);
    if (it != end()) return {it, false};
    data_.push_back(val);
    std::sort(data_.begin(), data_.end(), compare_pair);
    return {find(val.first), true};
  }

  template <typename... Args>
  std::pair<iterator, bool> emplace(Args&&... args) {
    return insert(value_type(std::forward<Args>(args)...));
  }

  iterator erase(const_iterator pos) { return data_.erase(pos); }
  size_type erase(const Key& key) {
    auto it = find(key);
    if (it == end()) return 0;
    data_.erase(it);
    return 1;
  }

 private:
  iterator lower_bound(const Key& key) {
    return std::lower_bound(data_.begin(), data_.end(), key,
                            [](const value_type& p, const Key& k) {
                              return Compare{}(p.first, k);
                            });
  }

  const_iterator lower_bound(const Key& key) const {
    return std::lower_bound(data_.begin(), data_.end(), key,
                            [](const value_type& p, const Key& k) {
                              return Compare{}(p.first, k);
                            });
  }

  static bool compare_pair(const value_type& a, const value_type& b) {
    return Compare{}(a.first, b.first);
  }

  std::vector<value_type> data_;
};

}  // namespace base

#endif  // BASE_CONTAINERS_FLAT_MAP_H_
