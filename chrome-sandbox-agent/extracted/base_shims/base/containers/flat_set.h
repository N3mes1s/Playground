// Copyright 2017 The Chromium Authors
// Standalone shim: base/containers/flat_set.h

#ifndef BASE_CONTAINERS_FLAT_SET_H_
#define BASE_CONTAINERS_FLAT_SET_H_

#include <algorithm>
#include <functional>
#include <vector>

namespace base {

template <typename Key, typename Compare = std::less<Key>>
class flat_set {
 public:
  using value_type = Key;
  using iterator = typename std::vector<Key>::iterator;
  using const_iterator = typename std::vector<Key>::const_iterator;
  using size_type = size_t;

  flat_set() = default;
  flat_set(std::initializer_list<Key> init) : data_(init) {
    std::sort(data_.begin(), data_.end(), Compare{});
    data_.erase(std::unique(data_.begin(), data_.end()), data_.end());
  }

  iterator begin() { return data_.begin(); }
  iterator end() { return data_.end(); }
  const_iterator begin() const { return data_.begin(); }
  const_iterator end() const { return data_.end(); }

  bool empty() const { return data_.empty(); }
  size_type size() const { return data_.size(); }
  void clear() { data_.clear(); }

  bool contains(const Key& key) const { return find(key) != end(); }
  size_type count(const Key& key) const { return contains(key) ? 1 : 0; }

  const_iterator find(const Key& key) const {
    auto it = std::lower_bound(data_.begin(), data_.end(), key, Compare{});
    if (it != data_.end() && !Compare{}(key, *it) && !Compare{}(*it, key))
      return it;
    return data_.end();
  }

  std::pair<iterator, bool> insert(const Key& key) {
    auto it = std::lower_bound(data_.begin(), data_.end(), key, Compare{});
    if (it != data_.end() && !Compare{}(key, *it) && !Compare{}(*it, key))
      return {it, false};
    return {data_.insert(it, key), true};
  }

  iterator erase(const_iterator pos) { return data_.erase(pos); }
  size_type erase(const Key& key) {
    auto it = find(key);
    if (it == data_.end()) return 0;
    data_.erase(it);
    return 1;
  }

 private:
  std::vector<Key> data_;
};

}  // namespace base

#endif  // BASE_CONTAINERS_FLAT_SET_H_
