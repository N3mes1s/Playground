// Copyright 2011 The Chromium Authors
// Standalone shim: base/functional/bind.h

#ifndef BASE_FUNCTIONAL_BIND_H_
#define BASE_FUNCTIONAL_BIND_H_

#include <functional>
#include "base/functional/callback.h"

namespace base {

// Map base::BindOnce / base::BindRepeating to std::bind / lambda captures.
// The real Chromium versions are much more sophisticated, but for sandbox
// usage this is sufficient.

template <typename Functor, typename... Args>
auto BindOnce(Functor&& f, Args&&... args) {
  return std::bind(std::forward<Functor>(f), std::forward<Args>(args)...);
}

template <typename Functor, typename... Args>
auto BindRepeating(Functor&& f, Args&&... args) {
  return std::bind(std::forward<Functor>(f), std::forward<Args>(args)...);
}

// Unretained: raw pointer binding (dangerous, but used throughout Chromium)
template <typename T>
T* Unretained(T* ptr) { return ptr; }

}  // namespace base

#endif  // BASE_FUNCTIONAL_BIND_H_
