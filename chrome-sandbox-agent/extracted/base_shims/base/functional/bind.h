// Copyright 2011 The Chromium Authors
// Standalone shim: base/functional/bind.h

#ifndef BASE_FUNCTIONAL_BIND_H_
#define BASE_FUNCTIONAL_BIND_H_

#include <functional>
#include <tuple>
#include <utility>

#include "base/functional/callback.h"

namespace base {

namespace internal {

// Helper to invoke a callable with bound args + remaining args.
// Uses tuple to store bound args and std::apply for invocation.
template <typename F, typename BoundTuple, typename... RemainingArgs>
decltype(auto) InvokeWithBound(F&& f, BoundTuple&& bound,
                                RemainingArgs&&... remaining) {
  return std::apply(
      [&](auto&&... bound_args) -> decltype(auto) {
        return std::invoke(std::forward<F>(f),
                           std::forward<decltype(bound_args)>(bound_args)...,
                           std::forward<RemainingArgs>(remaining)...);
      },
      std::forward<BoundTuple>(bound));
}

}  // namespace internal

// BindOnce: creates a callable that captures bound args and forwards remaining args.
// Unlike std::bind, this properly handles partial application without placeholders.
template <typename Functor, typename... BoundArgs>
auto BindOnce(Functor&& f, BoundArgs&&... bound_args) {
  auto bound = std::make_tuple(std::forward<BoundArgs>(bound_args)...);
  return [f = std::forward<Functor>(f),
          bound = std::move(bound)](auto&&... remaining) mutable -> decltype(auto) {
    return internal::InvokeWithBound(
        std::move(f), std::move(bound),
        std::forward<decltype(remaining)>(remaining)...);
  };
}

template <typename Functor, typename... BoundArgs>
auto BindRepeating(Functor&& f, BoundArgs&&... bound_args) {
  auto bound = std::make_tuple(std::forward<BoundArgs>(bound_args)...);
  return [f = std::forward<Functor>(f),
          bound = std::move(bound)](auto&&... remaining) mutable -> decltype(auto) {
    return internal::InvokeWithBound(
        f, bound,
        std::forward<decltype(remaining)>(remaining)...);
  };
}

// Unretained: raw pointer binding (dangerous, but used throughout Chromium)
template <typename T>
T* Unretained(T* ptr) { return ptr; }

}  // namespace base

#endif  // BASE_FUNCTIONAL_BIND_H_
