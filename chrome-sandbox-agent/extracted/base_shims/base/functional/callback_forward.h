// Copyright 2011 The Chromium Authors
// Standalone shim: base/functional/callback_forward.h

#ifndef BASE_FUNCTIONAL_CALLBACK_FORWARD_H_
#define BASE_FUNCTIONAL_CALLBACK_FORWARD_H_

#include <functional>
#include <utility>

namespace base {

// Wrapper around std::function that adds Chromium's .Run() and .is_null() API.
template <typename Signature>
class OnceCallback;

template <typename R, typename... Args>
class OnceCallback<R(Args...)> {
 public:
  OnceCallback() = default;
  OnceCallback(std::nullptr_t) {}

  template <typename F>
  OnceCallback(F&& f) : func_(std::forward<F>(f)) {}

  OnceCallback(OnceCallback&&) = default;
  OnceCallback& operator=(OnceCallback&&) = default;
  OnceCallback(const OnceCallback&) = default;
  OnceCallback& operator=(const OnceCallback&) = default;

  bool is_null() const { return !func_; }
  explicit operator bool() const { return !!func_; }

  R Run(Args... args) {
    return func_(std::forward<Args>(args)...);
  }

 private:
  std::function<R(Args...)> func_;
};

template <typename Signature>
class RepeatingCallback;

template <typename R, typename... Args>
class RepeatingCallback<R(Args...)> {
 public:
  RepeatingCallback() = default;
  RepeatingCallback(std::nullptr_t) {}

  template <typename F>
  RepeatingCallback(F&& f) : func_(std::forward<F>(f)) {}

  RepeatingCallback(RepeatingCallback&&) = default;
  RepeatingCallback& operator=(RepeatingCallback&&) = default;
  RepeatingCallback(const RepeatingCallback&) = default;
  RepeatingCallback& operator=(const RepeatingCallback&) = default;

  bool is_null() const { return !func_; }
  explicit operator bool() const { return !!func_; }

  R Run(Args... args) const {
    return func_(std::forward<Args>(args)...);
  }

 private:
  std::function<R(Args...)> func_;
};

using OnceClosure = OnceCallback<void()>;
using RepeatingClosure = RepeatingCallback<void()>;

}  // namespace base

#endif  // BASE_FUNCTIONAL_CALLBACK_FORWARD_H_
