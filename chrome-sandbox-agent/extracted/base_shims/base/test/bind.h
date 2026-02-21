// Standalone shim: base/test/bind.h
// Provides BindLambdaForTesting and other test-only binding helpers.

#ifndef BASE_TEST_BIND_H_
#define BASE_TEST_BIND_H_

#include <functional>
#include <utility>

namespace base {

// BindLambdaForTesting: wraps a lambda into a callable.
// In Chromium, this converts a lambda to OnceCallback/RepeatingCallback.
// Available in both base:: and base::test:: namespaces.
template <typename Lambda>
auto BindLambdaForTesting(Lambda&& lambda) {
  return std::forward<Lambda>(lambda);
}

namespace test {
using base::BindLambdaForTesting;
}  // namespace test

}  // namespace base

#endif  // BASE_TEST_BIND_H_
