// Standalone shim: base/test/multiprocess_test.h
// In Chromium, MultiProcessTest supports forking child processes for tests.

#ifndef BASE_TEST_MULTIPROCESS_TEST_H_
#define BASE_TEST_MULTIPROCESS_TEST_H_

#include "testing/gtest/include/gtest/gtest.h"

namespace base {

class MultiProcessTest : public ::testing::Test {
 public:
  MultiProcessTest() = default;
};

}  // namespace base

#endif  // BASE_TEST_MULTIPROCESS_TEST_H_
