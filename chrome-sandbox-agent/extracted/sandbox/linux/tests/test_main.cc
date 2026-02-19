// test_main.cc - Simplified test main for Chrome sandbox tests.
// Replaces the full Chrome test runner (which requires base/test/) with
// a minimal gtest main that supports the SANDBOX_TEST / BPF_TEST_C macros.

#include "testing/gtest/include/gtest/gtest.h"

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  // Always use threadsafe death tests (Chrome's tests fork subprocesses)
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  return RUN_ALL_TESTS();
}
