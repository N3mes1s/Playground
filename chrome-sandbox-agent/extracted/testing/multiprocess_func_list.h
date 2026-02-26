// Standalone shim: testing/multiprocess_func_list.h
// In Chromium, this provides MULTIPROCESS_TEST_MAIN macro for child processes.

#ifndef TESTING_MULTIPROCESS_FUNC_LIST_H_
#define TESTING_MULTIPROCESS_FUNC_LIST_H_

// MULTIPROCESS_TEST_MAIN defines a function that can be invoked as a child
// process entry point. In standalone, we just define the function directly.
#define MULTIPROCESS_TEST_MAIN(function_name)                          \
  int function_name(int argc, char** argv);                            \
  static struct MultiProcessTestRegistration_##function_name {         \
    MultiProcessTestRegistration_##function_name() {}                  \
  } g_registration_##function_name;                                    \
  int function_name(int argc, char** argv)

#endif  // TESTING_MULTIPROCESS_FUNC_LIST_H_
