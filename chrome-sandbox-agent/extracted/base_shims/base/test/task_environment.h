// Standalone shim: base/test/task_environment.h
// In Chromium, TaskEnvironment provides a message loop and thread pool.
// For standalone, this is a minimal stub.

#ifndef BASE_TEST_TASK_ENVIRONMENT_H_
#define BASE_TEST_TASK_ENVIRONMENT_H_

namespace base {
namespace test {

class TaskEnvironment {
 public:
  enum class MainThreadType {
    DEFAULT,
    IO,
    UI,
  };

  TaskEnvironment() = default;
  explicit TaskEnvironment(MainThreadType) {}
  ~TaskEnvironment() = default;

  void RunUntilIdle() {}
};

// SingleThreadTaskEnvironment: TaskEnvironment with single-threaded message loop
using SingleThreadTaskEnvironment = TaskEnvironment;

}  // namespace test
}  // namespace base

#endif  // BASE_TEST_TASK_ENVIRONMENT_H_
