// Standalone shim: base/task/single_thread_task_runner.h
// Stub for standalone builds.

#ifndef BASE_TASK_SINGLE_THREAD_TASK_RUNNER_H_
#define BASE_TASK_SINGLE_THREAD_TASK_RUNNER_H_

namespace base {

class SingleThreadTaskRunner {
 public:
  virtual ~SingleThreadTaskRunner() = default;
};

}  // namespace base

#endif  // BASE_TASK_SINGLE_THREAD_TASK_RUNNER_H_
