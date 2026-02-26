// Copyright 2020 The Chromium Authors
// Standalone shim: base/check.h
// Provides CHECK/DCHECK/PCHECK macros with stream support.

#ifndef BASE_CHECK_H_
#define BASE_CHECK_H_

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <unistd.h>

#include "base/compiler_specific.h"

namespace logging {

// Stream that discards everything written to it.
class VoidifyStream {
 public:
  void operator&(std::ostream&) {}
};

// CheckError provides << streaming for CHECK failure messages.
class CheckError {
 public:
  CheckError(const char* file, int line, const char* condition)
      : file_(file), line_(line) {
    stream_ << file << ":" << line << ": CHECK failed: " << condition << ". ";
  }

  CheckError(const char* file, int line, const char* condition, bool is_pcheck)
      : file_(file), line_(line), is_pcheck_(is_pcheck) {
    stream_ << file << ":" << line << ": PCHECK failed: " << condition << ". ";
  }

  ~CheckError() {
    if (is_pcheck_) {
      stream_ << ": " << strerror(saved_errno_);
    }
    stream_ << "\n";
    fprintf(stderr, "%s", stream_.str().c_str());
    fflush(stderr);
    _exit(1);
  }

  std::ostream& stream() { return stream_; }

  // Non-copyable, non-movable
  CheckError(const CheckError&) = delete;
  CheckError& operator=(const CheckError&) = delete;

 private:
  const char* file_;
  int line_;
  bool is_pcheck_ = false;
  int saved_errno_ = errno;
  std::ostringstream stream_;
};

// NotReachedError for NOTREACHED()
class NotReachedError {
 public:
  NotReachedError(const char* file, int line) {
    stream_ << file << ":" << line << ": NOTREACHED hit. ";
  }
  ~NotReachedError() {
    stream_ << "\n";
    fprintf(stderr, "%s", stream_.str().c_str());
    fflush(stderr);
    _exit(1);
  }
  std::ostream& stream() { return stream_; }
  NotReachedError(const NotReachedError&) = delete;
  NotReachedError& operator=(const NotReachedError&) = delete;

 private:
  std::ostringstream stream_;
};

[[noreturn]] inline void RawCheckFailure(const char* message) {
  fprintf(stderr, "RAW_CHECK failed: %s\n", message);
  _exit(1);
}

}  // namespace logging

// Core CHECK macros with stream support: CHECK(cond) << "msg";
#define CHECK(condition, ...)                                   \
  (condition) ? (void)0                                         \
              : ::logging::VoidifyStream() &                    \
                    ::logging::CheckError(__FILE__, __LINE__,   \
                                          #condition)           \
                        .stream()

#define DCHECK(condition, ...) CHECK(condition)

#define PCHECK(condition, ...)                                  \
  (condition) ? (void)0                                         \
              : ::logging::VoidifyStream() &                    \
                    ::logging::CheckError(__FILE__, __LINE__,   \
                                          #condition, true)     \
                        .stream()

#define DPCHECK(condition, ...) PCHECK(condition)

#define RAW_CHECK(condition)                                    \
  do {                                                          \
    if (!(condition))                                           \
      ::logging::RawCheckFailure(#condition);                   \
  } while (0)

#define DUMP_WILL_BE_CHECK(condition, ...) CHECK(condition)

#define CHECK_WILL_STREAM() true

// Eat stream params when checks are compiled out (they never are in our case)
#define EAT_CHECK_STREAM_PARAMS(expr) \
  true ? (void)0 : ::logging::VoidifyStream() & (expr)

// NotFatalUntil stub (Chromium milestone-based rollout mechanism)
namespace base {
enum class NotFatalUntil { M0 = 0 };
}

#endif  // BASE_CHECK_H_
