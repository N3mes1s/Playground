// Copyright 2012 The Chromium Authors
// Standalone shim: base/logging.h
// Provides LOG/DLOG/VLOG/PLOG macros with ostream-style streaming.

#ifndef BASE_LOGGING_H_
#define BASE_LOGGING_H_

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <unistd.h>

#include "base/check.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"

namespace logging {

// Log severities
enum LogSeverity {
  LOGGING_INFO = 0,
  LOGGING_WARNING = 1,
  LOGGING_ERROR = 2,
  LOGGING_FATAL = 3,
  LOGGING_DFATAL = LOGGING_FATAL,  // In standalone builds, DFATAL = FATAL
  LOGGING_NUM_SEVERITIES = 4,
};

using SystemErrorCode = int;

inline SystemErrorCode GetLastSystemErrorCode() {
  return errno;
}

inline std::string SystemErrorCodeToString(SystemErrorCode error_code) {
  return strerror(error_code);
}

// LogMessage: accumulates a log message, writes to stderr on destruction.
class LogMessage {
 public:
  LogMessage(const char* file, int line, LogSeverity severity)
      : file_(file), line_(line), severity_(severity) {}

  ~LogMessage() {
    const char* severity_str = "INFO";
    switch (severity_) {
      case LOGGING_INFO: severity_str = "INFO"; break;
      case LOGGING_WARNING: severity_str = "WARNING"; break;
      case LOGGING_ERROR: severity_str = "ERROR"; break;
      case LOGGING_FATAL: severity_str = "FATAL"; break;
      default: break;
    }
    fprintf(stderr, "[%s:%d(%s)] %s\n", file_, line_, severity_str,
            stream_.str().c_str());
    fflush(stderr);
    if (severity_ >= LOGGING_FATAL) {
      _exit(1);
    }
  }

  std::ostream& stream() { return stream_; }

  LogMessage(const LogMessage&) = delete;
  LogMessage& operator=(const LogMessage&) = delete;

 private:
  const char* file_;
  int line_;
  LogSeverity severity_;
  std::ostringstream stream_;
};

// Errno-appending variant (for PLOG)
class ErrnoLogMessage {
 public:
  ErrnoLogMessage(const char* file, int line, LogSeverity severity)
      : file_(file), line_(line), severity_(severity), saved_errno_(errno) {}

  ~ErrnoLogMessage() {
    const char* severity_str = "INFO";
    switch (severity_) {
      case LOGGING_WARNING: severity_str = "WARNING"; break;
      case LOGGING_ERROR: severity_str = "ERROR"; break;
      case LOGGING_FATAL: severity_str = "FATAL"; break;
      default: break;
    }
    fprintf(stderr, "[%s:%d(%s)] %s: %s (errno %d)\n", file_, line_,
            severity_str, stream_.str().c_str(), strerror(saved_errno_),
            saved_errno_);
    fflush(stderr);
    if (severity_ >= LOGGING_FATAL) {
      _exit(1);
    }
  }

  std::ostream& stream() { return stream_; }

  ErrnoLogMessage(const ErrnoLogMessage&) = delete;
  ErrnoLogMessage& operator=(const ErrnoLogMessage&) = delete;

 private:
  const char* file_;
  int line_;
  LogSeverity severity_;
  int saved_errno_;
  std::ostringstream stream_;
};

// LogMessageVoidify: for EAT_STREAM_PARAMETERS pattern
class LogMessageVoidify {
 public:
  void operator&(std::ostream&) {}
};

// [[noreturn]] variant for LOG(FATAL)
class LogMessageFatal {
 public:
  LogMessageFatal(const char* file, int line, LogSeverity severity = LOGGING_FATAL)
      : file_(file), line_(line) {}
  [[noreturn]] ~LogMessageFatal() {
    fprintf(stderr, "[%s:%d(FATAL)] %s\n", file_, line_,
            stream_.str().c_str());
    fflush(stderr);
    _exit(1);
  }
  std::ostream& stream() { return stream_; }

 private:
  const char* file_;
  int line_;
  std::ostringstream stream_;
};

// [[noreturn]] errno variant for PLOG(FATAL)
class ErrnoLogMessageFatal {
 public:
  ErrnoLogMessageFatal(const char* file, int line)
      : file_(file), line_(line), saved_errno_(errno) {}
  [[noreturn]] ~ErrnoLogMessageFatal() {
    fprintf(stderr, "[%s:%d(FATAL)] %s: %s (errno %d)\n", file_, line_,
            stream_.str().c_str(), strerror(saved_errno_), saved_errno_);
    fflush(stderr);
    _exit(1);
  }
  std::ostream& stream() { return stream_; }

 private:
  const char* file_;
  int line_;
  int saved_errno_;
  std::ostringstream stream_;
};

inline void RawLog(int level, const char* message) {
  fprintf(stderr, "[RAW] %s\n", message);
  if (level >= LOGGING_FATAL)
    _exit(1);
}

// MSAN/sanitizer macros (no-ops in standalone build)
#define MSAN_UNPOISON(ptr, size)

}  // namespace logging

// --- Core LOG macros ---

// LOG(severity) << "message";
#define LOG(severity)                                                          \
  ::logging::LogMessage(__FILE__, __LINE__, ::logging::LOGGING_##severity)     \
      .stream()

#define LOG_IF(severity, condition)                                            \
  !(condition) ? (void)0 : ::logging::LogMessageVoidify() & LOG(severity)

#define LOG_IS_ON(severity) true

// VLOG: always enabled at all levels in this standalone build.
#define VLOG(verbose_level) LOG(INFO)
#define VLOG_IS_ON(verboselevel) true
#define VLOG_IF(verboselevel, condition) LOG_IF(INFO, condition)

// DLOG: same as LOG in debug/standalone builds.
#define DLOG(severity) LOG(severity)
#define DLOG_IF(severity, condition) LOG_IF(severity, condition)
#define DVLOG(verboselevel) VLOG(verboselevel)
#define DVLOG_IF(verboselevel, condition) VLOG_IF(verboselevel, condition)

// PLOG: LOG + errno string
#define PLOG(severity)                                                         \
  ::logging::ErrnoLogMessage(__FILE__, __LINE__,                               \
                             ::logging::LOGGING_##severity)                     \
      .stream()

#define PLOG_IF(severity, condition)                                           \
  !(condition) ? (void)0 : ::logging::LogMessageVoidify() & PLOG(severity)

#define DPLOG(severity) PLOG(severity)
#define DPLOG_IF(severity, condition) PLOG_IF(severity, condition)

// RAW_LOG for async-signal-safe contexts
#define RAW_LOG(level, message) ::logging::RawLog(::logging::LOGGING_##level, message)

// LOG_ASSERT
#define LOG_ASSERT(condition) CHECK(condition)

// EAT_STREAM_PARAMETERS: suppress unused stream expressions
#define EAT_STREAM_PARAMETERS                                                  \
  true ? (void)0 : ::logging::LogMessageVoidify() &                           \
                        ::logging::LogMessage(__FILE__, __LINE__,              \
                                              ::logging::LOGGING_INFO)        \
                            .stream()

#endif  // BASE_LOGGING_H_
