// Standalone shim: base/debug/crash_logging.h
#ifndef BASE_DEBUG_CRASH_LOGGING_H_
#define BASE_DEBUG_CRASH_LOGGING_H_

#include <string>
#include <string_view>

namespace base::debug {

enum class CrashKeySize {
  Size32 = 32,
  Size64 = 64,
  Size256 = 256,
};

class CrashKeyString {
 public:
  CrashKeyString(const char* name, CrashKeySize max_len) {}
  CrashKeyString(const char* name, size_t max_len) {}
};

inline CrashKeyString* AllocateCrashKeyString(const char* name,
                                               CrashKeySize size) {
  // No-op in standalone build: return a static dummy
  static CrashKeyString dummy("", CrashKeySize::Size256);
  return &dummy;
}

inline void SetCrashKeyString(CrashKeyString*, std::string_view) {}

// SCOPED_CRASH_KEY_STRING_VALUE: no-op in standalone.
#define SCOPED_CRASH_KEY_STRING_VALUE(category, name, value)

}  // namespace base::debug

#endif  // BASE_DEBUG_CRASH_LOGGING_H_
