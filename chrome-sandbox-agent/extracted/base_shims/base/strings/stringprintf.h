// Copyright 2013 The Chromium Authors
// Standalone shim: base/strings/stringprintf.h

#ifndef BASE_STRINGS_STRINGPRINTF_H_
#define BASE_STRINGS_STRINGPRINTF_H_

#include <cstdarg>
#include <cstdio>
#include <string>

#include "base/compiler_specific.h"

namespace base {

inline std::string StringPrintV(const char* format, va_list ap) {
  va_list ap_copy;
  va_copy(ap_copy, ap);
  int size = vsnprintf(nullptr, 0, format, ap_copy);
  va_end(ap_copy);
  if (size < 0) return {};
  std::string result(size, '\0');
  vsnprintf(result.data(), size + 1, format, ap);
  return result;
}

inline std::string StringPrintf(const char* format, ...)
    PRINTF_FORMAT(1, 2);

inline std::string StringPrintf(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  std::string result = StringPrintV(format, ap);
  va_end(ap);
  return result;
}

inline void StringAppendV(std::string* dst, const char* format, va_list ap) {
  va_list ap_copy;
  va_copy(ap_copy, ap);
  int size = vsnprintf(nullptr, 0, format, ap_copy);
  va_end(ap_copy);
  if (size < 0) return;
  size_t old_size = dst->size();
  dst->resize(old_size + size);
  vsnprintf(dst->data() + old_size, size + 1, format, ap);
}

inline void StringAppendF(std::string* dst, const char* format, ...)
    PRINTF_FORMAT(2, 3);

inline void StringAppendF(std::string* dst, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  StringAppendV(dst, format, ap);
  va_end(ap);
}

}  // namespace base

#endif  // BASE_STRINGS_STRINGPRINTF_H_
