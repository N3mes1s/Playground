// Copyright 2013 The Chromium Authors
// Standalone shim: base/strings/safe_sprintf.h
// Async-signal-safe string formatting.
// In the full Chromium, this is a custom implementation that avoids malloc.
// For the standalone build, we provide a thin wrapper around snprintf.

#ifndef BASE_STRINGS_SAFE_SPRINTF_H_
#define BASE_STRINGS_SAFE_SPRINTF_H_

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstring>

namespace base {
namespace strings {

// SafeSNPrintf: snprintf-based implementation.
// Not truly async-signal-safe (unlike Chromium's), but sufficient for
// the standalone sandbox build where signal-handler formatting is rare.
inline ssize_t SafeSNPrintf(char* buf, size_t N, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int result = vsnprintf(buf, N, fmt, ap);
  va_end(ap);
  return result;
}

// SafeSPrintf: fixed-size buffer variant.
template <size_t N>
ssize_t SafeSPrintf(char (&buf)[N], const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int result = vsnprintf(buf, N, fmt, ap);
  va_end(ap);
  return result;
}

}  // namespace strings
}  // namespace base

#endif  // BASE_STRINGS_SAFE_SPRINTF_H_
