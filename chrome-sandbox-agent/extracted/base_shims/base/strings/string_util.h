// Copyright 2013 The Chromium Authors
// Standalone shim: base/strings/string_util.h

#ifndef BASE_STRINGS_STRING_UTIL_H_
#define BASE_STRINGS_STRING_UTIL_H_

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace base {

enum class CompareCase {
  SENSITIVE,
  INSENSITIVE_ASCII,
};

enum TrimPositions {
  TRIM_NONE = 0,
  TRIM_LEADING = 1 << 0,
  TRIM_TRAILING = 1 << 1,
  TRIM_ALL = TRIM_LEADING | TRIM_TRAILING,
};

inline char ToLowerASCII(char c) {
  return (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c;
}

inline char ToUpperASCII(char c) {
  return (c >= 'a' && c <= 'z') ? (c - ('a' - 'A')) : c;
}

inline bool IsAsciiWhitespace(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

inline bool IsAsciiDigit(char c) { return c >= '0' && c <= '9'; }
inline bool IsAsciiAlpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
inline bool IsHexDigit(char c) {
  return IsAsciiDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline int HexDigitToInt(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

inline bool StartsWith(std::string_view str, std::string_view search_for,
                        CompareCase case_sensitivity = CompareCase::SENSITIVE) {
  if (search_for.size() > str.size()) return false;
  auto sub = str.substr(0, search_for.size());
  if (case_sensitivity == CompareCase::SENSITIVE)
    return sub == search_for;
  for (size_t i = 0; i < search_for.size(); ++i)
    if (ToLowerASCII(sub[i]) != ToLowerASCII(search_for[i])) return false;
  return true;
}

inline bool EndsWith(std::string_view str, std::string_view search_for,
                      CompareCase case_sensitivity = CompareCase::SENSITIVE) {
  if (search_for.size() > str.size()) return false;
  auto sub = str.substr(str.size() - search_for.size());
  if (case_sensitivity == CompareCase::SENSITIVE)
    return sub == search_for;
  for (size_t i = 0; i < search_for.size(); ++i)
    if (ToLowerASCII(sub[i]) != ToLowerASCII(search_for[i])) return false;
  return true;
}

inline bool EqualsCaseInsensitiveASCII(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (ToLowerASCII(a[i]) != ToLowerASCII(b[i])) return false;
  return true;
}

inline bool IsStringASCII(std::string_view str) {
  for (char c : str)
    if (static_cast<unsigned char>(c) > 127) return false;
  return true;
}

inline char* WriteInto(std::string* str, size_t length_with_null) {
  str->resize(length_with_null - 1);
  return str->empty() ? nullptr : &(*str)[0];
}

// Portable snprintf/vsnprintf wrappers
inline int snprintf(char* buf, size_t size, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int result = ::vsnprintf(buf, size, fmt, ap);
  va_end(ap);
  return result;
}

inline int vsnprintf(char* buf, size_t size, const char* fmt, va_list ap) {
  return ::vsnprintf(buf, size, fmt, ap);
}

// strlcpy: BSD-style safe string copy
inline size_t strlcpy(char* dst, const char* src, size_t dst_size) {
  size_t src_len = strlen(src);
  if (dst_size > 0) {
    size_t copy_len = (src_len >= dst_size) ? dst_size - 1 : src_len;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
  }
  return src_len;
}

}  // namespace base

#endif  // BASE_STRINGS_STRING_UTIL_H_
