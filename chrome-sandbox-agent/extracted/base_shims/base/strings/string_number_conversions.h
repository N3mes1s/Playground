// Copyright 2012 The Chromium Authors
// Standalone shim: base/strings/string_number_conversions.h

#ifndef BASE_STRINGS_STRING_NUMBER_CONVERSIONS_H_
#define BASE_STRINGS_STRING_NUMBER_CONVERSIONS_H_

#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstdlib>
#include <string>
#include <string_view>

namespace base {

inline std::string NumberToString(int value) { return std::to_string(value); }
inline std::string NumberToString(unsigned int value) { return std::to_string(value); }
inline std::string NumberToString(long value) { return std::to_string(value); }
inline std::string NumberToString(unsigned long value) { return std::to_string(value); }
inline std::string NumberToString(long long value) { return std::to_string(value); }
inline std::string NumberToString(unsigned long long value) { return std::to_string(value); }
inline std::string NumberToString(double value) { return std::to_string(value); }

inline bool StringToInt(std::string_view input, int* output) {
  char* end;
  std::string s(input);
  errno = 0;
  long result = strtol(s.c_str(), &end, 10);
  if (errno != 0 || end == s.c_str() || *end != '\0') return false;
  if (result < INT_MIN || result > INT_MAX) return false;
  *output = static_cast<int>(result);
  return true;
}

inline bool StringToUint(std::string_view input, unsigned* output) {
  char* end;
  std::string s(input);
  errno = 0;
  unsigned long result = strtoul(s.c_str(), &end, 10);
  if (errno != 0 || end == s.c_str() || *end != '\0') return false;
  if (result > UINT_MAX) return false;
  *output = static_cast<unsigned>(result);
  return true;
}

inline bool StringToInt64(std::string_view input, int64_t* output) {
  char* end;
  std::string s(input);
  errno = 0;
  long long result = strtoll(s.c_str(), &end, 10);
  if (errno != 0 || end == s.c_str() || *end != '\0') return false;
  *output = static_cast<int64_t>(result);
  return true;
}

inline bool StringToUint64(std::string_view input, uint64_t* output) {
  char* end;
  std::string s(input);
  errno = 0;
  unsigned long long result = strtoull(s.c_str(), &end, 10);
  if (errno != 0 || end == s.c_str() || *end != '\0') return false;
  *output = static_cast<uint64_t>(result);
  return true;
}

inline bool StringToSizeT(std::string_view input, size_t* output) {
  uint64_t tmp;
  if (!StringToUint64(input, &tmp)) return false;
  *output = static_cast<size_t>(tmp);
  return true;
}

}  // namespace base

#endif  // BASE_STRINGS_STRING_NUMBER_CONVERSIONS_H_
