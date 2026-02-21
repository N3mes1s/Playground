// Stub: base/strings/pattern.h
#ifndef BASE_STRINGS_PATTERN_H_
#define BASE_STRINGS_PATTERN_H_

#include <string>
#include <string_view>

namespace base {

// Simple pattern matching: supports only '*' as wildcard
inline bool MatchPattern(std::string_view str, std::string_view pattern) {
  // Simple glob match for unit_tests.cc DeathSEGVMessagePattern
  size_t si = 0, pi = 0;
  size_t star_si = std::string::npos, star_pi = std::string::npos;
  while (si < str.size()) {
    if (pi < pattern.size() && (pattern[pi] == str[si] || pattern[pi] == '?')) {
      ++si;
      ++pi;
    } else if (pi < pattern.size() && pattern[pi] == '*') {
      star_pi = pi++;
      star_si = si;
    } else if (star_pi != std::string::npos) {
      pi = star_pi + 1;
      si = ++star_si;
    } else {
      return false;
    }
  }
  while (pi < pattern.size() && pattern[pi] == '*') ++pi;
  return pi == pattern.size();
}

}  // namespace base

#endif  // BASE_STRINGS_PATTERN_H_
