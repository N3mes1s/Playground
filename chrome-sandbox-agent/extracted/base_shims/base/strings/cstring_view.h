// Standalone shim: base/strings/cstring_view.h
#ifndef BASE_STRINGS_CSTRING_VIEW_H_
#define BASE_STRINGS_CSTRING_VIEW_H_

#include <cstring>
#include <string>
#include <string_view>

namespace base {

// cstring_view: a string_view guaranteed to be null-terminated.
class cstring_view {
 public:
  constexpr cstring_view() : ptr_("") {}
  // NOLINTNEXTLINE(google-explicit-constructor)
  constexpr cstring_view(const char* s) : ptr_(s ? s : "") {}
  // NOLINTNEXTLINE(google-explicit-constructor)
  cstring_view(const std::string& s) : ptr_(s.c_str()) {}

  const char* c_str() const { return ptr_; }
  const char* data() const { return ptr_; }
  size_t size() const { return std::strlen(ptr_); }
  size_t length() const { return size(); }
  bool empty() const { return ptr_[0] == '\0'; }

  // Implicit conversion to string_view
  operator std::string_view() const { return std::string_view(ptr_); }

  bool operator==(const cstring_view& o) const { return std::strcmp(ptr_, o.ptr_) == 0; }
  bool operator!=(const cstring_view& o) const { return std::strcmp(ptr_, o.ptr_) != 0; }
  bool operator==(const char* s) const { return std::strcmp(ptr_, s) == 0; }
  bool operator!=(const char* s) const { return std::strcmp(ptr_, s) != 0; }

 private:
  const char* ptr_;
};

}  // namespace base

#endif  // BASE_STRINGS_CSTRING_VIEW_H_
