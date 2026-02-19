// Standalone shim: base/strings/cstring_view.h
#ifndef BASE_STRINGS_CSTRING_VIEW_H_
#define BASE_STRINGS_CSTRING_VIEW_H_

#include <string_view>

namespace base {

// cstring_view: a string_view guaranteed to be null-terminated.
// In standalone build, just alias to string_view.
using cstring_view = std::string_view;

}  // namespace base

#endif  // BASE_STRINGS_CSTRING_VIEW_H_
