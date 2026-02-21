// Standalone shim: base/location.h
// FROM_HERE is a source location annotation used throughout Chromium.
#ifndef BASE_LOCATION_H_
#define BASE_LOCATION_H_

namespace base {

class Location {
 public:
  constexpr Location() = default;
  constexpr Location(const char* file, int line) : file_(file), line_(line) {}
  const char* file_name() const { return file_; }
  int line_number() const { return line_; }

 private:
  const char* file_ = "";
  int line_ = -1;
};

}  // namespace base

#define FROM_HERE ::base::Location(__FILE__, __LINE__)

#endif  // BASE_LOCATION_H_
