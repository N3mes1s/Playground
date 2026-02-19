// Copyright 2012 The Chromium Authors
// Standalone shim: base/files/file_path.h

#ifndef BASE_FILES_FILE_PATH_H_
#define BASE_FILES_FILE_PATH_H_

#include <string>
#include <string_view>

namespace base {

// Minimal FilePath for standalone sandbox build.
class FilePath {
 public:
  using StringType = std::string;
  using CharType = char;
  using StringViewType = std::string_view;

  static constexpr CharType kSeparators[] = "/";
  static constexpr CharType kCurrentDirectory[] = ".";
  static constexpr CharType kParentDirectory[] = "..";

  FilePath() = default;
  explicit FilePath(StringViewType path) : path_(path) {}
  FilePath(const FilePath&) = default;
  FilePath& operator=(const FilePath&) = default;
  FilePath(FilePath&&) = default;
  FilePath& operator=(FilePath&&) = default;

  const StringType& value() const { return path_; }
  bool empty() const { return path_.empty(); }

  FilePath Append(StringViewType component) const {
    if (path_.empty()) return FilePath(std::string(component));
    if (component.empty()) return *this;
    std::string result = path_;
    if (result.back() != '/') result += '/';
    result += component;
    return FilePath(result);
  }

  FilePath Append(const FilePath& component) const {
    return Append(component.value());
  }

  FilePath DirName() const {
    auto pos = path_.rfind('/');
    if (pos == std::string::npos) return FilePath(".");
    if (pos == 0) return FilePath("/");
    return FilePath(path_.substr(0, pos));
  }

  FilePath BaseName() const {
    auto pos = path_.rfind('/');
    if (pos == std::string::npos) return *this;
    return FilePath(path_.substr(pos + 1));
  }

  bool operator==(const FilePath& other) const { return path_ == other.path_; }
  bool operator!=(const FilePath& other) const { return path_ != other.path_; }
  bool operator<(const FilePath& other) const { return path_ < other.path_; }

 private:
  StringType path_;
};

}  // namespace base

#endif  // BASE_FILES_FILE_PATH_H_
