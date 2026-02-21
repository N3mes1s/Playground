// Standalone shim: base/files/scoped_temp_dir.h
// Creates a temporary directory and deletes it on destruction.

#ifndef BASE_FILES_SCOPED_TEMP_DIR_H_
#define BASE_FILES_SCOPED_TEMP_DIR_H_

#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <ftw.h>

#include "base/files/file_path.h"

namespace base {

class ScopedTempDir {
 public:
  ScopedTempDir() = default;
  ~ScopedTempDir() {
    if (!path_.empty()) {
      // Recursively remove the directory
      nftw(path_.value().c_str(),
           [](const char* fpath, const struct stat*, int, struct FTW*) -> int {
             return remove(fpath);
           },
           64, FTW_DEPTH | FTW_PHYS);
    }
  }

  ScopedTempDir(ScopedTempDir&& other) noexcept : path_(std::move(other.path_)) {
    other.path_ = FilePath();
  }
  ScopedTempDir& operator=(ScopedTempDir&& other) noexcept {
    path_ = std::move(other.path_);
    other.path_ = FilePath();
    return *this;
  }

  ScopedTempDir(const ScopedTempDir&) = delete;
  ScopedTempDir& operator=(const ScopedTempDir&) = delete;

  bool CreateUniqueTempDir() {
    char tmpl[] = "/tmp/chrome_sandbox_test_XXXXXX";
    char* result = mkdtemp(tmpl);
    if (!result) return false;
    path_ = FilePath(result);
    return true;
  }

  bool CreateUniqueTempDirUnderPath(const FilePath& base_path) {
    std::string tmpl = base_path.value() + "/chrome_test_XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    char* result = mkdtemp(buf.data());
    if (!result) return false;
    path_ = FilePath(result);
    return true;
  }

  bool IsValid() const { return !path_.empty(); }

  const FilePath& GetPath() const { return path_; }

  // Set the path, creating the directory if it doesn't already exist.
  bool Set(const FilePath& path) {
    struct stat st;
    if (stat(path.value().c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
      if (mkdir(path.value().c_str(), 0700) != 0)
        return false;
    }
    path_ = path;
    return true;
  }

  FilePath Take() {
    FilePath p = path_;
    path_ = FilePath();
    return p;
  }

 private:
  FilePath path_;
};

}  // namespace base

#endif  // BASE_FILES_SCOPED_TEMP_DIR_H_
