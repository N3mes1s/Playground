// Standalone shim: base/files/file_enumerator.h
// Enumerates files in a directory.

#ifndef BASE_FILES_FILE_ENUMERATOR_H_
#define BASE_FILES_FILE_ENUMERATOR_H_

#include <dirent.h>
#include <sys/stat.h>
#include <string>
#include <vector>

#include "base/files/file_path.h"

namespace base {

class FileEnumerator {
 public:
  enum FileType {
    FILES = 1,
    DIRECTORIES = 2,
  };

  FileEnumerator(const FilePath& root_path, bool recursive, int file_type)
      : root_path_(root_path), recursive_(recursive), file_type_(file_type) {
    Enumerate(root_path_.value());
    index_ = 0;
  }

  FileEnumerator(const FilePath& root_path, bool recursive, int file_type,
                 const std::string& pattern)
      : FileEnumerator(root_path, recursive, file_type) {
    // Pattern matching not implemented in stub
  }

  FilePath Next() {
    if (index_ >= entries_.size()) return FilePath();
    return entries_[index_++];
  }

 private:
  void Enumerate(const std::string& path) {
    DIR* dir = opendir(path.c_str());
    if (!dir) return;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
      std::string name = entry->d_name;
      if (name == "." || name == "..") continue;
      std::string full = path + "/" + name;
      struct stat st;
      if (stat(full.c_str(), &st) != 0) continue;
      if (S_ISDIR(st.st_mode)) {
        if (file_type_ & DIRECTORIES)
          entries_.push_back(FilePath(full));
        if (recursive_)
          Enumerate(full);
      } else if (S_ISREG(st.st_mode)) {
        if (file_type_ & FILES)
          entries_.push_back(FilePath(full));
      }
    }
    closedir(dir);
  }

  FilePath root_path_;
  bool recursive_;
  int file_type_;
  std::vector<FilePath> entries_;
  size_t index_ = 0;
};

}  // namespace base

#endif  // BASE_FILES_FILE_ENUMERATOR_H_
