// Copyright 2012 The Chromium Authors
// Standalone shim: base/files/file_util.h

#ifndef BASE_FILES_FILE_UTIL_H_
#define BASE_FILES_FILE_UTIL_H_

#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>

#include "base/files/file_path.h"

namespace base {

inline bool PathExists(const FilePath& path) {
  struct stat st;
  return stat(path.value().c_str(), &st) == 0;
}

inline bool DirectoryExists(const FilePath& path) {
  struct stat st;
  return stat(path.value().c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

inline bool ReadFileToString(const FilePath& path, std::string* contents) {
  std::ifstream file(path.value());
  if (!file.is_open()) return false;
  std::ostringstream ss;
  ss << file.rdbuf();
  *contents = ss.str();
  return true;
}

inline bool ReadFileToStringWithMaxSize(const FilePath& path,
                                        std::string* contents,
                                        size_t max_size) {
  std::ifstream file(path.value());
  if (!file.is_open()) return false;
  contents->resize(max_size);
  file.read(contents->data(), max_size);
  contents->resize(file.gcount());
  return true;
}

inline int WriteFile(const FilePath& path, const char* data, int size) {
  std::ofstream file(path.value(), std::ios::binary);
  if (!file.is_open()) return -1;
  file.write(data, size);
  return file.good() ? size : -1;
}

}  // namespace base

#endif  // BASE_FILES_FILE_UTIL_H_
