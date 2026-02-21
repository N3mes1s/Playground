// Copyright 2012 The Chromium Authors
// Standalone shim: base/files/file_util.h

#ifndef BASE_FILES_FILE_UTIL_H_
#define BASE_FILES_FILE_UTIL_H_

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "base/files/file.h"
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

inline bool CreateTemporaryFile(FilePath* path) {
  char tmpl[] = "/tmp/base_tmp_XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd < 0) return false;
  close(fd);
  *path = FilePath(tmpl);
  return true;
}

inline bool IsDirectoryEmpty(const FilePath& path) {
  DIR* dir = opendir(path.value().c_str());
  if (!dir) return true;
  struct dirent* entry;
  bool empty = true;
  while ((entry = readdir(dir)) != nullptr) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      empty = false;
      break;
    }
  }
  closedir(dir);
  return empty;
}

inline File CreateAndOpenTemporaryFileInDir(const FilePath& dir,
                                             FilePath* path) {
  std::string tmpl = dir.value() + "/tmpXXXXXX";
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  int fd = mkstemp(buf.data());
  if (fd < 0) return File();
  *path = FilePath(buf.data());
  return File(fd);
}

inline bool CreateDirectory(const FilePath& path) {
  return mkdir(path.value().c_str(), 0755) == 0 || errno == EEXIST;
}

inline bool DeleteFile(const FilePath& path) {
  return unlink(path.value().c_str()) == 0 || rmdir(path.value().c_str()) == 0;
}

}  // namespace base

#endif  // BASE_FILES_FILE_UTIL_H_
