// Standalone shim: base/path_service.h
#ifndef BASE_PATH_SERVICE_H_
#define BASE_PATH_SERVICE_H_

#include <unistd.h>
#include "base/files/file_path.h"

namespace base {

enum { DIR_EXE = 0, DIR_MODULE = 1 };

class PathService {
 public:
  static bool Get(int key, FilePath* path) {
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) return false;
    buf[len] = '\0';
    *path = FilePath(buf);
    if (key == DIR_EXE || key == DIR_MODULE)
      *path = path->DirName();
    return true;
  }
};

}  // namespace base

#endif  // BASE_PATH_SERVICE_H_
