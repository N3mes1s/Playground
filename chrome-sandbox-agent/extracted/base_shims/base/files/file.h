// Stub: base/files/file.h
#ifndef BASE_FILES_FILE_H_
#define BASE_FILES_FILE_H_

#include <fcntl.h>
#include <unistd.h>
#include <string>

#include "base/files/file_path.h"
#include "base/files/scoped_file.h"

namespace base {

class File {
 public:
  enum Flags {
    FLAG_OPEN = 1 << 0,
    FLAG_CREATE = 1 << 1,
    FLAG_OPEN_ALWAYS = 1 << 2,
    FLAG_CREATE_ALWAYS = 1 << 3,
    FLAG_OPEN_TRUNCATED = 1 << 4,
    FLAG_READ = 1 << 5,
    FLAG_WRITE = 1 << 6,
    FLAG_EXCLUSIVE_READ = 1 << 7,
    FLAG_EXCLUSIVE_WRITE = 1 << 8,
    FLAG_ASYNC = 1 << 9,
    FLAG_TEMPORARY = 1 << 10,
    FLAG_HIDDEN = 1 << 11,
    FLAG_DELETE_ON_CLOSE = 1 << 12,
    FLAG_WIN_BACKUP_SEMANTICS = 1 << 13,
    FLAG_WIN_EXECUTE = 1 << 14,
    FLAG_WIN_SEQUENTIAL_SCAN = 1 << 15,
    FLAG_WIN_SHARE_DELETE = 1 << 16,
    FLAG_CAN_DELETE_ON_CLOSE = 1 << 17,
  };

  File() : fd_(-1) {}
  explicit File(int fd) : fd_(fd) {}
  File(const FilePath& path, uint32_t flags) {
    int oflags = 0;
    if (flags & FLAG_READ) oflags |= O_RDONLY;
    if (flags & FLAG_WRITE) oflags |= O_WRONLY;
    if ((flags & FLAG_READ) && (flags & FLAG_WRITE)) oflags = O_RDWR;
    if (flags & FLAG_CREATE) oflags |= O_CREAT;
    if (flags & FLAG_OPEN_TRUNCATED) oflags |= O_TRUNC;
    fd_ = open(path.value().c_str(), oflags, 0644);
  }
  ~File() { if (fd_ >= 0) close(fd_); }

  File(File&& other) : fd_(other.fd_) { other.fd_ = -1; }
  File& operator=(File&& other) {
    if (fd_ >= 0) close(fd_);
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
  }

  bool IsValid() const { return fd_ >= 0; }
  int GetPlatformFile() const { return fd_; }
  int TakePlatformFile() { int f = fd_; fd_ = -1; return f; }

 private:
  int fd_;
};

}  // namespace base

#endif  // BASE_FILES_FILE_H_
