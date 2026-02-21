// Copyright 2014 The Chromium Authors
// Standalone shim: base/files/scoped_file.h
// RAII wrapper for POSIX file descriptors.

#ifndef BASE_FILES_SCOPED_FILE_H_
#define BASE_FILES_SCOPED_FILE_H_

#include <cstdio>
#include <memory>
#include <unistd.h>

namespace base {

// ScopedFD: RAII wrapper for a POSIX file descriptor.
// Closes the fd on destruction. Mimics Chromium's ScopedGeneric<int, ...>.
class ScopedFD {
 public:
  ScopedFD() : fd_(-1) {}
  explicit ScopedFD(int fd) : fd_(fd) {}
  ~ScopedFD() { reset(); }

  // Move only
  ScopedFD(ScopedFD&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  ScopedFD& operator=(ScopedFD&& other) noexcept {
    if (this != &other) {
      reset(other.release());
    }
    return *this;
  }
  ScopedFD(const ScopedFD&) = delete;
  ScopedFD& operator=(const ScopedFD&) = delete;

  int get() const { return fd_; }

  int release() {
    int tmp = fd_;
    fd_ = -1;
    return tmp;
  }

  void reset(int fd = -1) {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = fd;
  }

  bool is_valid() const { return fd_ >= 0; }
  explicit operator bool() const { return is_valid(); }

  bool operator==(const ScopedFD& other) const { return fd_ == other.fd_; }
  bool operator!=(const ScopedFD& other) const { return fd_ != other.fd_; }

 private:
  int fd_;
};

// ScopedFILE: RAII wrapper for FILE*.
struct ScopedFILECloser {
  void operator()(FILE* f) const {
    if (f) fclose(f);
  }
};
using ScopedFILE = std::unique_ptr<FILE, ScopedFILECloser>;

}  // namespace base

#endif  // BASE_FILES_SCOPED_FILE_H_
